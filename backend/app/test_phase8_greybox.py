import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding, FindingSeverity, FindingSource
from app.models.api_endpoint import ApiEndpoint
from app.services.greybox_context_engine import (
    GreyBoxContextEngine,
    extract_explicit_route_from_code,
    classify_vulnerability_family,
    map_vulnerability_to_probes,
    calculate_priority_score,
)
from app.services.cross_validation_engine import normalize_endpoint_path


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    project = Project(id=1, name="Phase 8 Grey-Box Test Project", source_type="OPENAPI", source_status="READY", api_target_url="http://test.api", api_dast_enabled=True)
    scan = Scan(id=1, project_id=1, status=ScanStatus.COMPLETED)
    session.add(project)
    session.add(scan)
    session.commit()

    yield session
    session.close()


def test_01_framework_route_extractors():
    """Verify route extraction from Python (FastAPI, Flask), JS (Express), and Java (Spring)."""
    # FastAPI / Flask
    assert extract_explicit_route_from_code('@app.get("/users/{id}")') == ("GET", "/users/{id}")
    assert extract_explicit_route_from_code('@router.post("/api/v1/auth")') == ("POST", "/api/v1/auth")

    # Express / JS
    assert extract_explicit_route_from_code('app.get("/api/items", (req, res) => {})') == ("GET", "/api/items")
    assert extract_explicit_route_from_code('router.put("/users/profile", updateProfile)') == ("PUT", "/users/profile")

    # Java Spring
    assert extract_explicit_route_from_code('@GetMapping("/accounts/{id}")') == ("GET", "/accounts/{id}")
    assert extract_explicit_route_from_code('@PostMapping("/login")') == ("POST", "/login")

    # Unsupported framework / syntax -> None safely
    assert extract_explicit_route_from_code("function helper() { return true; }") is None


def test_02_openapi_code_correlation_parameter_normalization():
    """Verify OpenAPI -> Code parameter normalization (/users/{id} vs /users/{userId})."""
    m1, p1 = normalize_endpoint_path("GET /users/{id}")
    m2, p2 = normalize_endpoint_path("GET /users/{userId}")
    m3, p3 = normalize_endpoint_path("GET /users/12345")

    assert (m1, p1) == ("GET", "/users/{param}")
    assert (m2, p2) == ("GET", "/users/{param}")
    assert (m3, p3) == ("GET", "/users/{param}")


def test_03_four_priority_mapping_levels(db_session):
    """Test all 4 Grey-Box mapping levels: EXACT_OPENAPI, CODE_ROUTE_EXACT, HEURISTIC_CONTROLLER, UNMAPPED."""
    ep1 = ApiEndpoint(id=101, project_id=1, path="/api/v1/users/{id}", method="GET", risk_level="HIGH")
    ep2 = ApiEndpoint(id=102, project_id=1, path="/api/v1/billing/{id}", method="GET", risk_level="CRITICAL")
    ep3 = ApiEndpoint(id=103, project_id=1, path="/api/v1/orders/{id}", method="GET", risk_level="MEDIUM")
    db_session.add_all([ep1, ep2, ep3])
    db_session.commit()

    # Level 1: EXACT_OPENAPI
    f1 = Finding(
        project_id=1, scan_id=1, title="OpenAPI BOLA", description="Exact match",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="API:GET:/api/v1/users/{id}",
        source=FindingSource.API_SECURITY, fingerprint="fp_lvl1"
    )

    # Level 2: CODE_ROUTE_EXACT
    f2 = Finding(
        project_id=1, scan_id=1, title="Billing Route BOLA", description="Code route match",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="src/billing.py",
        source=FindingSource.SAST, code_snippet='@app.get("/api/v1/billing/{id}")', fingerprint="fp_lvl2"
    )

    # Level 3: HEURISTIC_CONTROLLER
    f3 = Finding(
        project_id=1, scan_id=1, title="Orders Controller Issue", description="Heuristic match",
        severity=FindingSeverity.MEDIUM, category="BOLA", file_path="controllers/ordersController.js",
        source=FindingSource.SAST, code_snippet="const id = req.params.id;", fingerprint="fp_lvl3"
    )

    # Level 4: UNMAPPED
    f4 = Finding(
        project_id=1, scan_id=1, title="Helper Utility Flaw", description="Unmapped helper",
        severity=FindingSeverity.LOW, category="Code Quality", file_path="utils/helper.py",
        source=FindingSource.SAST, fingerprint="fp_lvl4"
    )

    db_session.add_all([f1, f2, f3, f4])
    db_session.commit()

    engine = GreyBoxContextEngine(db=db_session)
    contexts = engine.build_context(project_id=1, scan_id=1, static_findings=[f1, f2, f3, f4], endpoints=[ep1, ep2, ep3])

    ctx_map = {c.finding_id: c for c in contexts}
    assert ctx_map[f1.id].mapping_confidence == "EXACT_OPENAPI"
    assert ctx_map[f1.id].endpoint_id == 101

    assert ctx_map[f2.id].mapping_confidence == "CODE_ROUTE_EXACT"
    assert ctx_map[f2.id].endpoint_id == 102

    assert ctx_map[f3.id].mapping_confidence == "HEURISTIC_CONTROLLER"
    assert ctx_map[f3.id].endpoint_id == 103

    assert ctx_map[f4.id].mapping_confidence == "UNMAPPED"
    assert ctx_map[f4.id].endpoint_id is None
    assert ctx_map[f4.id].recommended_probe_types == []


def test_04_evidence_driven_probe_selection():
    """Verify evidence-driven probe selection maps to applicable active probe or returns empty probes."""
    assert map_vulnerability_to_probes("BOLA")[0] == ["BOLA"]
    assert map_vulnerability_to_probes("AUTH")[0] == ["AUTH_ENFORCEMENT"]
    assert map_vulnerability_to_probes("MASS_ASSIGNMENT")[0] == ["MASS_ASSIGNMENT"]
    assert map_vulnerability_to_probes("RATE_LIMITING")[0] == ["RATE_LIMITING"]
    assert map_vulnerability_to_probes("SQL_INJECTION")[0] == ["SQL_INJECTION"]
    assert map_vulnerability_to_probes("COMMAND_INJECTION")[0] == ["COMMAND_INJECTION"]
    assert map_vulnerability_to_probes("XSS")[0] == ["XSS"]
    assert map_vulnerability_to_probes("DOM_XSS")[0] == ["DOM_XSS"]

    # Unsupported or non-probing static categories -> empty probe list
    assert map_vulnerability_to_probes("SSRF")[0] == []
    assert map_vulnerability_to_probes("SECRETS")[0] == []
    assert map_vulnerability_to_probes("SCA")[0] == []


def test_05_priority_score_calculation():
    """Verify priority score is deterministic, bounded 0-100, and returns correct priority levels."""
    score, level = calculate_priority_score(
        finding_severity="CRITICAL", endpoint_risk_level="CRITICAL",
        auth_status="UNAUTHENTICATED", bola_status="POTENTIAL_BOLA",
        mass_assignment_status="NONE", sensitive_data_fields="ssn"
    )
    assert 0 <= score <= 100
    assert level == "CRITICAL"
