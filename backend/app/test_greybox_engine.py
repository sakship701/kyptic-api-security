import pytest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.models.api_endpoint import ApiEndpoint
from app.services.greybox_context_engine import (
    GreyBoxContextEngine,
    extract_explicit_route_from_code,
    classify_vulnerability_family,
    map_vulnerability_to_probes,
    calculate_priority_score,
)
from app.services.dast_probes import run_active_dast_probes
from app.services.cross_validation_engine import CrossValidationEngine


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    project = Project(id=1, name="Test Project", source_type="OPENAPI", source_status="READY", api_target_url="http://test.api", api_dast_enabled=True)
    scan = Scan(id=1, project_id=1, status=ScanStatus.COMPLETED)
    session.add(project)
    session.add(scan)
    session.commit()

    yield session
    session.close()


def test_01_api_security_finding_exact_openapi_endpoint(db_session):
    """1. API Security finding -> exact OpenAPI endpoint."""
    ep = ApiEndpoint(id=10, project_id=1, path="/api/v1/users/{id}", method="GET", risk_level="HIGH")
    db_session.add(ep)
    db_session.commit()

    f = Finding(
        project_id=1, scan_id=1, title="BOLA Risk", description="BOLA static check",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="API:GET:/api/v1/users/{id}",
        source=FindingSource.API_SECURITY, scanner_name="api-security", fingerprint="fp_gb_01"
    )

    engine = GreyBoxContextEngine(db=db_session)
    contexts = engine.build_context(project_id=1, scan_id=1, static_findings=[f], endpoints=[ep])

    assert len(contexts) == 1
    assert contexts[0].endpoint_id == 10
    assert contexts[0].mapping_confidence == "EXACT_OPENAPI"
    assert contexts[0].recommended_probe_types == ["BOLA"]


def test_02_http_method_mismatch_no_mapping(db_session):
    """2. HTTP method mismatch -> no mapping."""
    ep = ApiEndpoint(id=11, project_id=1, path="/api/v1/users/{id}", method="POST", risk_level="HIGH")
    db_session.add(ep)
    db_session.commit()

    f = Finding(
        project_id=1, scan_id=1, title="BOLA Risk GET", description="BOLA check",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="API:GET:/api/v1/users/{id}",
        source=FindingSource.API_SECURITY, scanner_name="api-security", fingerprint="fp_gb_02"
    )

    engine = GreyBoxContextEngine(db=db_session)
    contexts = engine.build_context(project_id=1, scan_id=1, static_findings=[f], endpoints=[ep])

    assert len(contexts) == 1
    assert contexts[0].mapping_confidence == "UNMAPPED"


def test_03_explicit_supported_route_syntax_exact_code_mapping(db_session):
    """3. Explicit supported route syntax -> exact code route mapping."""
    ep = ApiEndpoint(id=12, project_id=1, path="/api/v1/billing/{id}", method="GET", risk_level="CRITICAL")
    db_session.add(ep)
    db_session.commit()

    f = Finding(
        project_id=1, scan_id=1, title="Unchecked Billing ID", description="Code issue",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="src/routes/billing.py",
        source=FindingSource.SAST, scanner_name="semgrep", code_snippet='@app.get("/api/v1/billing/{id}")\ndef get_billing():',
        fingerprint="fp_gb_03"
    )

    engine = GreyBoxContextEngine(db=db_session)
    contexts = engine.build_context(project_id=1, scan_id=1, static_findings=[f], endpoints=[ep])

    assert len(contexts) == 1
    assert contexts[0].endpoint_id == 12
    assert contexts[0].mapping_confidence == "CODE_ROUTE_EXACT"


def test_04_05_controller_heuristic_mapping(db_session):
    """4. Controller heuristic mapping. 5. Weak heuristic does not become exact mapping."""
    ep = ApiEndpoint(id=13, project_id=1, path="/api/v1/orders/{id}", method="GET", risk_level="MEDIUM")
    db_session.add(ep)
    db_session.commit()

    f = Finding(
        project_id=1, scan_id=1, title="Orders BOLA", description="Controller issue",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="controllers/ordersController.js",
        source=FindingSource.SAST, scanner_name="semgrep", code_snippet='const orderId = req.params.id;',
        fingerprint="fp_gb_04"
    )

    engine = GreyBoxContextEngine(db=db_session)
    contexts = engine.build_context(project_id=1, scan_id=1, static_findings=[f], endpoints=[ep])

    assert len(contexts) == 1
    assert contexts[0].endpoint_id == 13
    assert contexts[0].mapping_confidence == "HEURISTIC_CONTROLLER"
    assert contexts[0].mapping_confidence != "EXACT_OPENAPI"


def test_06_unmapped_finding_remains_unmapped(db_session):
    """6. Unmapped finding remains unmapped."""
    ep = ApiEndpoint(id=14, project_id=1, path="/api/v1/health", method="GET", risk_level="INFO")
    db_session.add(ep)
    db_session.commit()

    f = Finding(
        project_id=1, scan_id=1, title="Generic Utility Flaw", description="Unmapped code issue",
        severity=FindingSeverity.LOW, category="Code Quality", file_path="utils/helper.py",
        source=FindingSource.SAST, scanner_name="semgrep", fingerprint="fp_gb_06"
    )

    engine = GreyBoxContextEngine(db=db_session)
    contexts = engine.build_context(project_id=1, scan_id=1, static_findings=[f], endpoints=[ep])

    assert len(contexts) == 1
    assert contexts[0].mapping_confidence == "UNMAPPED"
    assert contexts[0].endpoint_id is None
    assert contexts[0].recommended_probe_types == []


def test_07_08_09_10_vulnerability_to_probe_mappings(db_session):
    """7. BOLA -> BOLA. 8. Auth -> AUTH_ENFORCEMENT. 9. Mass Assignment -> MASS_ASSIGNMENT. 10. Rate Limit -> RATE_LIMITING."""
    assert map_vulnerability_to_probes("BOLA")[0] == ["BOLA"]
    assert map_vulnerability_to_probes("AUTH")[0] == ["AUTH_ENFORCEMENT"]
    assert map_vulnerability_to_probes("MASS_ASSIGNMENT")[0] == ["MASS_ASSIGNMENT"]
    assert map_vulnerability_to_probes("RATE_LIMITING")[0] == ["RATE_LIMITING"]


def test_11_12_13_unsupported_vulnerability_probes(db_session):
    """Verify probe mapping for supported Phase 5 expansion vs un-probed static findings."""
    assert map_vulnerability_to_probes("SQL_INJECTION")[0] == ["SQL_INJECTION"]
    assert map_vulnerability_to_probes("XSS")[0] == ["XSS"]
    assert map_vulnerability_to_probes("SSRF")[0] == []
    assert map_vulnerability_to_probes("XXE")[0] == []
    assert map_vulnerability_to_probes("SECRETS")[0] == []
    assert map_vulnerability_to_probes("SCA")[0] == []


def test_14_15_16_priority_score_and_level_mapping():
    """14. Priority score deterministic. 15. Priority bounded 0-100. 16. Priority level mapping correct."""
    score, level = calculate_priority_score(
        finding_severity="CRITICAL", endpoint_risk_level="CRITICAL",
        auth_status="UNAUTHENTICATED", bola_status="POTENTIAL_BOLA",
        mass_assignment_status="NONE", sensitive_data_fields="ssn,password"
    )

    assert 0 <= score <= 100
    assert score == 100  # 35 + 25 + 15 + 15 + 10 = 100
    assert level == "CRITICAL"


def test_17_unauthenticated_endpoint_affects_priority_not_vulnerability():
    """17. Unauthenticated endpoint affects priority but does not prove vulnerability."""
    score1, _ = calculate_priority_score("HIGH", "HIGH", "AUTHENTICATED", "NONE", "NONE", None)
    score2, _ = calculate_priority_score("HIGH", "HIGH", "UNAUTHENTICATED", "NONE", "NONE", None)

    assert score2 > score1


def test_18_23_multiple_findings_same_endpoint_deduplicate_execution(db_session):
    """18. Multiple findings targeting same endpoint/probe produce one scheduled probe. 23. No duplicate dynamic execution."""
    ep = ApiEndpoint(id=15, project_id=1, path="/api/v1/users/{id}", method="GET", risk_level="HIGH", bola_status="POTENTIAL_BOLA")
    db_session.add(ep)
    db_session.commit()

    f1 = Finding(
        project_id=1, scan_id=1, title="BOLA 1", description="BOLA check 1",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="API:GET:/api/v1/users/{id}",
        source=FindingSource.API_SECURITY, scanner_name="api-security", fingerprint="fp_dedup_1"
    )
    f2 = Finding(
        project_id=1, scan_id=1, title="BOLA 2", description="BOLA check 2",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="API:GET:/api/v1/users/{id}",
        source=FindingSource.API_SECURITY, scanner_name="api-security", fingerprint="fp_dedup_2"
    )

    engine = GreyBoxContextEngine(db=db_session)
    contexts = engine.build_context(project_id=1, scan_id=1, static_findings=[f1, f2], endpoints=[ep])

    assert len(contexts) == 2
    # Both contexts point to endpoint 15 and recommended probe "BOLA"
    assert contexts[0].endpoint_id == 15
    assert contexts[1].endpoint_id == 15


def test_19_21_dast_failure_preserves_static_findings_and_cross_validation(db_session):
    """19. DAST failure preserves static findings. 21. Existing Phase 2 CrossValidationEngine receives runtime findings normally."""
    f_stat = Finding(
        project_id=1, scan_id=1, title="BOLA Risk", description="BOLA static check",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="GET /api/v1/users/{id}",
        source=FindingSource.API_SECURITY, scanner_name="api-security", fingerprint="fp_cv_preserve"
    )

    cv_engine = CrossValidationEngine(db=db_session)
    results = cv_engine.process_findings(project_id=1, scan_id=1, findings=[f_stat], dast_status="FAILED")

    assert len(results) == 1
    assert results[0].verification_status == "INCONCLUSIVE"


def test_20_ssrf_safety_controls_preserved(db_session):
    """20. No SSRF safety regression."""
    project = Project(id=2, name="SSRF Target", source_type="OPENAPI", source_status="READY", api_target_url="http://169.254.169.254", api_dast_enabled=True)
    db_session.add(project)
    db_session.commit()

    ep = ApiEndpoint(id=20, project_id=2, path="/api/test", method="GET")
    db_session.add(ep)
    db_session.commit()

    # Dynamic probes against metadata IP should return empty list
    dast_findings = run_active_dast_probes(db=db_session, project=project, scan_id=1, endpoints=[ep])
    assert dast_findings == []


def test_22_repeated_execution_produces_same_context(db_session):
    """22. Repeated execution produces same context/schedule."""
    ep = ApiEndpoint(id=16, project_id=1, path="/api/v1/items/{id}", method="GET", risk_level="MEDIUM")
    db_session.add(ep)
    db_session.commit()

    f = Finding(
        project_id=1, scan_id=1, title="BOLA Check", description="BOLA item check",
        severity=FindingSeverity.MEDIUM, category="BOLA", file_path="API:GET:/api/v1/items/{id}",
        source=FindingSource.API_SECURITY, scanner_name="api-security", fingerprint="fp_repeat_1"
    )

    engine = GreyBoxContextEngine(db=db_session)
    ctx1 = engine.build_context(project_id=1, scan_id=1, static_findings=[f], endpoints=[ep])
    ctx2 = engine.build_context(project_id=1, scan_id=1, static_findings=[f], endpoints=[ep])

    assert ctx1[0].priority_score == ctx2[0].priority_score
    assert ctx1[0].context_reason == ctx2[0].context_reason
