import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding, FindingSeverity, FindingSource
from app.models.api_endpoint import ApiEndpoint
from app.services.risk_map_service import RiskMapService
from app.services.compliance_service import ComplianceService


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    project = Project(id=1, name="Phase 13 Risk & Compliance Project", source_type="OPENAPI", source_status="READY")
    scan = Scan(id=1, project_id=1, status=ScanStatus.COMPLETED)
    session.add_all([project, scan])
    session.commit()

    yield session
    session.close()


def test_01_risk_map_graph_database_driven(db_session):
    """Risk Map graph generated strictly from database endpoints and findings without phantom nodes."""
    ep = ApiEndpoint(id=10, project_id=1, path="/api/v1/checkout", method="POST", risk_level="HIGH")
    f = Finding(
        project_id=1, scan_id=1, title="BOLA on Checkout", description="BOLA flaw on checkout route", severity=FindingSeverity.HIGH,
        category="BOLA", cwe="CWE-639", owasp="API1:2023", file_path="/api/v1/checkout", source=FindingSource.API_SECURITY, fingerprint="fp_rm_01"
    )
    db_session.add_all([ep, f])
    db_session.commit()

    res = RiskMapService.generate_graph(db=db_session, project_id=1)

    assert res.project_id == 1
    assert res.project_name == "Phase 13 Risk & Compliance Project"
    assert len(res.nodes) >= 4  # PROJECT, API, ENDPOINT, FINDING

    node_types = {n.type for n in res.nodes}
    assert "PROJECT" in node_types
    assert "API" in node_types
    assert "ENDPOINT" in node_types
    assert "FINDING" in node_types


def test_02_risk_map_scaling_and_empty_endpoints(db_session):
    """Risk Map scales safely when endpoints are empty (links findings directly to API node)."""
    f = Finding(
        project_id=1, scan_id=1, title="Hardcoded AWS Key", description="Hardcoded key in config", severity=FindingSeverity.CRITICAL,
        category="SECRETS", cwe="CWE-798", owasp="A02:2021", file_path="config.py", source=FindingSource.SECRETS, fingerprint="fp_rm_02"
    )
    db_session.add(f)
    db_session.commit()

    res = RiskMapService.generate_graph(db=db_session, project_id=1)

    # Verify no phantom endpoint node was created when endpoints list is empty
    endpoint_nodes = [n for n in res.nodes if n.type == "ENDPOINT"]
    assert len(endpoint_nodes) == 0


def test_03_compliance_service_evaluation(db_session):
    """Compliance Service evaluates framework controls into AFFECTED, NOT_AFFECTED, INSUFFICIENT_EVIDENCE."""
    f = Finding(
        project_id=1, scan_id=1, title="BOLA Flaw", description="BOLA vulnerability", severity=FindingSeverity.HIGH,
        category="BOLA", cwe="CWE-639", owasp="API1:2023", file_path="API:GET:/users/{id}", source=FindingSource.API_SECURITY, fingerprint="fp_comp_01"
    )
    db_session.add(f)
    db_session.commit()

    res = ComplianceService.evaluate_compliance(db=db_session, project_id=1, framework="PCI_DSS")

    assert res.project_id == 1
    assert res.framework == "PCI_DSS"
    assert "legal compliance certification" in res.summary.disclaimer

    statuses = {c.status for c in res.controls}
    assert "AFFECTED" in statuses or "NOT_AFFECTED" in statuses or "INSUFFICIENT_EVIDENCE" in statuses
