import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.api_endpoint import ApiEndpoint
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.services.risk_map_service import RiskMapService

# Setup isolated in-memory SQLite database with StaticPool for thread-safe test sharing
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=test_engine)
    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def risk_map_project():
    db = TestingSessionLocal()
    project = Project(name="Risk Map Test Project", target_url="https://api.test.com")
    db.add(project)
    db.commit()
    db.refresh(project)
    pid = project.id

    endpoint = ApiEndpoint(
        project_id=pid,
        path="/api/v1/users",
        method="GET",
        risk_score=75,
        risk_level="HIGH",
    )
    db.add(endpoint)
    db.commit()

    scan = Scan(project_id=pid, status=ScanStatus.COMPLETED)
    db.add(scan)
    db.commit()

    finding1 = Finding(
        project_id=pid,
        scan_id=scan.id,
        title="SQL Injection in user route",
        description="Dynamic query string concatenation",
        severity=FindingSeverity.CRITICAL,
        cvss=9.8,
        category="Injection",
        file_path="/api/v1/users",
        line_number=24,
        status=FindingStatus.OPEN,
        source=FindingSource.SAST,
        cwe="CWE-89",
        owasp="A03:2021-Injection",
        confidence_score=95,
        confidence_level="HIGH",
        verification_status="CONFIRMED",
    )
    finding2 = Finding(
        project_id=pid,
        scan_id=scan.id,
        title="BOLA vulnerability in user profile",
        description="Missing user ID ownership verification",
        severity=FindingSeverity.HIGH,
        cvss=8.1,
        category="BOLA",
        file_path="controllers/user.py",
        line_number=50,
        status=FindingStatus.OPEN,
        source=FindingSource.DAST,
        cwe="CWE-639",
        owasp="API1:2023-BOLA",
        confidence_score=90,
        confidence_level="HIGH",
        verification_status="CONFIRMED",
    )
    db.add(finding1)
    db.add(finding2)
    db.commit()
    db.close()
    return pid


def test_empty_project_risk_map():
    db = TestingSessionLocal()
    project = Project(name="Empty Risk Project")
    db.add(project)
    db.commit()
    db.refresh(project)

    graph = RiskMapService.generate_graph(db, project.id)
    assert graph.project_id == project.id
    assert len(graph.nodes) >= 2  # PROJECT and API nodes
    assert len(graph.edges) >= 1  # PROJECT_API edge
    assert graph.summary.critical_findings == 0
    assert graph.summary.overall_risk_score == 100
    db.close()


def test_populated_project_risk_map(risk_map_project):
    db = TestingSessionLocal()
    graph = RiskMapService.generate_graph(db, risk_map_project)

    node_types = {n.type for n in graph.nodes}
    assert "PROJECT" in node_types
    assert "API" in node_types
    assert "ENDPOINT" in node_types
    assert "FINDING" in node_types
    assert "VULNERABILITY" in node_types
    assert "FILE" in node_types

    edge_types = {e.type for e in graph.edges}
    assert "PROJECT_API" in edge_types
    assert "API_ENDPOINT" in edge_types
    assert "ENDPOINT_FINDING" in edge_types
    assert "FINDING_VULN" in edge_types

    assert graph.summary.critical_findings >= 1
    assert graph.summary.high_findings >= 1
    assert graph.summary.overall_risk_score < 100
    db.close()


def test_risk_map_large_graph_no_truncation():
    """Verify projects with >12 findings and >8 endpoints return complete graph data with zero truncation."""
    db = TestingSessionLocal()
    project = Project(name="Large Risk Project")
    db.add(project)
    db.commit()

    scan = Scan(project_id=project.id, status=ScanStatus.COMPLETED)
    db.add(scan)
    db.commit()

    # Create 10 endpoints
    for i in range(10):
        ep = ApiEndpoint(
            project_id=project.id,
            path=f"/api/v1/resource_{i}",
            method="GET",
            risk_score=50,
            risk_level="MEDIUM",
        )
        db.add(ep)
    db.commit()

    # Create 16 findings (>12 threshold)
    for i in range(16):
        f = Finding(
            project_id=project.id,
            scan_id=scan.id,
            title=f"Vulnerability Finding #{i+1}",
            description=f"Automated test finding #{i+1}",
            severity=FindingSeverity.HIGH if i % 2 == 0 else FindingSeverity.MEDIUM,
            cvss=7.5,
            category="API Security",
            file_path=f"/api/v1/resource_{i % 10}",
            line_number=10 + i,
            status=FindingStatus.OPEN,
            source=FindingSource.DAST,
            cwe=f"CWE-{100 + i}",
            owasp="API1:2023",
            confidence_score=85,
            confidence_level="HIGH",
            verification_status="CONFIRMED",
        )
        db.add(f)
    db.commit()

    graph = RiskMapService.generate_graph(db, project.id)

    endpoint_nodes = [n for n in graph.nodes if n.type == "ENDPOINT"]
    finding_nodes = [n for n in graph.nodes if n.type == "FINDING"]

    # Verify zero truncation
    assert len(endpoint_nodes) == 10
    assert len(finding_nodes) == 16
    db.close()


def test_risk_map_50_plus_findings():
    """Verify scalable graph generation for 50+ findings."""
    db = TestingSessionLocal()
    project = Project(name="Enterprise 50+ Finding Project")
    db.add(project)
    db.commit()

    scan = Scan(project_id=project.id, status=ScanStatus.COMPLETED)
    db.add(scan)
    db.commit()

    # Create 55 findings
    for i in range(55):
        f = Finding(
            project_id=project.id,
            scan_id=scan.id,
            title=f"Scale Test Finding #{i+1}",
            description="Scalability validation",
            severity=FindingSeverity.CRITICAL if i < 5 else FindingSeverity.LOW,
            cvss=9.0 if i < 5 else 3.0,
            category="Injection",
            file_path="src/app.py",
            line_number=i + 1,
            status=FindingStatus.OPEN,
            source=FindingSource.SAST,
            cwe="CWE-89",
            owasp="A03:2021",
            confidence_score=90,
            confidence_level="HIGH",
            verification_status="CONFIRMED",
        )
        db.add(f)
    db.commit()

    graph = RiskMapService.generate_graph(db, project.id)
    finding_nodes = [n for n in graph.nodes if n.type == "FINDING"]
    assert len(finding_nodes) == 55
    assert graph.summary.critical_findings == 5
    assert graph.summary.low_findings == 50
    db.close()


def test_risk_map_project_isolation(risk_map_project):
    """Verify Project A risk map never exposes Project B findings."""
    db = TestingSessionLocal()
    project_b = Project(name="Project B Secret Target")
    db.add(project_b)
    db.commit()

    scan_b = Scan(project_id=project_b.id, status=ScanStatus.COMPLETED)
    db.add(scan_b)
    db.commit()

    finding_b = Finding(
        project_id=project_b.id,
        scan_id=scan_b.id,
        title="Project B Proprietary Secret Leak",
        description="Confidential data",
        severity=FindingSeverity.CRITICAL,
        cvss=9.9,
        category="Secrets",
        file_path="secret/key.pem",
        line_number=1,
        status=FindingStatus.OPEN,
        source=FindingSource.SECRETS,
        cwe="CWE-798",
        confidence_score=100,
        confidence_level="HIGH",
        verification_status="CONFIRMED",
    )
    db.add(finding_b)
    db.commit()

    # Query Project A
    graph_a = RiskMapService.generate_graph(db, risk_map_project)
    node_labels_a = {n.label for n in graph_a.nodes}

    assert "Project B Proprietary Secret Leak" not in node_labels_a
    assert all(n.project_id == risk_map_project for n in graph_a.nodes if n.project_id is not None)
    db.close()


def test_risk_map_metadata_preservation(risk_map_project):
    """Verify confidence score, level, and verification status are preserved authoritative values."""
    db = TestingSessionLocal()
    graph = RiskMapService.generate_graph(db, risk_map_project)

    finding_nodes = [n for n in graph.nodes if n.type == "FINDING"]
    assert len(finding_nodes) >= 2

    for fn in finding_nodes:
        assert fn.confidence_score in (90, 95)
        assert fn.confidence_level == "HIGH"
        assert fn.verification_status == "CONFIRMED"
    db.close()

