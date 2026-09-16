import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.security.compliance_registry import ComplianceRegistry, FrameworkControlDefinition
from app.services.compliance_service import ComplianceService

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
def compliance_project():
    db = TestingSessionLocal()
    project = Project(name="Compliance Test Project")
    db.add(project)
    db.commit()
    db.refresh(project)
    pid = project.id

    scan = Scan(project_id=pid, status=ScanStatus.COMPLETED, scanner="full_scan")
    db.add(scan)
    db.commit()

    finding1 = Finding(
        project_id=pid,
        scan_id=scan.id,
        title="SQL Injection in auth route",
        description="Dynamic query string concatenation",
        severity=FindingSeverity.CRITICAL,
        cvss=9.8,
        category="Injection",
        file_path="controllers/auth.py",
        line_number=42,
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
        title="BOLA in billing endpoint",
        description="Missing user ownership check",
        severity=FindingSeverity.HIGH,
        cvss=8.1,
        category="BOLA",
        file_path="controllers/billing.py",
        line_number=14,
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


def test_compliance_registry_frameworks():
    assert "PCI_DSS" in ComplianceRegistry.FRAMEWORKS
    assert "SOC_2" in ComplianceRegistry.FRAMEWORKS
    assert "ISO_27001" in ComplianceRegistry.FRAMEWORKS
    assert "OWASP_API_TOP_10" in ComplianceRegistry.FRAMEWORKS
    assert "OWASP_TOP_10" in ComplianceRegistry.FRAMEWORKS
    assert "CWE" in ComplianceRegistry.FRAMEWORKS

    pci_controls = ComplianceRegistry.get_controls_for_framework("PCI_DSS")
    assert len(pci_controls) > 0


def test_compliance_service_evaluation(compliance_project):
    db = TestingSessionLocal()
    res = ComplianceService.evaluate_compliance(db, compliance_project, "PCI_DSS")

    assert res.project_id == compliance_project
    assert res.framework == "PCI_DSS"
    assert res.summary.total_controls > 0
    assert res.summary.affected_controls >= 1
    assert "legal compliance certification" in res.summary.disclaimer

    # Check affected control mapping
    affected_ctrls = [c for c in res.controls if c.status == "AFFECTED"]
    assert len(affected_ctrls) >= 1
    assert len(affected_ctrls[0].mapped_findings) >= 1
    db.close()


def test_compliance_no_scan_evidence():
    """TEST 1: No relevant scan evidence -> INSUFFICIENT_EVIDENCE"""
    db = TestingSessionLocal()
    project = Project(name="Unassessed Project")
    db.add(project)
    db.commit()

    res = ComplianceService.evaluate_compliance(db, project.id, "PCI_DSS")
    assert res.summary.insufficient_evidence_controls == res.summary.total_controls
    assert res.summary.coverage_percentage == 0.0
    for ctrl in res.controls:
        assert ctrl.status == "INSUFFICIENT_EVIDENCE"
    db.close()


def test_compliance_partial_assessment():
    """TEST 2: Partial assessment -> INSUFFICIENT_EVIDENCE"""
    db = TestingSessionLocal()
    project = Project(name="Partial Assessment Project")
    db.add(project)
    db.commit()

    # Only a SAST scan completed
    scan = Scan(project_id=project.id, status=ScanStatus.COMPLETED, scanner="sast")
    db.add(scan)
    db.commit()

    res = ComplianceService.evaluate_compliance(db, project.id, "OWASP_API_TOP_10")
    # API1:2023 is BOLA (requires DAST domain). Since only SAST was run, API1:2023 must be INSUFFICIENT_EVIDENCE
    bola_ctrl = next(c for c in res.controls if c.control_id == "API1:2023")
    assert bola_ctrl.status == "INSUFFICIENT_EVIDENCE"
    db.close()


def test_compliance_open_mapped_finding(compliance_project):
    """TEST 3: Open mapped finding -> AFFECTED"""
    db = TestingSessionLocal()
    res = ComplianceService.evaluate_compliance(db, compliance_project, "PCI_DSS")
    pci_inj = next(c for c in res.controls if c.control_id == "PCI-6.2.4")
    assert pci_inj.status == "AFFECTED"
    assert pci_inj.affected_findings_count >= 1
    db.close()


def test_compliance_no_direct_mapping():
    """TEST 4: No direct mapping -> NO_DIRECT_MAPPING"""
    db = TestingSessionLocal()
    project = Project(name="Unmapped Control Test Project")
    db.add(project)
    db.commit()

    unmapped_ctrl = FrameworkControlDefinition(
        control_id="CUSTOM-9.9",
        control_name="Manual Governance Check",
        framework="PCI_DSS",
        description="Non-technical policy check",
        cwes=[],
        owasps=[],
        remediation_reference="Review policy document manually."
    )

    orig_controls = list(ComplianceRegistry.CONTROLS)
    ComplianceRegistry.CONTROLS.append(unmapped_ctrl)
    try:
        res = ComplianceService.evaluate_compliance(db, project.id, "PCI_DSS")
        ctrl_res = next(c for c in res.controls if c.control_id == "CUSTOM-9.9")
        assert ctrl_res.status == "NO_DIRECT_MAPPING"
    finally:
        ComplianceRegistry.CONTROLS = orig_controls
    db.close()


def test_compliance_sufficient_assessment_not_affected():
    """TEST 5: Sufficient assessment with no mapped finding -> NOT_AFFECTED"""
    db = TestingSessionLocal()
    project = Project(name="Fully Assessed Secure Project")
    db.add(project)
    db.commit()

    scan = Scan(project_id=project.id, status=ScanStatus.COMPLETED, scanner="full_scan")
    db.add(scan)
    db.commit()

    res = ComplianceService.evaluate_compliance(db, project.id, "PCI_DSS")
    for ctrl in res.controls:
        assert ctrl.status == "NOT_AFFECTED"
    assert res.summary.coverage_percentage == 100.0
    db.close()


def test_compliance_coverage_excludes_insufficient_evidence():
    """TEST 6: Coverage does not treat INSUFFICIENT_EVIDENCE as successful coverage"""
    db = TestingSessionLocal()
    project = Project(name="Unscanned Coverage Project")
    db.add(project)
    db.commit()

    res = ComplianceService.evaluate_compliance(db, project.id, "PCI_DSS")
    assert res.summary.insufficient_evidence_controls > 0
    assert res.summary.coverage_percentage == 0.0
    db.close()


def test_compliance_no_finding_mutation(compliance_project):
    """TEST 7: Compliance evaluation does not mutate findings"""
    db = TestingSessionLocal()
    finding_before = db.query(Finding).filter(Finding.project_id == compliance_project).first()
    orig_status = finding_before.verification_status
    orig_conf = finding_before.confidence_score

    ComplianceService.evaluate_compliance(db, compliance_project, "PCI_DSS")

    finding_after = db.query(Finding).filter(Finding.project_id == compliance_project).first()
    assert finding_after.verification_status == orig_status
    assert finding_after.confidence_score == orig_conf
    db.close()


def test_compliance_api_endpoint(compliance_project):
    client = TestClient(app)
    response = client.get(f"/api/v1/projects/{compliance_project}/compliance?framework=PCI_DSS")
    assert response.status_code == 200
    data = response.json()
    assert "summary" in data
    assert "controls" in data
    assert data["framework"] == "PCI_DSS"
    assert data["summary"]["affected_controls"] >= 1

