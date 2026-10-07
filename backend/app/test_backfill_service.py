import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.services.backfill_service import recalculate_project_findings

SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def backfill_fixture():
    db = TestingSessionLocal()
    p1 = Project(name="Project 1")
    p2 = Project(name="Project 2 Isolated")
    db.add_all([p1, p2])
    db.commit()
    db.refresh(p1)
    db.refresh(p2)

    s1 = Scan(project_id=p1.id, status=ScanStatus.COMPLETED)
    s2 = Scan(project_id=p2.id, status=ScanStatus.COMPLETED)
    db.add_all([s1, s2])
    db.commit()

    # Secret finding with historical 8.1
    f_secret = Finding(
        project_id=p1.id,
        scan_id=s1.id,
        title="Hardcoded Secret Keyword Detected",
        description="AWS Secret Key",
        severity=FindingSeverity.CRITICAL,
        cvss=8.1,
        category="Secrets Exposure",
        file_path="src/config.py",
        line_number=10,
        status=FindingStatus.OPEN,
        source=FindingSource.SECRETS,
        scanner_name="detect-secrets",
        confidence_score=65,
        confidence_level="MEDIUM",
        verification_status="UNVERIFIED",
    )

    # SCA finding with authoritative CVE advisory
    f_sca = Finding(
        project_id=p1.id,
        scan_id=s1.id,
        title="Vulnerable Dependency: requests (CVE-2023-32681)",
        description="Leaked auth headers",
        severity=FindingSeverity.HIGH,
        cvss=7.5,
        cvss_source="OSV / NVD Advisory",
        cvss_version="3.1",
        category="Dependency Vulnerability",
        file_path="requirements.txt",
        line_number=1,
        status=FindingStatus.OPEN,
        source=FindingSource.SCA,
        scanner_name="sca-dependency",
        rule_id="CVE-2023-32681",
        code_snippet="Package: requests@2.25.0",
        confidence_score=70,
        confidence_level="MEDIUM",
        verification_status="UNVERIFIED",
    )

    # Isolated Project 2 finding
    f_p2 = Finding(
        project_id=p2.id,
        scan_id=s2.id,
        title="Isolated Project 2 Secret",
        description="Isolated secret",
        severity=FindingSeverity.HIGH,
        cvss=8.1,
        category="Secrets Exposure",
        file_path="src/app.py",
        line_number=5,
        status=FindingStatus.OPEN,
        source=FindingSource.SECRETS,
        scanner_name="detect-secrets",
        confidence_score=65,
        confidence_level="MEDIUM",
        verification_status="UNVERIFIED",
    )

    db.add_all([f_secret, f_sca, f_p2])
    db.commit()
    p1_id = p1.id
    p2_id = p2.id
    db.close()
    return p1_id, p2_id


def test_dry_run_does_not_modify_database(backfill_fixture):
    p1_id, _ = backfill_fixture
    db = TestingSessionLocal()

    summary = recalculate_project_findings(db, project_id=p1_id, dry_run=True)
    assert len(summary) == 2

    # Verify DB rows were NOT updated
    db_findings = db.query(Finding).filter(Finding.project_id == p1_id).order_by(Finding.id.asc()).all()
    assert float(db_findings[0].cvss) == 8.1
    assert db_findings[0].confidence_score == 65
    db.close()


def test_backfill_execution(backfill_fixture):
    p1_id, p2_id = backfill_fixture
    db = TestingSessionLocal()

    summary = recalculate_project_findings(db, project_id=p1_id, dry_run=False)
    assert len(summary) == 2

    # Reload Project 1 findings
    f_secret = db.query(Finding).filter(Finding.project_id == p1_id, Finding.source == FindingSource.SECRETS).first()
    f_sca = db.query(Finding).filter(Finding.project_id == p1_id, Finding.source == FindingSource.SCA).first()

    # Secret finding checks:
    assert f_secret.cvss is None
    assert f_secret.cvss_vector is None
    assert f_secret.cvss_source is None
    assert f_secret.cvss_version is None
    assert f_secret.severity == FindingSeverity.CRITICAL  # Existing severity preserved
    assert f_secret.project_id == p1_id  # Existing project_id preserved
    assert f_secret.scan_id is not None  # Existing scan_id preserved
    assert f_secret.confidence_score != 65  # Recalculated by ConfidenceService

    # SCA finding checks:
    assert float(f_sca.cvss) == 7.5  # Authoritative CVSS preserved
    assert f_sca.cvss_source == "OSV / NVD Advisory"

    # Project isolation check: Project 2 finding untouched
    f_p2 = db.query(Finding).filter(Finding.project_id == p2_id).first()
    assert float(f_p2.cvss) == 8.1
    assert f_p2.confidence_score == 65
    db.close()


def test_idempotence_running_twice_produces_identical_results(backfill_fixture):
    p1_id, _ = backfill_fixture
    db = TestingSessionLocal()

    # First run
    recalculate_project_findings(db, project_id=p1_id, dry_run=False)
    f1 = db.query(Finding).filter(Finding.project_id == p1_id).order_by(Finding.id.asc()).all()
    cvss_run1 = [f.cvss for f in f1]
    conf_run1 = [f.confidence_score for f in f1]

    # Second run
    recalculate_project_findings(db, project_id=p1_id, dry_run=False)
    f2 = db.query(Finding).filter(Finding.project_id == p1_id).order_by(Finding.id.asc()).all()
    cvss_run2 = [f.cvss for f in f2]
    conf_run2 = [f.confidence_score for f in f2]

    assert cvss_run1 == cvss_run2
    assert conf_run1 == conf_run2
    db.close()
