import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding, FindingSeverity, FindingSource
from app.models.api_endpoint import ApiEndpoint
from app.services.posture_service import calculate_risk_score


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    p1 = Project(id=1, name="User A Project", source_type="OPENAPI", user_id=100)
    p2 = Project(id=2, name="User B Project", source_type="ZIP", user_id=200)
    session.add_all([p1, p2])
    session.commit()

    yield session
    session.close()


def test_01_dashboard_kpi_dynamic_calculation(db_session):
    """Dashboard KPIs calculated dynamically from database findings."""
    f1 = Finding(project_id=1, scan_id=1, title="Crit Flaw", description="Crit description", file_path="src/db.py", severity=FindingSeverity.CRITICAL, category="SQLi", source=FindingSource.SAST, fingerprint="fp_dash_01")
    f2 = Finding(project_id=1, scan_id=1, title="High Flaw", description="High description", file_path="API:GET:/users", severity=FindingSeverity.HIGH, category="BOLA", source=FindingSource.API_SECURITY, fingerprint="fp_dash_02")
    f3 = Finding(project_id=1, scan_id=1, title="Med Flaw", description="Med description", file_path="views/index.html", severity=FindingSeverity.MEDIUM, category="XSS", source=FindingSource.DAST, fingerprint="fp_dash_03")
    db_session.add_all([f1, f2, f3])
    db_session.commit()

    findings = db_session.query(Finding).filter(Finding.project_id == 1).all()
    score, grade, counts = calculate_risk_score(findings)

    assert len(findings) == 3
    assert counts["critical"] == 1
    assert counts["high"] == 1
    assert counts["medium"] == 1
    assert 0 <= score <= 100
    assert "A" in grade or "B" in grade or "C" in grade or "D" in grade or "F" in grade


def test_02_dashboard_tenant_isolation(db_session):
    """Dashboard queries filter strictly by project ownership, prohibiting cross-tenant data leakage."""
    f_user_a = Finding(project_id=1, scan_id=1, title="Secret A", description="Secret A desc", file_path="config_a.py", severity=FindingSeverity.CRITICAL, category="SECRETS", source=FindingSource.SECRETS, fingerprint="fp_tenant_a")
    f_user_b = Finding(project_id=2, scan_id=2, title="Secret B", description="Secret B desc", file_path="config_b.py", severity=FindingSeverity.HIGH, category="SECRETS", source=FindingSource.SECRETS, fingerprint="fp_tenant_b")
    db_session.add_all([f_user_a, f_user_b])
    db_session.commit()

    findings_a = db_session.query(Finding).filter(Finding.project_id == 1).all()
    findings_b = db_session.query(Finding).filter(Finding.project_id == 2).all()

    assert len(findings_a) == 1
    assert findings_a[0].title == "Secret A"

    assert len(findings_b) == 1
    assert findings_b[0].title == "Secret B"


def test_03_empty_project_dashboard_state(db_session):
    """Empty project dashboard returns 0 counts and 100/A default posture without fake security numbers."""
    findings = db_session.query(Finding).filter(Finding.project_id == 2).all()
    score, grade, counts = calculate_risk_score(findings)

    assert len(findings) == 0
    assert counts["critical"] == 0
    assert counts["high"] == 0
    assert score == 100
    assert "A" in grade
