import pytest
import io
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding, FindingSeverity, FindingSource
from app.models.api_endpoint import ApiEndpoint
from app.services.report_service import ReportService, map_owasp_category


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    project = Project(id=10, name="Phase 11 Report Project", source_type="OPENAPI", source_status="READY", api_target_url="http://test.api")
    scan = Scan(id=10, project_id=10, status=ScanStatus.COMPLETED)
    session.add_all([project, scan])
    session.commit()

    yield session
    session.close()


def test_01_json_report_real_database_metrics(db_session):
    """JSON report metrics dynamically calculated from actual database records."""
    f1 = Finding(
        project_id=10, scan_id=10, title="SQLi Flaw", description="SQL injection check",
        severity=FindingSeverity.CRITICAL, category="SQL_INJECTION", cvss=9.8,
        file_path="src/db.py", line_number=42, source=FindingSource.SAST, fingerprint="fp_rpt_01"
    )
    f2 = Finding(
        project_id=10, scan_id=10, title="BOLA Flaw", description="BOLA check",
        severity=FindingSeverity.HIGH, category="BOLA", cvss=7.5,
        file_path="API:GET:/users/{id}", source=FindingSource.API_SECURITY, fingerprint="fp_rpt_02"
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    service = ReportService(db=db_session)
    report = service.generate_json_report(project_id=10, report_type="executive")

    assert report["project_id"] == 10
    assert report["project_name"] == "Phase 11 Report Project"
    assert report["metrics"]["total_findings"] == 2
    assert report["metrics"]["severity_counts"]["critical"] == 1
    assert report["metrics"]["severity_counts"]["high"] == 1
    assert len(report["findings"]) == 2


def test_02_html_and_pdf_report_generation(db_session):
    """HTML and PDF reports generate valid content containing real project identity."""
    f = Finding(
        project_id=10, scan_id=10, title="XSS Defect", description="Reflected XSS",
        severity=FindingSeverity.MEDIUM, category="XSS", cvss=6.1,
        file_path="views/index.html", source=FindingSource.DAST, fingerprint="fp_rpt_03"
    )
    db_session.add(f)
    db_session.commit()

    service = ReportService(db=db_session)

    # HTML
    html_out = service.generate_html_report(project_id=10, report_type="executive")
    assert "Phase 11 Report Project" in html_out
    assert "XSS Defect" in html_out

    # PDF
    pdf_out = service.generate_pdf_report(project_id=10, report_type="executive")
    assert isinstance(pdf_out, bytes)
    assert len(pdf_out) > 500
    assert pdf_out.startswith(b"%PDF")


def test_03_empty_report_state_handling(db_session):
    """Empty project report shows zero findings state without hardcoded fake figures."""
    proj_empty = Project(id=11, name="Empty Project", source_type="ZIP", source_status="READY")
    db_session.add(proj_empty)
    db_session.commit()

    service = ReportService(db=db_session)
    report = service.generate_json_report(project_id=11, report_type="executive")

    assert report["metrics"]["total_findings"] == 0
    assert report["metrics"]["severity_counts"]["critical"] == 0
    assert report["findings"] == []

    html_out = service.generate_html_report(project_id=11, report_type="executive")
    assert "No security findings detected" in html_out


def test_04_owasp_category_mapping():
    """Verify OWASP category mapping produces standardized OWASP 2021 / OWASP API 2023 titles."""
    assert "API1:2023" in map_owasp_category("BOLA", "Object authorization")
    assert "A03:2021" in map_owasp_category("SQL_INJECTION", "SQLi check")
    assert "A06:2021" in map_owasp_category("SCA", "Vulnerable package")
