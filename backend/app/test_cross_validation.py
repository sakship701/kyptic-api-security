import pytest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.services.cross_validation_engine import (
    CrossValidationEngine,
    are_categories_compatible,
    are_endpoints_compatible,
    normalize_endpoint_path,
)
from app.services.report_service import ReportService
from app.schemas.finding import FindingResponse


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    project = Project(id=1, name="Test Project", source_type="ZIP", source_status="READY")
    scan = Scan(id=1, project_id=1, status=ScanStatus.COMPLETED)
    session.add(project)
    session.add(scan)
    session.commit()

    yield session
    session.close()


def test_edgecase_01_same_endpoint_different_categories_no_correlation(db_session):
    """1. Same endpoint + different vulnerability categories -> no correlation."""
    f1 = Finding(
        project_id=1, scan_id=1, title="BOLA Vulnerability", description="BOLA issue",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="GET /api/v1/users/{id}",
        source=FindingSource.API_SECURITY, scanner_name="api-security", fingerprint="fp_edge_bola"
    )
    f2 = Finding(
        project_id=1, scan_id=1, title="Missing Security Header", description="Missing X-Frame-Options",
        severity=FindingSeverity.LOW, category="Security Misconfiguration", file_path="GET /api/v1/users/123",
        source=FindingSource.DAST, scanner_name="dast-web", fingerprint="fp_edge_header"
    )

    engine = CrossValidationEngine(db=db_session)
    result = engine.process_findings(project_id=1, scan_id=1, findings=[f1, f2])

    assert result[0].correlation_count == 0
    assert result[1].correlation_count == 0
    assert result[0].correlated_finding_ids is None
    assert result[1].correlated_finding_ids is None


def test_edgecase_02_same_category_different_endpoint_no_correlation(db_session):
    """2. Same vulnerability category + different endpoint -> no correlation."""
    f1 = Finding(
        project_id=1, scan_id=1, title="SQL Injection", description="SQLi on users",
        severity=FindingSeverity.HIGH, category="Injection", file_path="POST /api/v1/users",
        source=FindingSource.DAST, scanner_name="dast-active-probe", fingerprint="fp_sqli_route1"
    )
    f2 = Finding(
        project_id=1, scan_id=1, title="SQL Injection", description="SQLi on products",
        severity=FindingSeverity.HIGH, category="Injection", file_path="POST /api/v1/products",
        source=FindingSource.DAST, scanner_name="dast-active-probe", fingerprint="fp_sqli_route2"
    )

    engine = CrossValidationEngine(db=db_session)
    result = engine.process_findings(project_id=1, scan_id=1, findings=[f1, f2])

    assert result[0].correlation_count == 0
    assert result[1].correlation_count == 0


def test_edgecase_03_same_endpoint_sqli_vs_xss_no_correlation(db_session):
    """3. Same endpoint + SQLi vs XSS -> no correlation."""
    assert not are_categories_compatible("Injection", "SQL Injection", "Injection", "Cross-Site Scripting (XSS)")


def test_edgecase_04_multiple_static_unrelated_scanners_corroborated(db_session):
    """4. Multiple static findings from unrelated scanners -> CORROBORATED status, score <= 100."""
    f1 = Finding(
        project_id=1, scan_id=1, title="Potential BOLA Risk", description="Static spec audit",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="GET /api/v1/data/{id}",
        source=FindingSource.API_SECURITY, scanner_name="api-security", fingerprint="fp_stat_api"
    )
    f2 = Finding(
        project_id=1, scan_id=1, title="Missing Authorization Check", description="SAST rule",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="controllers/dataController.js",
        source=FindingSource.SAST, scanner_name="semgrep", fingerprint="fp_stat_sast"
    )

    engine = CrossValidationEngine(db=db_session)
    result = engine.process_findings(project_id=1, scan_id=1, findings=[f1, f2])

    assert result[0].verification_status == "CORROBORATED"
    assert result[0].confidence_score <= 100
    assert result[0].correlation_count == 1
    assert "API Security" in result[0].evidence_sources
    assert "SAST" in result[0].evidence_sources


def test_edgecase_05_static_matching_dast_evidence_increases_confidence(db_session):
    """5. Static + matching DAST evidence -> confidence increases appropriately to VERIFIED."""
    f_stat = Finding(
        project_id=1, scan_id=1, title="BOLA Suspected", description="Static BOLA audit",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="GET /api/v1/orders/{id}",
        source=FindingSource.API_SECURITY, scanner_name="api-security", fingerprint="fp_stat_ord"
    )
    f_dast = Finding(
        project_id=1, scan_id=1, title="BOLA Confirmed", description="Active probe proof",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="GET /api/v1/orders/101",
        source=FindingSource.DAST, scanner_name="dast-active-probe", fingerprint="fp_dast_ord"
    )

    engine = CrossValidationEngine(db=db_session)
    result = engine.process_findings(project_id=1, scan_id=1, findings=[f_stat, f_dast])

    assert result[0].verification_status == "VERIFIED"
    assert result[0].confidence_score >= 85


def test_edgecase_06_generic_dast_finding_not_automatically_verified(db_session):
    """6. Generic DAST finding (dast-web header check) -> does not automatically become VERIFIED."""
    f_generic = Finding(
        project_id=1, scan_id=1, title="Missing Anti-Clickjacking Header", description="Missing X-Frame-Options",
        severity=FindingSeverity.LOW, category="Security Misconfiguration", file_path="GET /index.html",
        source=FindingSource.DAST, scanner_name="dast-web", fingerprint="fp_gen_header"
    )

    engine = CrossValidationEngine(db=db_session)
    result = engine.process_findings(project_id=1, scan_id=1, findings=[f_generic])

    assert result[0].verification_status != "VERIFIED"
    assert result[0].verification_status == "UNVERIFIED"
    assert result[0].confidence_score == 70


def test_edgecase_07_dast_scanner_failure_inconclusive(db_session):
    """7. DAST scanner failure -> INCONCLUSIVE where dynamic verification was actually attempted/relevant."""
    f_static = Finding(
        project_id=1, scan_id=1, title="SQL Injection Suspected", description="Route concat",
        severity=FindingSeverity.HIGH, category="SQL Injection", file_path="POST /api/v1/search",
        source=FindingSource.API_SECURITY, scanner_name="api-security", fingerprint="fp_sqli_fail"
    )

    engine = CrossValidationEngine(db=db_session)
    result = engine.process_findings(project_id=1, scan_id=1, findings=[f_static], dast_status="FAILED")

    assert result[0].verification_status == "INCONCLUSIVE"
    assert "failed" in result[0].verification_explanation.lower()


def test_edgecase_08_dast_unavailable_accurate_explanation(db_session):
    """8. DAST unavailable/not applicable -> explanation accurately describes lack of verification."""
    f_sca = Finding(
        project_id=1, scan_id=1, title="Vulnerable Dependency", description="Outdated lib",
        severity=FindingSeverity.HIGH, category="Vulnerable Component", file_path="package.json",
        source=FindingSource.SCA, scanner_name="sca-dependency", fingerprint="fp_sca_pkg"
    )
    f_ssrf_blocked = Finding(
        project_id=1, scan_id=1, title="BOLA Risk", description="BOLA static",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="GET /api/v1/internal",
        source=FindingSource.API_SECURITY, scanner_name="api-security", fingerprint="fp_ssrf_blocked"
    )

    engine = CrossValidationEngine(db=db_session)
    res_sca = engine.process_findings(project_id=1, scan_id=1, findings=[f_sca])
    assert res_sca[0].verification_status == "UNVERIFIED"
    assert "not applicable" in res_sca[0].verification_explanation.lower()

    res_ssrf = engine.process_findings(project_id=1, scan_id=1, findings=[f_ssrf_blocked], dast_status="SKIPPED_SSRF_BLOCKED")
    assert res_ssrf[0].verification_status == "UNVERIFIED"
    assert "unavailable" in res_ssrf[0].verification_explanation.lower()


def test_edgecase_09_old_finding_default_metadata_safety(db_session):
    """9. Old finding/default metadata -> default values remain safe."""
    f_old = Finding(
        project_id=1, scan_id=1, title="Legacy Finding", description="Old record",
        severity=FindingSeverity.LOW, category="Info", file_path="readme.txt",
        source=FindingSource.SAST
    )
    db_session.add(f_old)
    db_session.commit()

    reloaded = db_session.get(Finding, f_old.id)
    assert reloaded.confidence_score == 50
    assert reloaded.confidence_level == "MEDIUM"
    assert reloaded.verification_status == "UNVERIFIED"
    assert reloaded.correlation_count == 0


def test_edgecase_10_11_correlation_count_and_ids_exclude_self_and_duplicates(db_session):
    """10. correlation_count excludes itself and duplicates. 11. correlated_finding_ids contain distinct valid IDs."""
    f1 = Finding(
        project_id=1, scan_id=1, title="BOLA Threat", description="Static spec",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="GET /api/v1/accounts/{id}",
        source=FindingSource.API_SECURITY, scanner_name="api-security", fingerprint="fp_acct_main"
    )
    f2 = Finding(
        project_id=1, scan_id=1, title="BOLA Code Issue", description="SAST check",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="controllers/accountsController.js",
        source=FindingSource.SAST, scanner_name="semgrep", fingerprint="fp_acct_sub"
    )
    # Duplicate fingerprint copy of f2
    f3 = Finding(
        project_id=1, scan_id=1, title="BOLA Code Issue Dup", description="SAST check dup",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="controllers/accountsController.js",
        source=FindingSource.SAST, scanner_name="semgrep", fingerprint="fp_acct_sub"
    )

    engine = CrossValidationEngine(db=db_session)
    result = engine.process_findings(project_id=1, scan_id=1, findings=[f1, f2, f3])

    assert result[0].correlation_count == 1
    assert result[0].correlated_finding_ids == "fp_acct_sub"
    assert "fp_acct_main" not in (result[0].correlated_finding_ids or "")


def test_edgecase_12_13_confidence_bounded_and_deterministic(db_session):
    """12. confidence always remains 0-100. 13. confidence calculation is deterministic across repeated executions."""
    f = Finding(
        project_id=1, scan_id=1, title="XSS Risk", description="Reflected parameter",
        severity=FindingSeverity.MEDIUM, category="Cross-Site Scripting (XSS)", file_path="GET /search",
        source=FindingSource.DAST, scanner_name="dast-web", fingerprint="fp_xss_det"
    )

    engine = CrossValidationEngine(db=db_session)
    res1 = engine.process_findings(project_id=1, scan_id=1, findings=[f])
    score1 = res1[0].confidence_score

    res2 = engine.process_findings(project_id=1, scan_id=1, findings=[f])
    score2 = res2[0].confidence_score

    assert score1 == score2
    assert 0 <= score1 <= 100
