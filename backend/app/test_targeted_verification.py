import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.models.api_endpoint import ApiEndpoint
from app.security.vulnerability_registry import VulnerabilityRegistry, VulnerabilityDefinition
from app.schemas.targeted_verification import TargetedVerificationRequest, TargetedVerificationStatus
from app.services.targeted_verification_engine import TargetedVerificationEngine, TargetedVerificationContext
from app.services.dast_probes import DastProbeResult, DastVerificationStatus, DastProbeType
from app.services.dast_http_client import DastAuthContext, DastResponse


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    project = Project(id=1, name="Test Targeted Project", source_type="OPENAPI", source_status="READY", api_target_url="http://test.api", api_dast_enabled=True)
    scan = Scan(id=1, project_id=1, status=ScanStatus.COMPLETED)
    session.add(project)
    session.add(scan)
    session.commit()

    yield session
    session.close()


@patch("app.services.targeted_verification_engine.is_ssrf_safe_url", return_value=(True, "Safe"))
def test_01_bola_finding_selects_bola_verifier(mock_ssrf, db_session):
    ep = ApiEndpoint(id=1, project_id=1, path="/api/v1/users/{id}", method="GET")
    db_session.add(ep)
    db_session.commit()

    f = Finding(
        project_id=1, scan_id=1, title="BOLA Vulnerability", description="BOLA static check",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="API:GET:/api/v1/users/{id}",
        source=FindingSource.API_SECURITY, scanner_name="api-security", fingerprint="fp_tv_01"
    )
    db_session.add(f)
    db_session.commit()

    engine = TargetedVerificationEngine(db=db_session)
    res = engine.verify_finding(project_id=1, finding_id=f.id)

    assert res.probe_type == "BOLA"
    assert res.vulnerability_id == "BOLA"


@patch("app.services.targeted_verification_engine.is_ssrf_safe_url", return_value=(True, "Safe"))
def test_02_broken_auth_finding_selects_auth_verifier(mock_ssrf, db_session):
    ep = ApiEndpoint(id=2, project_id=1, path="/api/v1/secure", method="GET")
    db_session.add(ep)
    db_session.commit()

    f = Finding(
        project_id=1, scan_id=1, title="Broken Auth", description="Auth check",
        severity=FindingSeverity.HIGH, category="BROKEN_AUTH", file_path="API:GET:/api/v1/secure",
        source=FindingSource.API_SECURITY, scanner_name="api-security", fingerprint="fp_tv_02"
    )
    db_session.add(f)
    db_session.commit()

    engine = TargetedVerificationEngine(db=db_session)
    res = engine.verify_finding(project_id=1, finding_id=f.id)

    assert res.probe_type == "AUTH_ENFORCEMENT"


@patch("app.services.targeted_verification_engine.is_ssrf_safe_url", return_value=(True, "Safe"))
def test_03_mass_assignment_finding_selects_ma_verifier(mock_ssrf, db_session):
    ep = ApiEndpoint(id=3, project_id=1, path="/api/v1/users", method="POST")
    db_session.add(ep)
    db_session.commit()

    f = Finding(
        project_id=1, scan_id=1, title="Mass Assignment", description="MA check",
        severity=FindingSeverity.HIGH, category="MASS_ASSIGNMENT", file_path="API:POST:/api/v1/users",
        source=FindingSource.API_SECURITY, scanner_name="api-security", fingerprint="fp_tv_03"
    )
    db_session.add(f)
    db_session.commit()

    engine = TargetedVerificationEngine(db=db_session)
    res = engine.verify_finding(project_id=1, finding_id=f.id)

    assert res.probe_type == "MASS_ASSIGNMENT"


@patch("app.services.targeted_verification_engine.is_ssrf_safe_url", return_value=(True, "Safe"))
def test_04_rate_limit_finding_selects_rl_verifier(mock_ssrf, db_session):
    ep = ApiEndpoint(id=4, project_id=1, path="/api/v1/login", method="POST")
    db_session.add(ep)
    db_session.commit()

    f = Finding(
        project_id=1, scan_id=1, title="Rate Limit Issue", description="RL check",
        severity=FindingSeverity.HIGH, category="RATE_LIMIT", file_path="API:POST:/api/v1/login",
        source=FindingSource.API_SECURITY, scanner_name="api-security", fingerprint="fp_tv_04"
    )
    db_session.add(f)
    db_session.commit()

    engine = TargetedVerificationEngine(db=db_session)
    res = engine.verify_finding(project_id=1, finding_id=f.id)

    assert res.probe_type == "RATE_LIMITING"


def test_05_06_07_08_09_unsupported_vulnerability_returns_not_supported(db_session):
    req_ssrf = TargetedVerificationRequest(target_url="http://test.api", path="/users", vulnerability_id="SSRF")
    req_xxe = TargetedVerificationRequest(target_url="http://test.api", path="/users", vulnerability_id="XXE")
    req_jwt = TargetedVerificationRequest(target_url="http://test.api", path="/users", vulnerability_id="JWT_VULNERABILITY")

    engine = TargetedVerificationEngine(db=db_session)

    assert engine.verify_standalone(req_ssrf).status == TargetedVerificationStatus.NOT_SUPPORTED
    assert engine.verify_standalone(req_xxe).status == TargetedVerificationStatus.NOT_SUPPORTED
    assert engine.verify_standalone(req_jwt).status == TargetedVerificationStatus.NOT_SUPPORTED


def test_10_11_12_finding_and_project_validation_and_ssrf_blocking(db_session):
    engine = TargetedVerificationEngine(db=db_session)

    # 10. Finding not found
    res1 = engine.verify_finding(project_id=1, finding_id=999)
    assert res1.status == TargetedVerificationStatus.INCONCLUSIVE

    # 11. Project mismatch
    ep = ApiEndpoint(id=10, project_id=1, path="/api/test", method="GET")
    db_session.add(ep)
    db_session.commit()

    f = Finding(
        project_id=1, scan_id=1, title="Mismatch Finding", description="Mismatch check",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="API:GET:/api/test",
        source=FindingSource.API_SECURITY, fingerprint="fp_tv_mismatch"
    )
    db_session.add(f)
    db_session.commit()

    res_mismatch = engine.verify_finding(project_id=99, finding_id=f.id)
    assert res_mismatch.status == TargetedVerificationStatus.INCONCLUSIVE

    # 12 & 14 & 15. SSRF / Private Target Blocked
    req_ssrf_target = TargetedVerificationRequest(target_url="http://169.254.169.254", path="/latest/meta-data", vulnerability_id="BOLA")
    res2 = engine.verify_standalone(req_ssrf_target)
    assert res2.status == TargetedVerificationStatus.INCONCLUSIVE
    assert res2.safe_to_execute is False
    assert "security validation" in res2.explanation or "SSRF" in res2.explanation


@patch("app.services.targeted_verification_engine.is_ssrf_safe_url", return_value=(True, "Safe"))
def test_13_standalone_verification_works_without_finding(mock_ssrf, db_session):
    req = TargetedVerificationRequest(target_url="http://test.api", http_method="GET", path="/api/v1/health", vulnerability_id="RATE_LIMIT")
    engine = TargetedVerificationEngine(db=db_session)
    res = engine.verify_standalone(req)

    assert res.target_url == "http://test.api"
    assert res.path == "/api/v1/health"
    assert res.vulnerability_id == "RATE_LIMIT"


@patch("app.services.targeted_verification_engine.is_ssrf_safe_url", return_value=(True, "Safe"))
@patch("app.services.dast_probes.DastProbeEngine.probe_bola")
def test_16_confirmed_vulnerability_produces_confirmed_status(mock_probe_bola, mock_ssrf, db_session):
    mock_probe_bola.return_value = DastProbeResult(
        endpoint_id=1,
        probe_type=DastProbeType.BOLA,
        status=DastVerificationStatus.VERIFIED_VULNERABLE,
        evidence="BOLA access allowed for alternate ID 99999",
        response_status=200,
        response_snippet="{'user': 'admin'}",
    )
    req = TargetedVerificationRequest(target_url="http://test.api", http_method="GET", path="/api/v1/users/{id}", vulnerability_id="BOLA")
    engine = TargetedVerificationEngine(db=db_session)
    res = engine.verify_standalone(req)

    assert res.status == TargetedVerificationStatus.CONFIRMED
    assert "BOLA access allowed" in res.explanation


@patch("app.services.targeted_verification_engine.is_ssrf_safe_url", return_value=(True, "Safe"))
@patch("app.services.dast_probes.DastProbeEngine.probe_bola")
def test_17_secure_result_produces_not_confirmed_status(mock_probe_bola, mock_ssrf, db_session):
    mock_probe_bola.return_value = DastProbeResult(
        endpoint_id=1,
        probe_type=DastProbeType.BOLA,
        status=DastVerificationStatus.VERIFIED_SECURE,
        evidence="Alternate object request returned HTTP 403 Forbidden.",
        response_status=403,
    )
    req = TargetedVerificationRequest(target_url="http://test.api", http_method="GET", path="/api/v1/users/{id}", vulnerability_id="BOLA")
    engine = TargetedVerificationEngine(db=db_session)
    res = engine.verify_standalone(req)

    assert res.status == TargetedVerificationStatus.NOT_CONFIRMED
    assert "403 Forbidden" in res.explanation


@patch("app.services.targeted_verification_engine.is_ssrf_safe_url", return_value=(True, "Safe"))
@patch("app.services.dast_probes.DastProbeEngine.probe_bola")
def test_18_19_20_inconclusive_results(mock_probe_bola, mock_ssrf, db_session):
    mock_probe_bola.return_value = DastProbeResult(
        endpoint_id=1,
        probe_type=DastProbeType.BOLA,
        status=DastVerificationStatus.INCONCLUSIVE,
        evidence="Request timed out after 5 seconds.",
    )
    req = TargetedVerificationRequest(target_url="http://test.api", http_method="GET", path="/api/v1/users/{id}", vulnerability_id="BOLA")
    engine = TargetedVerificationEngine(db=db_session)
    res = engine.verify_standalone(req)

    assert res.status == TargetedVerificationStatus.INCONCLUSIVE
    assert "timed out" in res.explanation


@patch("app.services.targeted_verification_engine.is_ssrf_safe_url", return_value=(True, "Safe"))
def test_21_duplicate_concurrent_verification_blocked(mock_ssrf, db_session):
    engine = TargetedVerificationEngine(db=db_session)
    ctx = TargetedVerificationContext(
        finding_id=1, project_id=1, endpoint_id=1, target_url="http://test.api",
        http_method="GET", path="/api/test", vulnerability_id="BOLA", vulnerability_family="AUTHORIZATION",
        probe_type="BOLA", hypothesis="Concurrent test", source="TEST"
    )

    lock_key = (1, 1, "http://test.api", "/api/test", "BOLA")
    TargetedVerificationEngine._active_verifications.add(lock_key)

    try:
        res = engine.execute_targeted_verification(ctx, endpoint_model=ApiEndpoint(id=1, project_id=1, path="/api/test", method="GET"), auth_context=DastAuthContext())
        assert res.status == TargetedVerificationStatus.INCONCLUSIVE
        assert "already in progress" in res.explanation
    finally:
        TargetedVerificationEngine._active_verifications.discard(lock_key)


@patch("app.services.targeted_verification_engine.is_ssrf_safe_url", return_value=(True, "Safe"))
def test_22_sensitive_headers_tokens_redacted(mock_ssrf, db_session):
    req = TargetedVerificationRequest(
        target_url="http://test.api", http_method="GET", path="/api/v1/secret",
        vulnerability_id="BROKEN_AUTH", auth_type="BEARER", auth_token="super_secret_jwt_token_12345"
    )
    engine = TargetedVerificationEngine(db=db_session)
    res = engine.verify_standalone(req)

    assert "super_secret_jwt_token_12345" not in res.explanation
    if res.evidence:
        assert "super_secret_jwt_token_12345" not in res.evidence


@patch("app.services.targeted_verification_engine.is_ssrf_safe_url", return_value=(True, "Safe"))
def test_23_triage_state_preserved(mock_ssrf, db_session):
    ep = ApiEndpoint(id=5, project_id=1, path="/api/v1/orders", method="GET")
    db_session.add(ep)
    db_session.commit()

    f = Finding(
        project_id=1, scan_id=1, title="Resolved BOLA", description="Fixed issue",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="API:GET:/api/v1/orders",
        source=FindingSource.API_SECURITY, status=FindingStatus.RESOLVED, fingerprint="fp_tv_triage"
    )
    db_session.add(f)
    db_session.commit()

    engine = TargetedVerificationEngine(db=db_session)
    res = engine.verify_finding(project_id=1, finding_id=f.id)

    db_session.refresh(f)
    assert f.status == FindingStatus.RESOLVED  # Analyst triage state preserved


def test_27_28_29_registry_taxonomy_integrity():
    sqli_def = VulnerabilityRegistry.get_vulnerability("SQL_INJECTION")
    assert sqli_def is not None
    assert sqli_def.registered is True
    assert sqli_def.implemented is True
    assert sqli_def.supported is True

    ssrf_def = VulnerabilityRegistry.get_vulnerability("SSRF")
    assert ssrf_def is not None
    assert ssrf_def.registered is True
    assert ssrf_def.implemented is False
    assert ssrf_def.supported is False

    bola_def = VulnerabilityRegistry.get_vulnerability("BOLA")
    assert bola_def is not None
    assert bola_def.registered is True
    assert bola_def.implemented is True
    assert bola_def.supported is True


@patch("app.services.targeted_verification_engine.is_ssrf_safe_url", return_value=(True, "Safe"))
def test_30_standalone_target_does_not_trigger_unrelated_probes(mock_ssrf, db_session):
    with patch("app.services.dast_probes.DastProbeEngine.probe_bola") as mock_bola, \
         patch("app.services.dast_probes.DastProbeEngine.probe_auth_enforcement") as mock_auth, \
         patch("app.services.dast_probes.DastProbeEngine.probe_mass_assignment") as mock_ma, \
         patch("app.services.dast_probes.DastProbeEngine.probe_rate_limiting") as mock_rl:

        mock_bola.return_value = DastProbeResult(1, DastProbeType.BOLA, DastVerificationStatus.VERIFIED_SECURE)

        req = TargetedVerificationRequest(target_url="http://test.api", http_method="GET", path="/api/v1/users/{id}", vulnerability_id="BOLA")
        engine = TargetedVerificationEngine(db=db_session)
        res = engine.verify_standalone(req)

        assert res.probe_type == "BOLA"
        assert mock_bola.called is True
        assert mock_auth.called is False
        assert mock_ma.called is False
        assert mock_rl.called is False


@patch("app.services.targeted_verification_engine.is_ssrf_safe_url", return_value=(True, "Safe"))
@patch("app.services.dast_probes.DastProbeEngine.probe_bola")
def test_31_no_hardcoded_confidence_score_assignment(mock_probe_bola, mock_ssrf, db_session):
    mock_probe_bola.return_value = DastProbeResult(
        endpoint_id=1,
        probe_type=DastProbeType.BOLA,
        status=DastVerificationStatus.VERIFIED_VULNERABLE,
        evidence="BOLA access confirmed",
        response_status=200,
    )
    ep = ApiEndpoint(id=6, project_id=1, path="/api/v1/accounts", method="GET")
    db_session.add(ep)
    db_session.commit()

    f = Finding(
        project_id=1, scan_id=1, title="BOLA Test", description="Check BOLA",
        severity=FindingSeverity.HIGH, category="BOLA", file_path="API:GET:/api/v1/accounts",
        source=FindingSource.API_SECURITY, confidence_score=50, fingerprint="fp_tv_no_hardcode"
    )
    db_session.add(f)
    db_session.commit()

    engine = TargetedVerificationEngine(db=db_session)
    engine.verify_finding(project_id=1, finding_id=f.id)

    db_session.refresh(f)
    # Verification status is updated to VERIFIED_VULNERABLE, but confidence_score remains unchanged by TargetedVerificationEngine (Phase 2 retains authority)
    assert f.verification_status == "VERIFIED_VULNERABLE"
    assert f.confidence_score == 50  # Score was not artificially overwritten to 95
