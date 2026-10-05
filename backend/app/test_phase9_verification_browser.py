import pytest
from unittest.mock import MagicMock, patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.models.api_endpoint import ApiEndpoint
from app.schemas.targeted_verification import TargetedVerificationRequest, TargetedVerificationStatus
from app.services.targeted_verification_engine import TargetedVerificationEngine
from app.services.browser_dast_service import BrowserDastService, is_same_origin, get_origin
from app.services.dast_probes import DastProbeResult, DastVerificationStatus, DastProbeType
from app.services.dast_http_client import DastAuthContext, DastResponse
from app.security.verifiers.web_verifiers import CsrfVerifier
from app.security.vulnerability_registry import VulnerabilityRegistry


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    project = Project(id=1, name="Phase 9 Verification Project", source_type="OPENAPI", source_status="READY", api_target_url="http://test.api", api_dast_enabled=True)
    scan = Scan(id=1, project_id=1, status=ScanStatus.COMPLETED)
    session.add(project)
    session.add(scan)
    session.commit()

    yield session
    session.close()


def test_01_vulnerability_registry_status_matrix():
    """Verify registry explicitly declares implemented, supported, and mode flags for vulnerabilities."""
    sqli = VulnerabilityRegistry.get_vulnerability("SQL_INJECTION")
    assert sqli.implemented is True
    assert sqli.supported is True

    ssrf = VulnerabilityRegistry.get_vulnerability("SSRF")
    assert ssrf.implemented is False
    assert ssrf.supported is False


def test_02_targeted_verification_result_semantics(db_session):
    """Verify result semantics: CONFIRMED, NOT_CONFIRMED, INCONCLUSIVE, NOT_SUPPORTED."""
    engine = TargetedVerificationEngine(db=db_session)

    # NOT_SUPPORTED
    req_unsupported = TargetedVerificationRequest(target_url="http://test.api", path="/api", vulnerability_id="SSRF")
    res1 = engine.verify_standalone(req_unsupported)
    assert res1.status == TargetedVerificationStatus.NOT_SUPPORTED

    # INCONCLUSIVE (SSRF guard block)
    req_ssrf = TargetedVerificationRequest(target_url="http://169.254.169.254", path="/latest/meta-data", vulnerability_id="BOLA")
    res2 = engine.verify_standalone(req_ssrf)
    assert res2.status == TargetedVerificationStatus.INCONCLUSIVE


@patch("app.services.targeted_verification_engine.is_ssrf_safe_url", return_value=(True, "Safe"))
@patch("app.services.dast_probes.DastProbeEngine.probe_bola")
def test_03_confirmed_vs_not_confirmed_result(mock_probe, mock_ssrf, db_session):
    engine = TargetedVerificationEngine(db=db_session)
    req = TargetedVerificationRequest(target_url="http://test.api", path="/api/v1/users/{id}", vulnerability_id="BOLA")

    # CONFIRMED
    mock_probe.return_value = DastProbeResult(1, DastProbeType.BOLA, DastVerificationStatus.VERIFIED_VULNERABLE, evidence="BOLA confirmed")
    res_conf = engine.verify_standalone(req)
    assert res_conf.status == TargetedVerificationStatus.CONFIRMED

    # NOT_CONFIRMED
    mock_probe.return_value = DastProbeResult(1, DastProbeType.BOLA, DastVerificationStatus.VERIFIED_SECURE, evidence="403 Forbidden")
    res_not_conf = engine.verify_standalone(req)
    assert res_not_conf.status == TargetedVerificationStatus.NOT_CONFIRMED


def test_04_browser_dast_same_origin_and_ssrf():
    """Verify Browser DAST same-origin policy and SSRF safety controls."""
    origin = get_origin("https://example.com:443")
    assert is_same_origin("https://example.com/page", origin) is True
    assert is_same_origin("https://malicious.com/steal", origin) is False

    service = BrowserDastService()
    import asyncio
    res = asyncio.run(service.run_browser_dast("http://127.0.0.1:8000"))
    assert res.status == "SKIPPED_SSRF_BLOCKED"


def test_05_csrf_vulnerable_fixture_full_evidence_chain():
    """Vulnerable CSRF fixture: State-changing POST + Cookie session + Unvalidated cross-origin request returns HTTP 200 OK -> CONFIRMED."""
    verifier = CsrfVerifier()
    ep = ApiEndpoint(id=1, project_id=1, path="/api/v1/user/email", method="POST")
    client = MagicMock()

    # Mock cross-origin request response returning HTTP 200 OK without SameSite cookies or anti-CSRF checks
    resp = DastResponse(status_code=200, headers={"Content-Type": "application/json"}, body_preview='{"status":"email_updated"}', elapsed_ms=50.0, final_url="http://test.api/api/v1/user/email")
    client.execute_request.return_value = resp

    auth_ctx = DastAuthContext(auth_type="COOKIE", token_or_key="session_id=abc123xyz")
    res = verifier.verify(endpoint=ep, client=client, base_url="http://test.api", auth_context=auth_ctx)

    assert res.status == DastVerificationStatus.VERIFIED_VULNERABLE
    assert "CSRF Confirmed" in res.evidence
    assert "attacker-cross-origin.com" in res.evidence


def test_06_csrf_safe_fixture_samesite_and_token_protection():
    """Safe CSRF fixture: Enforces SameSite=Strict cookie policy or rejects cross-origin request with 403 Forbidden -> VERIFIED_SECURE."""
    verifier = CsrfVerifier()
    ep = ApiEndpoint(id=2, project_id=1, path="/api/v1/user/email", method="POST")
    client = MagicMock()

    # Case A: SameSite=Strict active
    resp_samesite = DastResponse(status_code=200, headers={"Set-Cookie": "session_id=abc; SameSite=Strict"}, body_preview='{"status":"ok"}', elapsed_ms=50.0, final_url="http://test.api/api/v1/user/email")
    client.execute_request.return_value = resp_samesite

    auth_ctx = DastAuthContext(auth_type="COOKIE", token_or_key="session_id=abc")
    res_samesite = verifier.verify(endpoint=ep, client=client, base_url="http://test.api", auth_context=auth_ctx)
    assert res_samesite.status == DastVerificationStatus.VERIFIED_SECURE

    # Case B: Cross-origin request denied (HTTP 403 Forbidden)
    resp_forbidden = DastResponse(status_code=403, headers={}, body_preview='{"detail":"Invalid Origin header"}', elapsed_ms=50.0, final_url="http://test.api/api/v1/user/email")
    client.execute_request.return_value = resp_forbidden
    res_forbidden = verifier.verify(endpoint=ep, client=client, base_url="http://test.api", auth_context=auth_ctx)
    assert res_forbidden.status == DastVerificationStatus.VERIFIED_SECURE


def test_07_csrf_non_cookie_auth_is_verified_secure():
    """Safe CSRF fixture: API relying on Bearer token header authentication is not vulnerable to browser cross-origin CSRF -> VERIFIED_SECURE."""
    verifier = CsrfVerifier()
    ep = ApiEndpoint(id=3, project_id=1, path="/api/v1/transfer", method="POST")
    client = MagicMock()

    auth_ctx = DastAuthContext(auth_type="BEARER", token_or_key="eyJhbGciOi...")
    res = verifier.verify(endpoint=ep, client=client, base_url="http://test.api", auth_context=auth_ctx)

    assert res.status == DastVerificationStatus.VERIFIED_SECURE
    assert "BEARER' header authentication" in res.evidence


def test_08_csrf_missing_token_without_2xx_returns_inconclusive():
    """CSRF test: Missing anti-CSRF token or missing header alone on failing request (e.g. 500 error) returns INCONCLUSIVE."""
    verifier = CsrfVerifier()
    ep = ApiEndpoint(id=4, project_id=1, path="/api/v1/action", method="POST")
    client = MagicMock()

    resp_error = DastResponse(status_code=500, headers={}, body_preview='{"error":"Server Error"}', elapsed_ms=50.0, final_url="http://test.api/api/v1/action")
    client.execute_request.return_value = resp_error

    auth_ctx = DastAuthContext(auth_type="COOKIE", token_or_key="session_id=xyz")
    res = verifier.verify(endpoint=ep, client=client, base_url="http://test.api", auth_context=auth_ctx)

    assert res.status == DastVerificationStatus.INCONCLUSIVE
    assert "Missing complete exploitability evidence chain" in res.evidence
