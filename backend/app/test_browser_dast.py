import pytest
from app.models.api_endpoint import ApiEndpoint
from app.schemas.targeted_verification import TargetedVerificationRequest, TargetedVerificationStatus
from app.security.verifiers.browser_verifiers import DomXssVerifier
from app.security.vulnerability_registry import VulnerabilityRegistry
from app.services.browser_dast_service import BrowserDastService, is_same_origin, get_origin
from app.services.dast_http_client import DastAuthContext
from app.services.dast_probes import DastVerificationStatus
from app.services.greybox_context_engine import map_vulnerability_to_probes
from app.services.targeted_verification_engine import TargetedVerificationEngine


def test_vulnerability_registry_dom_xss_definition():
    dom_xss_def = VulnerabilityRegistry.get_vulnerability("DOM_XSS")
    assert dom_xss_def is not None
    assert dom_xss_def.vulnerability_id == "DOM_XSS"
    assert dom_xss_def.implemented is True
    assert dom_xss_def.supported is True
    assert dom_xss_def.white_box_supported is True
    assert dom_xss_def.black_box_supported is True
    assert dom_xss_def.grey_box_supported is True
    assert dom_xss_def.targeted_verification_supported is True


def test_browser_dast_service_same_origin_check():
    target_origin = get_origin("https://example.com:443")
    assert is_same_origin("https://example.com/about", target_origin) is True
    assert is_same_origin("https://example.com/api/v1/users", target_origin) is True
    assert is_same_origin("https://attacker.com/steal", target_origin) is False
    assert is_same_origin("http://example.com/about", target_origin) is False


def test_browser_dast_service_ssrf_safety_block():
    service = BrowserDastService()
    # Synchronous test for async method using asyncio.run
    import asyncio
    res = asyncio.run(service.run_browser_dast("http://127.0.0.1:8000"))
    assert res.status == "SKIPPED_SSRF_BLOCKED"
    assert "SSRF safety guard" in res.logs[1]


def test_targeted_verification_engine_dom_xss_verifier_registration():
    engine = TargetedVerificationEngine()
    assert "DOM_XSS" in engine.verifiers


def test_greybox_context_engine_dom_xss_mapping():
    probes, reason = map_vulnerability_to_probes("DOM_XSS")
    assert probes == ["DOM_XSS"]
    assert "Playwright" in reason


def test_dom_xss_verifier_fallback_when_browser_unsupported():
    verifier = DomXssVerifier()
    ep = ApiEndpoint(id=1, project_id=1, path="/app", method="GET")
    auth_ctx = DastAuthContext(auth_type="NONE")

    res = verifier.verify(endpoint=ep, client=None, base_url="http://example.com", auth_context=auth_ctx)
    assert res.status in (DastVerificationStatus.INCONCLUSIVE, DastVerificationStatus.VERIFIED_SECURE)
