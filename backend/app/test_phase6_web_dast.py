import pytest
from app.services.dast_scanner import DASTStatus, DASTWebScanner, SafeRedirectHandler


def test_dast_same_origin_restriction():
    scanner = DASTWebScanner()
    target_origin = ("http", "example.com", 80)

    # Same origin URLs
    assert scanner.is_same_origin("http://example.com/login", target_origin) is True
    assert scanner.is_same_origin("http://example.com:80/api", target_origin) is True

    # Off-target origin URLs MUST BE BLOCKED
    assert scanner.is_same_origin("http://malicious.com/steal", target_origin) is False
    assert scanner.is_same_origin("https://example.com/login", target_origin) is False  # Scheme mismatch
    assert scanner.is_same_origin("http://example.com:8080/login", target_origin) is False  # Port mismatch


def test_dast_safe_redirect_handler_ssrf_revalidation():
    handler = SafeRedirectHandler(target_origin=("http", "example.com", 80))

    # Redirect to private IP (SSRF attempt) MUST BE BLOCKED
    blocked_req = handler.redirect_request(
        req=None, fp=None, code=302, msg="Found", headers={}, newurl="http://169.254.169.254/latest/meta-data/"
    )
    assert blocked_req is None

    # Redirect to off-target external domain MUST BE BLOCKED
    blocked_ext = handler.redirect_request(
        req=None, fp=None, code=302, msg="Found", headers={}, newurl="http://evil.com/phish"
    )
    assert blocked_ext is None


def test_dast_unreachable_target_status():
    scanner = DASTWebScanner()
    # Unreachable domain must return TARGET_UNREACHABLE status instead of reporting "0 vulnerabilities / secure"
    import asyncio
    res = asyncio.run(scanner.scan("http://non-existent-invalid-domain-12345.local"))
    assert res["status"] in (DASTStatus.TARGET_UNREACHABLE, DASTStatus.SCANNER_ERROR)
    assert len(res["results"]) == 0
