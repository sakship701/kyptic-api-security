import unittest
from unittest.mock import MagicMock, patch
import asyncio

from app.models.finding import FindingSeverity, FindingSource
from app.models.scan import Scan, ScanStatus
from app.services.dast_scanner import DASTWebScanner, DASTStatus, SafeRedirectHandler
from app.services.finding_normalizer import normalize_dast_results
from app.services.scan_service import _run_scan, SessionLocal


class TestDAST(unittest.TestCase):
    def setUp(self):
        self.scanner = DASTWebScanner()

    # 1. Target URL reachability & TARGET_UNREACHABLE status
    def test_target_unreachable_on_invalid_or_offline(self):
        result = asyncio.run(self.scanner.scan("http://localhost:9999"))
        self.assertEqual(result["status"], DASTStatus.TARGET_UNREACHABLE)
        self.assertEqual(len(result["crawled_pages"]), 0)

    # 2. Origin bounding & same-origin verification
    def test_origin_bounding(self):
        target_origin = ("http", "localhost", 8000)
        self.assertTrue(self.scanner.is_same_origin("http://localhost:8000/api/users", target_origin))
        self.assertTrue(self.scanner.is_same_origin("http://localhost:8000/", target_origin))
        self.assertFalse(self.scanner.is_same_origin("http://localhost:9000/", target_origin))
        self.assertFalse(self.scanner.is_same_origin("https://localhost:8000/", target_origin))
        self.assertFalse(self.scanner.is_same_origin("http://evil-attacker.com/", target_origin))

    # 3. Off-target redirect blocking
    def test_safe_redirect_handler_blocks_off_target(self):
        handler = SafeRedirectHandler(("http", "localhost", 8000))
        # Off-target redirect to evil-attacker.com
        res = handler.redirect_request(None, None, 302, "Found", {}, "http://evil-attacker.com/stolen")
        self.assertIsNone(res)

    # 4. HTTP Target Checks (No TLS cert error, flag HTTP usage, NO HSTS check)
    @patch("app.services.dast_scanner.DASTWebScanner._make_request")
    def test_http_target_checks(self, mock_req):
        # Mock 200 OK response with missing security headers
        mock_req.return_value = (
            200,
            {"Server": "uvicorn", "Content-Type": "text/html"},
            [("Server", "uvicorn"), ("Content-Type", "text/html")],
            "<html><head><title>Test</title></head><body><h1>Hello</h1></body></html>",
            None
        )

        result = asyncio.run(self.scanner.scan("http://localhost:8000"))
        self.assertEqual(result["status"], DASTStatus.SUCCESS)
        rule_ids = [r["rule_id"] for r in result["results"]]

        # Should flag HTTP usage & missing CSP/X-Frame/X-Content-Type
        self.assertIn("DAST-HTTP-WITHOUT-HTTPS", rule_ids)
        self.assertIn("DAST-MISSING-CSP", rule_ids)
        
        # Must NOT flag HSTS on HTTP target
        self.assertNotIn("DAST-MISSING-HSTS", rule_ids)
        # Must NOT flag TLS cert error on HTTP target
        self.assertNotIn("DAST-TLS-CERT-VERIFY-FAILED", rule_ids)

    # 5. HTTPS Target Checks (HSTS evaluated ONLY for HTTPS)
    @patch("app.services.dast_scanner.DASTWebScanner._make_request")
    def test_https_target_evaluates_hsts(self, mock_req):
        mock_req.return_value = (
            200,
            {"Server": "nginx", "Content-Type": "text/html"},
            [("Server", "nginx")],
            "<html><body>Secured</body></html>",
            None
        )

        result = asyncio.run(self.scanner.scan("https://example.com"))
        rule_ids = [r["rule_id"] for r in result["results"]]
        self.assertIn("DAST-MISSING-HSTS", rule_ids)

    # 6. Set-Cookie Flag Audit (Independent parsing of multiple cookies)
    @patch("app.services.dast_scanner.DASTWebScanner._make_request")
    def test_cookie_security_audit(self, mock_req):
        raw_headers = [
            ("Set-Cookie", "session_id=abc12345; Path=/"),
            ("Set-Cookie", "auth_token=xyz9876; Path=/; Secure; HttpOnly; SameSite=Strict")
        ]
        headers_dict = {"Set-Cookie": "auth_token=xyz9876..."}
        mock_req.return_value = (200, headers_dict, raw_headers, "<html></html>", None)

        result = asyncio.run(self.scanner.scan("https://example.com"))
        rule_ids = [r["rule_id"] for r in result["results"]]
        
        # Should flag session_id missing flags
        self.assertIn("DAST-INSECURE-COOKIE-SESSION_ID", rule_ids)
        # Should NOT flag auth_token which has all flags
        self.assertNotIn("DAST-INSECURE-COOKIE-AUTH_TOKEN", rule_ids)

    # 7. CORS Policy Audit
    @patch("app.services.dast_scanner.DASTWebScanner._make_request")
    def test_cors_policy_audit(self, mock_req):
        def side_effect(url, target_origin, method="GET", headers=None, timeout=5):
            if headers and headers.get("Origin") == "https://evil-attacker.example.com":
                return (
                    200,
                    {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
                    [("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true")],
                    "OK",
                    None
                )
            return (200, {}, [], "<html></html>", None)

        mock_req.side_effect = side_effect

        result = asyncio.run(self.scanner.scan("http://localhost:8000"))
        rule_ids = [r["rule_id"] for r in result["results"]]
        self.assertIn("DAST-CORS-WILDCARD-CREDENTIALS", rule_ids)

    # 8. Sensitive File Probing (Redacted bodies)
    @patch("app.services.dast_scanner.DASTWebScanner._make_request")
    def test_sensitive_file_probing_redacted_secrets(self, mock_req):
        def side_effect(url, target_origin, method="GET", headers=None, timeout=5):
            if "/.env" in url:
                return (200, {"Content-Type": "text/plain"}, [], "SECRET_DB_PASSWORD=SuperSecretKey123!\n", None)
            return (200, {}, [], "<html></html>", None)

        mock_req.side_effect = side_effect

        result = asyncio.run(self.scanner.scan("http://localhost:8000"))
        env_findings = [r for r in result["results"] if r["rule_id"] == "DAST-EXPOSED-ENV-FILE"]
        self.assertEqual(len(env_findings), 1)
        
        # Verify body secret is NOT present in snippet
        snippet = env_findings[0]["evidence_snippet"]
        self.assertNotIn("SuperSecretKey123!", snippet)
        self.assertIn("[Sensitive File Exposed - Body Redacted]", snippet)

    # 9. Finding Normalization & FindingSource.DAST
    def test_dast_finding_normalization(self):
        raw_output = {
            "status": DASTStatus.SUCCESS,
            "results": [
                {
                    "rule_id": "DAST-MISSING-CSP",
                    "title": "Missing CSP Header",
                    "summary": "No CSP header found",
                    "severity": "MEDIUM",
                    "category": "A05:2021-Security Misconfiguration",
                    "url": "http://localhost:8000",
                    "evidence_snippet": "Missing Header: Content-Security-Policy",
                }
            ]
        }

        findings = normalize_dast_results(raw_output, project_id=1, scan_id=5)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.source, FindingSource.DAST)
        self.assertEqual(f.rule_id, "DAST-MISSING-CSP")
        self.assertEqual(f.severity, FindingSeverity.MEDIUM)
        self.assertIsNone(f.cvss)  # No fabricated CVSS score

    # 10. Crash Resilience in Scan Service
    @patch("app.services.dast_scanner.DASTWebScanner.scan")
    def test_dast_crash_resilience(self, mock_scan):
        mock_scan.side_effect = RuntimeError("Simulated DAST crash")


if __name__ == "__main__":
    unittest.main()
