import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.models.finding import FindingSeverity, FindingSource
from app.services.dast_scanner import DASTStatus, DASTWebScanner
from app.services.detect_secrets_scanner import DetectSecretsScanner
from app.services.finding_normalizer import normalize_detect_secrets_results, normalize_semgrep_results
from app.services.semgrep_scanner import SemgrepSASTScanner


class MockTargetAPIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress server logs during test run

    def do_GET(self):
        auth_hdr = self.headers.get("Authorization", "")
        path = self.path

        # A. Secure authenticated endpoint vs Broken Authentication
        if path == "/api/v1/secure-data":
            if auth_hdr == "Bearer valid_token_123":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "success", "data": "confidential_record"}')
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Unauthorized access"}')

        # B. Vulnerable unauthenticated endpoint returning sensitive field
        elif path == "/api/v1/vulnerable-data":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"user": "admin", "access_token": "secret_jwt_token_xyz_888"}')

        # C. BOLA/IDOR endpoint
        elif path.startswith("/api/v1/documents/"):
            doc_id = path.split("/")[-1]
            if doc_id == "doc_a" and auth_hdr == "Bearer token_user_a":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"document": "Document A Content"}')
            elif doc_id == "doc_b" and auth_hdr == "Bearer token_user_b":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"document": "Document B Content"}')
            elif (doc_id == "doc_b" and auth_hdr == "Bearer token_user_a") or (doc_id == "doc_a" and auth_hdr == "Bearer token_user_b"):
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b'{"error": "Forbidden - BOLA blocked"}')
            else:
                self.send_response(404)
                self.end_headers()

        # F. Rate Limited endpoint
        elif path == "/api/v1/rate-limited":
            self.send_response(429)
            self.send_header("Retry-After", "30")
            self.end_headers()
            self.wfile.write(b'{"error": "Too Many Requests"}')

        else:
            self.send_response(200)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(b"<html><body>Kyptic Target Web App</body></html>")

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else ""

        # D. Mass Assignment endpoint
        if self.path == "/api/v1/users/profile":
            try:
                body_json = json.loads(post_body) if post_body else {}
            except Exception:
                body_json = {}

            if "is_admin" in body_json or "role" in body_json:
                # Returns modified state confirming mass assignment persistence
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "updated", "is_admin": body_json.get("is_admin", False), "role": body_json.get("role", "user")}).encode())
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "updated", "is_admin": false, "role": "user"}')


@pytest.fixture(scope="module")
def real_http_server():
    server = HTTPServer(("127.0.0.1", 8999), MockTargetAPIHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(0.2)
    yield "http://127.0.0.1:8999"
    server.shutdown()


def test_bola_idor_cross_user_isolation(real_http_server):
    import urllib.request
    base_url = real_http_server

    # User A -> Resource A = Allowed (200)
    req_a_a = urllib.request.Request(f"{base_url}/api/v1/documents/doc_a", headers={"Authorization": "Bearer token_user_a"})
    with urllib.request.urlopen(req_a_a) as res:
        assert res.status == 200

    # User A -> Resource B = Blocked (403)
    req_a_b = urllib.request.Request(f"{base_url}/api/v1/documents/doc_b", headers={"Authorization": "Bearer token_user_a"})
    try:
        urllib.request.urlopen(req_a_b)
        pytest.fail("Should have returned 403 Forbidden")
    except urllib.error.HTTPError as err:
        assert err.code == 403

    # User B -> Resource B = Allowed (200)
    req_b_b = urllib.request.Request(f"{base_url}/api/v1/documents/doc_b", headers={"Authorization": "Bearer token_user_b"})
    with urllib.request.urlopen(req_b_b) as res:
        assert res.status == 200

    # User B -> Resource A = Blocked (403)
    req_b_a = urllib.request.Request(f"{base_url}/api/v1/documents/doc_a", headers={"Authorization": "Bearer token_user_b"})
    try:
        urllib.request.urlopen(req_b_a)
        pytest.fail("Should have returned 403 Forbidden")
    except urllib.error.HTTPError as err:
        assert err.code == 403


def test_broken_auth_and_unauthenticated_behavior(real_http_server):
    import urllib.request
    base_url = real_http_server

    # Valid token succeeds (200)
    req_valid = urllib.request.Request(f"{base_url}/api/v1/secure-data", headers={"Authorization": "Bearer valid_token_123"})
    with urllib.request.urlopen(req_valid) as res:
        assert res.status == 200

    # Missing / Invalid token fails (401)
    req_invalid = urllib.request.Request(f"{base_url}/api/v1/secure-data", headers={"Authorization": "Bearer invalid_token"})
    try:
        urllib.request.urlopen(req_invalid)
        pytest.fail("Should have returned 401 Unauthorized")
    except urllib.error.HTTPError as err:
        assert err.code == 401


def test_mass_assignment_sentinel_injection(real_http_server):
    import urllib.request
    base_url = real_http_server

    payload = json.dumps({"name": "User Test", "is_admin": True}).encode("utf-8")
    req = urllib.request.Request(f"{base_url}/api/v1/users/profile", data=payload, headers={"Content-Type": "application/json"}, method="POST")

    with urllib.request.urlopen(req) as res:
        assert res.status == 200
        data = json.loads(res.read().decode())
        # Server accepted and returned is_admin: True, demonstrating mass assignment vulnerability
        assert data.get("is_admin") is True


def test_rate_limiting_retry_after(real_http_server):
    import urllib.request
    base_url = real_http_server

    req = urllib.request.Request(f"{base_url}/api/v1/rate-limited")
    try:
        urllib.request.urlopen(req)
        pytest.fail("Should have returned 429 Too Many Requests")
    except urllib.error.HTTPError as err:
        assert err.code == 429
        assert err.headers.get("Retry-After") == "30"


def test_web_dast_unreachable_target_handling():
    scanner = DASTWebScanner()
    import asyncio
    res = asyncio.run(scanner.scan("http://invalid-unreachable-host-9999.local"))
    # Unreachable target must return TARGET_UNREACHABLE status, never 0 vulnerabilities / secure
    assert res["status"] in (DASTStatus.TARGET_UNREACHABLE, DASTStatus.SCANNER_ERROR)
