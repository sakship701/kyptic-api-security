import io
import unittest
import urllib.request
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.project import Project
from app.services.dast_http_client import (
    DastHttpClient,
    DastAuthContext,
    redact_secrets,
    sanitize_headers,
    DastSsrfError,
    DastTimeoutError,
    DastPayloadTooLargeError,
    DastTargetInvalidError,
)

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"


class TestDastHttpClientPhase1(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            SQLALCHEMY_DATABASE_URL,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.db = self.SessionLocal()

        def override_get_db():
            db = self.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

        self.project = Project(name="DAST Phase 1 Project", technology="Python/FastAPI")
        self.db.add(self.project)
        self.db.commit()
        self.db.refresh(self.project)

    def tearDown(self):
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=self.engine)
        self.db.close()

    def test_ssrf_private_ip_rejected(self):
        dast_client = DastHttpClient(allow_localhost=False)
        with self.assertRaises(DastSsrfError):
            dast_client.execute_request("http://127.0.0.1:8000/api")

        with self.assertRaises(DastSsrfError):
            dast_client.execute_request("http://10.0.0.1/admin")

        with self.assertRaises(DastSsrfError):
            dast_client.execute_request("http://169.254.169.254/latest/meta-data")

    def test_invalid_scheme_rejected(self):
        dast_client = DastHttpClient(allow_localhost=False)
        with self.assertRaises(DastSsrfError):
            dast_client.execute_request("file:///etc/passwd")

        with self.assertRaises(DastSsrfError):
            dast_client.execute_request("ftp://example.com/file")

    def test_malformed_url_rejected(self):
        dast_client = DastHttpClient(allow_localhost=False)
        with self.assertRaises(DastSsrfError):
            dast_client.execute_request("not-a-valid-url")

    def test_localhost_policy_explicit_control(self):
        dast_client_strict = DastHttpClient(allow_localhost=False)
        with self.assertRaises(DastSsrfError):
            dast_client_strict.execute_request("http://localhost:8000/health")

        dast_client_local = DastHttpClient(allow_localhost=True)
        # Mock actual urllib.request.build_opener call to prevent making actual socket calls
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.geturl.return_value = "http://localhost:8000/health"
        mock_response.read.return_value = b'{"status":"ok"}'

        with patch("urllib.request.build_opener") as mock_opener:
            mock_opener_instance = MagicMock()
            mock_opener_instance.open.return_value.__enter__.return_value = mock_response
            mock_opener.return_value = mock_opener_instance

            resp = dast_client_local.execute_request("http://localhost:8000/health")
            self.assertEqual(resp.status_code, 200)
            self.assertIn("status", resp.body_preview)

    def test_payload_size_limit_enforced(self):
        dast_client = DastHttpClient(allow_localhost=True)
        large_payload = "A" * (600 * 1024)  # 600 KB exceeds 500 KB limit
        with self.assertRaises(DastPayloadTooLargeError):
            dast_client.execute_request("http://localhost:8000/api", method="POST", body=large_payload)

    def test_cross_origin_redirect_rejected(self):
        from app.services.dast_http_client import DastSafeRedirectHandler
        handler = DastSafeRedirectHandler(target_origin=("http", "example.com", 80), allow_localhost=False)

        req = MagicMock()
        # Redirect destination targeting a different domain evil.com
        redirect_res = handler.redirect_request(req, None, 302, "Found", {}, "http://evil.com/phishing")
        self.assertIsNone(redirect_res)

    def test_redirect_to_private_ip_rejected(self):
        from app.services.dast_http_client import DastSafeRedirectHandler
        handler = DastSafeRedirectHandler(target_origin=("http", "example.com", 80), allow_localhost=False)

        req = MagicMock()
        # Redirect destination targeting internal private network
        redirect_res = handler.redirect_request(req, None, 302, "Found", {}, "http://192.168.1.1/admin")
        self.assertIsNone(redirect_res)

    def test_same_origin_redirect_allowed(self):
        from app.services.dast_http_client import DastSafeRedirectHandler
        handler = DastSafeRedirectHandler(target_origin=("http", "example.com", 80), allow_localhost=False)

        req = MagicMock()
        with patch.object(urllib.request.HTTPRedirectHandler, "redirect_request", return_value="ALLOWED"):
            redirect_res = handler.redirect_request(req, None, 302, "Found", {}, "http://example.com/new-path")
            self.assertEqual(redirect_res, "ALLOWED")

    def test_bearer_authentication_injection(self):
        auth_ctx = DastAuthContext(auth_type="BEARER", token_or_key="eyJhbGciOiJIUzI1NiI...")
        headers = auth_ctx.apply_to_headers({"User-Agent": "Test"})
        self.assertEqual(headers["Authorization"], "Bearer eyJhbGciOiJIUzI1NiI...")

    def test_api_key_injection(self):
        auth_ctx = DastAuthContext(auth_type="API_KEY", token_or_key="secret-api-key-123", header_name="X-API-Key")
        headers = auth_ctx.apply_to_headers({})
        self.assertEqual(headers["X-API-Key"], "secret-api-key-123")

    def test_basic_authentication_injection(self):
        auth_ctx = DastAuthContext(auth_type="BASIC", username="admin", password="password123")
        headers = auth_ctx.apply_to_headers({})
        self.assertTrue(headers["Authorization"].startswith("Basic "))

    def test_secret_redaction_utility(self):
        raw_log = "Error making request with Authorization: Bearer secret-token-xyz on header X-API-Key: my-key"
        redacted = redact_secrets(raw_log, secrets_to_redact=["secret-token-xyz", "my-key"])
        self.assertNotIn("secret-token-xyz", redacted)
        self.assertNotIn("my-key", redacted)
        self.assertIn("[REDACTED_SECRET]", redacted)

    def test_sanitize_headers(self):
        headers = {
            "Authorization": "Bearer secret-token-123",
            "X-API-Key": "my-secret-key",
            "Content-Type": "application/json"
        }
        sanitized = sanitize_headers(headers)
        self.assertEqual(sanitized["Authorization"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized["X-API-Key"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized["Content-Type"], "application/json")

    def test_secrets_absent_from_error_messages(self):
        dast_client = DastHttpClient(allow_localhost=False)
        auth_ctx = DastAuthContext(auth_type="BEARER", token_or_key="SECRET_TOKEN_VALUE_999")
        try:
            dast_client.execute_request("http://127.0.0.1:8000/test", auth_context=auth_ctx)
        except Exception as e:
            self.assertNotIn("SECRET_TOKEN_VALUE_999", str(e))

    def test_router_get_and_update_dast_config(self):
        # Update config via API router endpoint with safe target
        payload = {
            "api_target_url": "https://api.example.com",
            "api_dast_enabled": True,
            "api_auth_type": "BEARER",
            "api_auth_header_name": "Authorization"
        }

        with patch("app.routers.api_security.is_ssrf_safe_url", return_value=(True, "SSRF safe")):
            put_res = self.client.put(
                f"/api/projects/{self.project.id}/api-security/dast-config",
                json=payload
            )
            self.assertEqual(put_res.status_code, 200)
            data = put_res.json()
            self.assertTrue(data["api_dast_enabled"])
            self.assertEqual(data["api_target_url"], "https://api.example.com")

            # Get config
            get_res = self.client.get(f"/api/projects/{self.project.id}/api-security/dast-config")
            self.assertEqual(get_res.status_code, 200)
            get_data = get_res.json()
            self.assertEqual(get_data["api_target_url"], "https://api.example.com")

    def test_router_update_dast_config_ssrf_rejected(self):
        payload = {
            "api_target_url": "http://169.254.169.254/metadata",
            "api_dast_enabled": True
        }
        res = self.client.put(
            f"/api/projects/{self.project.id}/api-security/dast-config",
            json=payload
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("SSRF", res.json()["detail"])


if __name__ == "__main__":
    unittest.main()
