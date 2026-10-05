import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.project import Project
from app.models.api_endpoint import ApiEndpoint
from app.services.ssrf_protection import is_local_demo_target

KYPTIC_LOCAL_DEMO_URL = "http://127.0.0.1:8001"

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"


class TestDastProjectConfiguration(unittest.TestCase):
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
        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

        # Create authenticated test user
        from app.models.user import User
        from app.services.auth_service import create_access_token, hash_password
        from app.config import settings

        user = User(
            email=settings.BOOTSTRAP_OWNER_EMAIL,
            password_hash=hash_password("Password123!"),
            is_active=True,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)

        token = create_access_token({"user_id": user.id, "email": user.email}, db=self.db)
        self.client.headers["Authorization"] = f"Bearer {token}"

        # Create Project 1 (default disabled state)
        self.project1 = Project(
            name="Kyptic Demo Vulnerable App",
            technology="Python/FastAPI",
            user_id=user.id,
            api_dast_enabled=False,
            api_target_url=None,
        )
        # Create Project 2 for isolation test
        self.project2 = Project(
            name="Secondary Isolation Project",
            technology="NodeJS/Express",
            user_id=user.id,
            api_dast_enabled=False,
            api_target_url=None,
        )
        self.db.add_all([self.project1, self.project2])
        self.db.commit()
        self.db.refresh(self.project1)
        self.db.refresh(self.project2)

        # Add endpoint for active scan tests
        ep = ApiEndpoint(
            project_id=self.project1.id,
            path="/api/search",
            method="GET",
            auth_status="UNAUTHENTICATED",
            rate_limit_status="MISSING",
            request_validation_status="UNCONSTRAINED",
            risk_score=50,
            risk_level="MEDIUM",
            discovered_via="OPENAPI",
        )
        self.db.add(ep)
        self.db.commit()

    def tearDown(self):
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=self.engine)
        self.db.close()

    def test_1_get_existing_dast_config(self):
        """1. GET existing DAST config reflects database initial state."""
        response = self.client.get(f"/api/projects/{self.project1.id}/api-security/dast-config")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["project_id"], self.project1.id)
        self.assertFalse(data["api_dast_enabled"])
        self.assertIsNone(data["api_target_url"])

    def test_2_put_dast_config(self):
        """2. PUT DAST config updates database state with valid demo target."""
        payload = {
            "api_target_url": KYPTIC_LOCAL_DEMO_URL,
            "api_dast_enabled": True,
            "api_auth_type": "NONE",
            "api_auth_header_name": "Authorization"
        }
        response = self.client.put(
            f"/api/projects/{self.project1.id}/api-security/dast-config",
            json=payload
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["api_target_url"], KYPTIC_LOCAL_DEMO_URL)
        self.assertTrue(data["api_dast_enabled"])

        # Re-fetch GET to verify persisted state in DB
        get_resp = self.client.get(f"/api/projects/{self.project1.id}/api-security/dast-config")
        self.assertEqual(get_resp.status_code, 200)
        persisted = get_resp.json()
        self.assertTrue(persisted["api_dast_enabled"])
        self.assertEqual(persisted["api_target_url"], KYPTIC_LOCAL_DEMO_URL)

    def test_3_project_isolation(self):
        """3. Project isolation: Updating Project 1 target does not affect Project 2."""
        payload = {
            "api_target_url": KYPTIC_LOCAL_DEMO_URL,
            "api_dast_enabled": True,
        }
        self.client.put(
            f"/api/projects/{self.project1.id}/api-security/dast-config",
            json=payload
        )

        p2_resp = self.client.get(f"/api/projects/{self.project2.id}/api-security/dast-config")
        self.assertEqual(p2_resp.status_code, 200)
        p2_data = p2_resp.json()
        self.assertFalse(p2_data["api_dast_enabled"])
        self.assertIsNone(p2_data["api_target_url"])

    def test_4_dast_disabled_blocks_active_scan(self):
        """4. DAST disabled for project blocks active scan."""
        response = self.client.post(f"/api/projects/{self.project1.id}/api-security/dast/scan")
        self.assertEqual(response.status_code, 400)
        self.assertIn("DAST dynamic testing is disabled for this project", response.json()["detail"])

    def test_5_dast_enabled_valid_target_allows_active_scan(self):
        """5. DAST enabled + valid target allows active scan execution."""
        # Enable DAST first
        self.client.put(
            f"/api/projects/{self.project1.id}/api-security/dast-config",
            json={"api_target_url": KYPTIC_LOCAL_DEMO_URL, "api_dast_enabled": True}
        )

        # Mock probe engine execution so test runs deterministically
        with patch("app.routers.api_security.run_active_dast_probes") as mock_probes:
            mock_probes.return_value = []
            response = self.client.post(f"/api/projects/{self.project1.id}/api-security/dast/scan")
            self.assertEqual(response.status_code, 200, f"Expected 200, got {response.status_code}: {response.json()}")
            data = response.json()
            self.assertEqual(data["status"], "completed")

    def test_6_invalid_unsafe_target_rejected_server_side(self):
        """6. Invalid/unsafe SSRF targets (e.g. cloud metadata, arbitrary localhost) are rejected."""
        unsafe_urls = [
            "http://169.254.169.254/latest/meta-data",
            "http://10.0.0.1/internal",
            "http://127.0.0.1:9999/admin",  # Arbitrary localhost port, not local demo
            "file:///etc/passwd",
        ]

        for unsafe_url in unsafe_urls:
            response = self.client.put(
                f"/api/projects/{self.project1.id}/api-security/dast-config",
                json={"api_target_url": unsafe_url, "api_dast_enabled": True}
            )
            self.assertEqual(response.status_code, 400, f"Failed to reject unsafe URL: {unsafe_url}")
            self.assertIn("SSRF validation failed", response.json()["detail"])

    def test_7_global_dast_disabled_still_blocks_active_scan(self):
        """7. Global DAST disabled still blocks active scan even if project DAST is enabled."""
        self.client.put(
            f"/api/projects/{self.project1.id}/api-security/dast-config",
            json={"api_target_url": KYPTIC_LOCAL_DEMO_URL, "api_dast_enabled": True}
        )

        with patch("app.routers.api_security.GLOBAL_SCANNER_CONFIG", {"dast_enabled": False}):
            response = self.client.post(f"/api/projects/{self.project1.id}/api-security/dast/scan")
            self.assertEqual(response.status_code, 400)
            self.assertIn("Global DAST engine is disabled", response.json()["detail"])

    def test_8_local_demo_target_uses_exact_origin_safety_mechanism(self):
        """8. Local demo target uses existing exact-origin safety mechanism."""
        self.assertTrue(is_local_demo_target(KYPTIC_LOCAL_DEMO_URL))
        self.assertTrue(is_local_demo_target("http://127.0.0.1:8001/"))
        self.assertFalse(is_local_demo_target("http://127.0.0.1:8002"))
        self.assertFalse(is_local_demo_target("http://127.0.0.1:8000"))


if __name__ == "__main__":
    unittest.main()
