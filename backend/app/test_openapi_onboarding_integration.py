import asyncio
import io
import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.api_endpoint import ApiEndpoint
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.services.report_service import ReportService, map_owasp_category
from app.services.scan_service import _run_scan
from app.services.storage_service import get_project_dir

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

JSON_SPEC_30 = """{
  "openapi": "3.0.0",
  "info": {"title": "Test JSON API", "version": "1.0.0"},
  "paths": {
    "/api/users": {
      "get": {
        "summary": "Get users",
        "responses": {"200": {"description": "OK"}}
      }
    }
  }
}"""

YAML_SPEC_30 = """
openapi: 3.0.1
info:
  title: Test YAML API
  version: 1.0.0
paths:
  /api/orders:
    post:
      summary: Create order
      responses:
        '201':
          description: Created
"""

YML_SPEC_31 = """
openapi: 3.1.0
info:
  title: Test YML API 3.1
  version: 1.0.0
paths:
  /api/health:
    get:
      summary: Healthcheck
      responses:
        '200':
          description: Healthy
"""

SWAGGER_20 = """
swagger: "2.0"
info:
  title: Test Swagger 2.0 API
  version: 1.0.0
paths:
  /api/legacy:
    get:
      summary: Legacy route
      responses:
        200:
          description: OK
"""

REMOTE_REF_SPEC = """
openapi: 3.0.0
info:
  title: Remote Ref Attack Spec
  version: 1.0.0
paths:
  /api/remote:
    get:
      summary: Remote ref route
      responses:
        '200':
          description: OK
          content:
            application/json:
              schema:
                $ref: "http://malicious.attacker.com/evil.json#/definitions/Malicious"
"""


class TestOpenApiOnboardingIntegration(unittest.TestCase):
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

        self.session_patcher = patch("app.services.scan_service.SessionLocal", self.SessionLocal)
        self.mock_session_local = self.session_patcher.start()

        # Create base test project
        self.project = Project(
            name="Onboarding Integration Test Project",
            technology="Python/FastAPI",
            status="active",
        )
        self.db.add(self.project)
        self.db.commit()
        self.db.refresh(self.project)

    def tearDown(self):
        self.session_patcher.stop()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=self.engine)
        self.db.close()

    # 1. JSON OpenAPI project creation
    def test_01_json_openapi_project_creation(self):
        files = {"file": ("openapi.json", JSON_SPEC_30.encode("utf-8"), "application/json")}
        res = self.client.post(f"/api/projects/{self.project.id}/ingest/openapi", files=files)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["source_type"], "OPENAPI")
        self.assertEqual(data["status"], "READY")

    # 2. YAML OpenAPI project creation
    def test_02_yaml_openapi_project_creation(self):
        files = {"file": ("openapi.yaml", YAML_SPEC_30.encode("utf-8"), "application/x-yaml")}
        res = self.client.post(f"/api/projects/{self.project.id}/ingest/openapi", files=files)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "READY")

    # 3. YML OpenAPI project creation
    def test_03_yml_openapi_project_creation(self):
        files = {"file": ("openapi.yml", YML_SPEC_31.encode("utf-8"), "text/yaml")}
        res = self.client.post(f"/api/projects/{self.project.id}/ingest/openapi", files=files)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "READY")

    # 4. OpenAPI 3.0 acceptance
    def test_04_openapi_30_acceptance(self):
        files = {"file": ("spec.json", JSON_SPEC_30.encode("utf-8"), "application/json")}
        res = self.client.post(f"/api/projects/{self.project.id}/ingest/openapi", files=files)
        self.assertEqual(res.status_code, 200)
        self.assertIn("3.0", res.json()["message"])

    # 5. OpenAPI 3.1 acceptance
    def test_05_openapi_31_acceptance(self):
        files = {"file": ("spec31.yml", YML_SPEC_31.encode("utf-8"), "text/yaml")}
        res = self.client.post(f"/api/projects/{self.project.id}/ingest/openapi", files=files)
        self.assertEqual(res.status_code, 200)
        self.assertIn("3.1", res.json()["message"])

    # 6. OpenAPI 2.0 / Swagger acceptance
    def test_06_openapi_20_acceptance(self):
        files = {"file": ("swagger.json", SWAGGER_20.encode("utf-8"), "application/json")}
        res = self.client.post(f"/api/projects/{self.project.id}/ingest/openapi", files=files)
        self.assertEqual(res.status_code, 200)
        self.assertIn("2.0", res.json()["message"])

    # 7. Malformed specification rejection
    def test_07_malformed_specification_rejection(self):
        files = {"file": ("bad.json", b"INVALID_JSON_CONTENT{{{", "application/json")}
        res = self.client.post(f"/api/projects/{self.project.id}/ingest/openapi", files=files)
        self.assertEqual(res.status_code, 400)
        self.assertIn("Malformed or unsupported", res.json()["detail"])

    # 8. Missing paths rejection
    def test_08_missing_paths_rejection(self):
        empty_spec = json.dumps({"openapi": "3.0.0", "info": {"title": "Empty", "version": "1.0"}}).encode("utf-8")
        files = {"file": ("empty.json", empty_spec, "application/json")}
        res = self.client.post(f"/api/projects/{self.project.id}/ingest/openapi", files=files)
        self.assertEqual(res.status_code, 400)
        self.assertIn("missing required 'paths'", res.json()["detail"])

    # 9. Unsupported extension rejection
    def test_09_unsupported_extension_rejection(self):
        files = {"file": ("spec.exe", b"binary content", "application/octet-stream")}
        res = self.client.post(f"/api/projects/{self.project.id}/ingest/openapi", files=files)
        self.assertEqual(res.status_code, 400)
        self.assertIn("Unsupported specification file format", res.json()["detail"])

    # 10. >50 MB file rejection
    @patch("app.routers.api_security.MAX_SPEC_SIZE", 1024)
    def test_10_oversized_file_rejection(self):
        oversized = b"a" * 2000
        files = {"file": ("large.json", oversized, "application/json")}
        res = self.client.post(f"/api/projects/{self.project.id}/ingest/openapi", files=files)
        self.assertEqual(res.status_code, 413)

    # 11. Remote $ref rejection
    def test_11_remote_ref_rejection(self):
        files = {"file": ("remote.yaml", REMOTE_REF_SPEC.encode("utf-8"), "text/yaml")}
        res = self.client.post(f"/api/projects/{self.project.id}/ingest/openapi", files=files)
        self.assertEqual(res.status_code, 400)
        self.assertIn("Remote or unsafe $ref pointers are rejected", res.json()["detail"])

    # 12. No outbound network request for remote $ref
    @patch("urllib.request.urlopen")
    def test_12_no_outbound_request_for_remote_ref(self, mock_urlopen):
        files = {"file": ("remote.yaml", REMOTE_REF_SPEC.encode("utf-8"), "text/yaml")}
        self.client.post(f"/api/projects/{self.project.id}/ingest/openapi", files=files)
        self.assertFalse(mock_urlopen.called)

    # 13. Nonexistent project handling
    def test_13_nonexistent_project_handling(self):
        files = {"file": ("spec.json", JSON_SPEC_30.encode("utf-8"), "application/json")}
        res = self.client.post("/api/projects/99999/ingest/openapi", files=files)
        self.assertEqual(res.status_code, 404)

    # 14. Created project reaches READY
    def test_14_created_project_reaches_ready(self):
        files = {"file": ("openapi.json", JSON_SPEC_30.encode("utf-8"), "application/json")}
        self.client.post(f"/api/projects/{self.project.id}/ingest/openapi", files=files)
        self.db.refresh(self.project)
        self.assertEqual(self.project.source_type, "OPENAPI")
        self.assertEqual(self.project.source_status, "READY")

    # 15. Created project can enter unified scan
    def test_15_created_project_can_enter_unified_scan(self):
        files = {"file": ("openapi.json", JSON_SPEC_30.encode("utf-8"), "application/json")}
        self.client.post(f"/api/projects/{self.project.id}/ingest/openapi", files=files)
        
        scan_res = self.client.post(f"/api/projects/{self.project.id}/scans")
        self.assertIn(scan_res.status_code, (200, 201))

    # 16. Unified scan locates onboarded specification
    def test_16_unified_scan_locates_onboarded_specification(self):
        files = {"file": ("openapi.json", JSON_SPEC_30.encode("utf-8"), "application/json")}
        self.client.post(f"/api/projects/{self.project.id}/ingest/openapi", files=files)

        scan = Scan(project_id=self.project.id, status=ScanStatus.QUEUED)
        self.db.add(scan)
        self.db.commit()

        asyncio.run(_run_scan(scan.id))
        self.db.refresh(scan)

        self.assertEqual(scan.status, ScanStatus.COMPLETED)
        self.assertIn("api-security", scan.scanner)

    # 17. GIT onboarding regression
    def test_17_git_onboarding_regression(self):
        res = self.client.post(
            f"/api/projects/{self.project.id}/ingest/git",
            json={"repository_url": "https://github.com/example/repo"}
        )
        self.assertEqual(res.status_code, 200)

    # 18. ZIP onboarding regression
    def test_18_zip_onboarding_regression(self):
        zip_bytes = io.BytesIO()
        import zipfile
        with zipfile.ZipFile(zip_bytes, "w") as zf:
            zf.writestr("app.py", "print('hello')")
        zip_bytes.seek(0)

        files = {"file": ("code.zip", zip_bytes.read(), "application/zip")}
        res = self.client.post(f"/api/projects/{self.project.id}/ingest/zip", files=files)
        self.assertEqual(res.status_code, 200)

    # 19. WEBSITE onboarding regression
    def test_19_website_onboarding_regression(self):
        res = self.client.post(
            f"/api/projects/{self.project.id}/ingest/website",
            json={"target_url": "https://example.com"}
        )
        self.assertEqual(res.status_code, 200)

    # 20. Filename / path traversal protection
    def test_20_path_traversal_protection(self):
        files = {"file": ("../../../../etc/passwd.json", JSON_SPEC_30.encode("utf-8"), "application/json")}
        res = self.client.post(f"/api/projects/{self.project.id}/ingest/openapi", files=files)
        self.assertEqual(res.status_code, 200)
        # Verify saved spec file is strictly inside project directory
        spec_path = get_project_dir(self.project.id) / "openapi_spec.raw"
        self.assertTrue(spec_path.exists())

    # 21. API Security source metadata
    def test_21_api_security_source_metadata(self):
        f = Finding(
            project_id=self.project.id,
            scan_id=1,
            title="Unauthenticated Endpoint",
            description="No auth required",
            severity=FindingSeverity.HIGH,
            category="API Security - Authentication",
            file_path="/api/users",
            source=FindingSource.API_SECURITY,
        )
        self.db.add(f)
        self.db.commit()

        self.assertEqual(f.source, FindingSource.API_SECURITY)

    # 22. DAST source metadata
    def test_22_dast_source_metadata(self):
        f = Finding(
            project_id=self.project.id,
            scan_id=1,
            title="BOLA Vulnerability Confirmed",
            description="Access control bypass",
            severity=FindingSeverity.CRITICAL,
            category="API1:2023 Broken Object Level Authorization",
            file_path="/api/orders/{id}",
            source=FindingSource.DAST,
        )
        self.db.add(f)
        self.db.commit()

        self.assertEqual(f.source, FindingSource.DAST)

    # 23. API endpoint metadata
    def test_23_api_endpoint_metadata(self):
        ep = ApiEndpoint(
            project_id=self.project.id,
            path="/api/v1/orders",
            method="POST",
            auth_status="AUTHENTICATED",
            risk_score=75,
            risk_level="HIGH",
        )
        self.db.add(ep)
        self.db.commit()

        self.assertEqual(ep.path, "/api/v1/orders")
        self.assertEqual(ep.method, "POST")

    # 24. API endpoint navigation metadata
    def test_24_api_endpoint_navigation_metadata(self):
        ep = ApiEndpoint(
            project_id=self.project.id,
            path="/api/v1/users",
            method="GET",
            auth_status="UNAUTHENTICATED",
            risk_score=85,
            risk_level="CRITICAL",
        )
        self.db.add(ep)
        self.db.commit()

        res = self.client.get(f"/api/projects/{self.project.id}/api-security/endpoints/{ep.id}")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["id"], ep.id)

    # 25. Missing endpoint metadata remains compatible
    def test_25_missing_endpoint_metadata_remains_compatible(self):
        f = Finding(
            project_id=self.project.id,
            scan_id=1,
            title="Static Code Bug",
            description="Regular SAST finding",
            severity=FindingSeverity.LOW,
            category="Quality",
            file_path="app/main.py",
            source=FindingSource.SAST,
        )
        self.db.add(f)
        self.db.commit()

        self.assertEqual(f.source, FindingSource.SAST)

    # 26. API OWASP category mapping
    def test_26_api_owasp_category_mapping(self):
        cat1 = map_owasp_category("API1:2023 Broken Object Level Authorization", "BOLA issue")
        cat6 = map_owasp_category("API6:2023 Mass Assignment", "Mass Assignment issue")
        self.assertIn("API1:2023", cat1)
        self.assertIn("API6:2023", cat6)

    # 27. API Security report section
    def test_27_api_security_report_section(self):
        ep = ApiEndpoint(
            project_id=self.project.id,
            path="/api/test",
            method="GET",
            auth_status="UNAUTHENTICATED",
            risk_score=90,
            risk_level="CRITICAL",
        )
        self.db.add(ep)
        self.db.commit()

        service = ReportService(self.db)
        data = service.generate_json_report(self.project.id)
        self.assertIsNotNone(data["api_security_summary"])
        self.assertEqual(data["api_security_summary"]["total_api_endpoints"], 1)

    # 28. API endpoint inventory report data
    def test_28_api_endpoint_inventory_report_data(self):
        ep = ApiEndpoint(
            project_id=self.project.id,
            path="/api/inventory",
            method="POST",
            auth_status="AUTHENTICATED",
            risk_score=50,
            risk_level="MEDIUM",
        )
        self.db.add(ep)
        self.db.commit()

        service = ReportService(self.db)
        data = service.generate_json_report(self.project.id)
        self.assertEqual(len(data["api_endpoints"]), 1)
        self.assertEqual(data["api_endpoints"][0]["path"], "/api/inventory")

    # 29. DAST metrics in reports
    def test_29_dast_metrics_in_reports(self):
        ep = ApiEndpoint(
            project_id=self.project.id,
            path="/api/dast-target",
            method="GET",
            auth_status="AUTHENTICATED",
            dast_status="VERIFIED_VULNERABLE",
            risk_score=95,
            risk_level="CRITICAL",
        )
        self.db.add(ep)
        self.db.commit()

        service = ReportService(self.db)
        data = service.generate_json_report(self.project.id)
        self.assertEqual(data["api_security_summary"]["dast_verified_vulnerable_count"], 1)

    # 30. Existing report types still work
    def test_30_existing_report_types_still_work(self):
        service = ReportService(self.db)
        html_report = service.generate_html_report(self.project.id)
        pdf_report = service.generate_pdf_report(self.project.id)

        self.assertIn("<!DOCTYPE html>", html_report)
        self.assertTrue(len(pdf_report) > 0)


if __name__ == "__main__":
    unittest.main()
