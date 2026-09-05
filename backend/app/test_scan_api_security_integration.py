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
from app.services.dast_http_client import DastResponse
from app.services.scan_service import _run_scan, start_scan_task
from app.services.storage_service import get_project_dir

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

SAMPLE_OPENAPI_SPEC = """
openapi: 3.0.0
info:
  title: Integration Test API
  version: 1.0.0
paths:
  /api/v1/users:
    get:
      summary: List users
      responses:
        '200':
          description: OK
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    id:
                      type: integer
                    password:
                      type: string
                    credit_card:
                      type: string
  /api/v1/orders/{order_id}:
    get:
      summary: Get order details
      parameters:
        - name: order_id
          in: path
          required: true
          schema:
            type: integer
      responses:
        '200':
          description: OK
    post:
      summary: Create order
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                is_admin:
                  type: boolean
                amount:
                  type: number
      responses:
        '201':
          description: Created
"""


class TestScanApiSecurityIntegration(unittest.TestCase):
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

        # Patch SessionLocal in scan_service to use our in-memory SQLite DB
        self.session_patcher = patch("app.services.scan_service.SessionLocal", self.SessionLocal)
        self.mock_session_local = self.session_patcher.start()

        # Create OPENAPI project
        self.openapi_project = Project(
            name="OpenAPI Unified Scan Project",
            technology="OpenAPI / Python",
            source_type="OPENAPI",
            source_status="READY",
            api_dast_enabled=False,
            api_target_url=None,
        )
        self.db.add(self.openapi_project)
        self.db.commit()
        self.db.refresh(self.openapi_project)

        # Save spec file for project
        self.project_dir = get_project_dir(self.openapi_project.id)
        self.spec_file = self.project_dir / "openapi_spec.raw"
        self.spec_file.write_bytes(SAMPLE_OPENAPI_SPEC.encode("utf-8"))

    def tearDown(self):
        self.session_patcher.stop()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=self.engine)
        self.db.close()

    # 1. OPENAPI project dispatches through unified scan API endpoint
    def test_01_openapi_project_dispatches_through_unified_scan_service(self):
        response = self.client.post(f"/api/projects/{self.openapi_project.id}/scans")
        self.assertIn(response.status_code, (200, 201))
        data = response.json()
        self.assertEqual(data["project_id"], self.openapi_project.id)
        self.assertIn(data["status"], ["queued", "running", "QUEUED", "RUNNING"])

    # 2. OPENAPI unified scan executes API Security static analysis
    def test_02_openapi_unified_scan_executes_api_security_static_analysis(self):
        scan = Scan(project_id=self.openapi_project.id, status=ScanStatus.QUEUED)
        self.db.add(scan)
        self.db.commit()

        asyncio.run(_run_scan(scan.id))
        self.db.refresh(scan)

        self.assertEqual(scan.status, ScanStatus.COMPLETED)
        self.assertEqual(scan.progress, 100)
        self.assertIn("api-security", scan.scanner)

    # 3. API endpoints are persisted after unified scan
    def test_03_api_endpoints_persisted_after_unified_scan(self):
        scan = Scan(project_id=self.openapi_project.id, status=ScanStatus.QUEUED)
        self.db.add(scan)
        self.db.commit()

        asyncio.run(_run_scan(scan.id))

        endpoints = self.db.query(ApiEndpoint).filter(ApiEndpoint.project_id == self.openapi_project.id).all()
        self.assertGreaterEqual(len(endpoints), 2)
        paths = [ep.path for ep in endpoints]
        self.assertIn("/api/v1/users", paths)

    # 4. API Security findings are persisted after unified scan
    def test_04_api_security_findings_persisted(self):
        scan = Scan(project_id=self.openapi_project.id, status=ScanStatus.QUEUED)
        self.db.add(scan)
        self.db.commit()

        asyncio.run(_run_scan(scan.id))

        findings = self.db.query(Finding).filter(Finding.scan_id == scan.id).all()
        self.assertGreater(len(findings), 0)
        categories = [f.category for f in findings]
        self.assertTrue(any("API Security" in c for c in categories))

    # 5. OPENAPI unified scan works when DAST is disabled
    def test_05_openapi_unified_scan_works_when_dast_disabled(self):
        self.openapi_project.api_dast_enabled = False
        self.db.commit()

        scan = Scan(project_id=self.openapi_project.id, status=ScanStatus.QUEUED)
        self.db.add(scan)
        self.db.commit()

        asyncio.run(_run_scan(scan.id))
        self.db.refresh(scan)

        self.assertEqual(scan.status, ScanStatus.COMPLETED)

    # 6. OPENAPI unified scan invokes DAST when configured
    @patch("app.services.dast_http_client.DastHttpClient.execute_request")
    def test_06_openapi_unified_scan_invokes_dast_when_configured(self, mock_exec):
        mock_exec.return_value = DastResponse(
            status_code=401,
            headers={"Content-Type": "application/json"},
            elapsed_ms=50.0,
            body_preview='{"error": "Unauthorized"}',
            final_url="http://target.test/api/v1/users",
        )

        self.openapi_project.api_dast_enabled = True
        self.openapi_project.api_target_url = "http://target.test"
        self.db.commit()

        scan = Scan(project_id=self.openapi_project.id, status=ScanStatus.QUEUED)
        self.db.add(scan)
        self.db.commit()

        with patch("app.services.scan_service.is_ssrf_safe_url", return_value=(True, "OK")):
            asyncio.run(_run_scan(scan.id))

        self.db.refresh(scan)
        self.assertEqual(scan.status, ScanStatus.COMPLETED)
        self.assertEqual(scan.dast_status, "COMPLETED")
        self.assertTrue(mock_exec.called)

    # 7. DAST is not invoked when disabled
    @patch("app.services.dast_http_client.DastHttpClient.execute_request")
    def test_07_dast_not_invoked_when_disabled(self, mock_exec):
        self.openapi_project.api_dast_enabled = False
        self.openapi_project.api_target_url = "http://target.test"
        self.db.commit()

        scan = Scan(project_id=self.openapi_project.id, status=ScanStatus.QUEUED)
        self.db.add(scan)
        self.db.commit()

        asyncio.run(_run_scan(scan.id))

        self.assertFalse(mock_exec.called)

    # 8. DAST is not invoked when target URL is missing
    @patch("app.services.dast_http_client.DastHttpClient.execute_request")
    def test_08_dast_not_invoked_when_target_url_missing(self, mock_exec):
        self.openapi_project.api_dast_enabled = True
        self.openapi_project.api_target_url = None
        self.db.commit()

        scan = Scan(project_id=self.openapi_project.id, status=ScanStatus.QUEUED)
        self.db.add(scan)
        self.db.commit()

        asyncio.run(_run_scan(scan.id))
        self.db.refresh(scan)

        self.assertEqual(scan.dast_status, "SKIPPED_NO_TARGET")
        self.assertFalse(mock_exec.called)

    # 9. SSRF-invalid DAST target does not result in an unsafe network request
    @patch("app.services.dast_http_client.DastHttpClient.execute_request")
    def test_09_ssrf_invalid_dast_target_no_unsafe_request(self, mock_exec):
        self.openapi_project.api_dast_enabled = True
        self.openapi_project.api_target_url = "http://169.254.169.254"
        self.db.commit()

        scan = Scan(project_id=self.openapi_project.id, status=ScanStatus.QUEUED)
        self.db.add(scan)
        self.db.commit()

        asyncio.run(_run_scan(scan.id))
        self.db.refresh(scan)

        self.assertEqual(scan.status, ScanStatus.COMPLETED)
        self.assertEqual(scan.dast_status, "SKIPPED_SSRF_BLOCKED")
        self.assertFalse(mock_exec.called)

    # 10. Missing OpenAPI specification produces a clean scan failure
    def test_10_missing_openapi_spec_clean_scan_failure(self):
        if self.spec_file.exists():
            self.spec_file.unlink()

        scan = Scan(project_id=self.openapi_project.id, status=ScanStatus.QUEUED)
        self.db.add(scan)
        self.db.commit()

        asyncio.run(_run_scan(scan.id))
        self.db.refresh(scan)

        self.assertEqual(scan.status, ScanStatus.FAILED)
        self.assertIn("specification source file not found", scan.error_message)

    # 11. Nonexistent OPENAPI project returns 404
    def test_11_nonexistent_openapi_project_404(self):
        response = self.client.post("/api/projects/99999/scans")
        self.assertEqual(response.status_code, 404)

    # 12. Existing GIT scan dispatch still works
    def test_12_existing_git_scan_dispatch_works(self):
        git_proj = Project(name="Git Proj", technology="Python", source_type="GIT_REPOSITORY", source_status="READY")
        self.db.add(git_proj)
        self.db.commit()

        response = self.client.post(f"/api/projects/{git_proj.id}/scans")
        self.assertIn(response.status_code, (200, 201))

    # 13. Existing ZIP scan dispatch still works
    def test_13_existing_zip_scan_dispatch_works(self):
        zip_proj = Project(name="Zip Proj", technology="Python", source_type="ZIP_ARCHIVE", source_status="READY")
        self.db.add(zip_proj)
        self.db.commit()

        response = self.client.post(f"/api/projects/{zip_proj.id}/scans")
        self.assertIn(response.status_code, (200, 201))

    # 14. Existing WEBSITE scan dispatch still works
    def test_14_existing_website_scan_dispatch_works(self):
        web_proj = Project(name="Web Proj", technology="Web", source_type="WEBSITE", source_status="READY", target_url="http://example.com")
        self.db.add(web_proj)
        self.db.commit()

        response = self.client.post(f"/api/projects/{web_proj.id}/scans")
        self.assertIn(response.status_code, (200, 201))

    # 15. Scan lifecycle reaches COMPLETED for successful OPENAPI scan
    def test_15_scan_lifecycle_reaches_completed(self):
        scan = Scan(project_id=self.openapi_project.id, status=ScanStatus.QUEUED)
        self.db.add(scan)
        self.db.commit()

        asyncio.run(_run_scan(scan.id))
        self.db.refresh(scan)

        self.assertEqual(scan.status, ScanStatus.COMPLETED)
        self.assertIsNotNone(scan.completed_at)
        self.assertIsNotNone(scan.duration)

    # 16. Scan lifecycle reaches FAILED for unrecoverable OpenAPI errors
    def test_16_scan_lifecycle_reaches_failed_on_error(self):
        self.spec_file.write_bytes(b"INVALID_YAML: ::: ::: [")

        scan = Scan(project_id=self.openapi_project.id, status=ScanStatus.QUEUED)
        self.db.add(scan)
        self.db.commit()

        asyncio.run(_run_scan(scan.id))
        self.db.refresh(scan)

        self.assertEqual(scan.status, ScanStatus.FAILED)
        self.assertIsNotNone(scan.error_message)

    # 17. A DAST endpoint failure does not crash the unified scan
    @patch("app.services.dast_http_client.DastHttpClient.execute_request")
    def test_17_dast_endpoint_failure_does_not_crash_scan(self, mock_exec):
        mock_exec.side_effect = Exception("Connection refused")

        self.openapi_project.api_dast_enabled = True
        self.openapi_project.api_target_url = "http://target.test"
        self.db.commit()

        scan = Scan(project_id=self.openapi_project.id, status=ScanStatus.QUEUED)
        self.db.add(scan)
        self.db.commit()

        with patch("app.services.scan_service.is_ssrf_safe_url", return_value=(True, "OK")):
            asyncio.run(_run_scan(scan.id))

        self.db.refresh(scan)
        self.assertEqual(scan.status, ScanStatus.COMPLETED)

    # 18. Existing triage states remain preserved after rescanning
    def test_18_existing_triage_states_preserved(self):
        # 1. Run first scan
        scan1 = Scan(project_id=self.openapi_project.id, status=ScanStatus.QUEUED)
        self.db.add(scan1)
        self.db.commit()
        asyncio.run(_run_scan(scan1.id))

        # Triage a finding
        finding = self.db.query(Finding).filter(Finding.scan_id == scan1.id).first()
        self.assertIsNotNone(finding)
        finding.status = FindingStatus.RESOLVED
        finding.resolution_comment = "Fixed in commit 123"
        self.db.commit()

        # 2. Run second scan
        scan2 = Scan(project_id=self.openapi_project.id, status=ScanStatus.QUEUED)
        self.db.add(scan2)
        self.db.commit()
        asyncio.run(_run_scan(scan2.id))

        # Verify triaged status carried forward
        finding2 = self.db.query(Finding).filter(Finding.scan_id == scan2.id, Finding.fingerprint == finding.fingerprint).first()
        self.assertIsNotNone(finding2)
        self.assertEqual(finding2.status, FindingStatus.RESOLVED)
        self.assertEqual(finding2.resolution_comment, "Fixed in commit 123")

    # 19. Static + DAST findings do not create unintended duplicates
    @patch("app.services.dast_http_client.DastHttpClient.execute_request")
    def test_19_static_and_dast_findings_no_unintended_duplicates(self, mock_exec):
        # Return 200 to trigger active BOLA / Auth vulnerability probe findings
        mock_exec.return_value = DastResponse(
            status_code=200,
            headers={"Content-Type": "application/json"},
            elapsed_ms=45.0,
            body_preview='{"id": 1, "data": "secret"}',
            final_url="http://target.test/api/v1/orders/1",
        )

        self.openapi_project.api_dast_enabled = True
        self.openapi_project.api_target_url = "http://target.test"
        self.db.commit()

        scan = Scan(project_id=self.openapi_project.id, status=ScanStatus.QUEUED)
        self.db.add(scan)
        self.db.commit()

        with patch("app.services.scan_service.is_ssrf_safe_url", return_value=(True, "OK")):
            asyncio.run(_run_scan(scan.id))

        findings = self.db.query(Finding).filter(Finding.scan_id == scan.id).all()
        fps = [f.fingerprint for f in findings if f.fingerprint]
        self.assertEqual(len(fps), len(set(fps)), "Findings contain duplicate fingerprints")

    # 20. Existing API Security direct analyze endpoint still works after refactoring
    def test_20_existing_api_security_direct_analyze_endpoint_works(self):
        response = self.client.post(f"/api/projects/{self.openapi_project.id}/api-security/analyze")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], ScanStatus.COMPLETED.value)


if __name__ == "__main__":
    unittest.main()
