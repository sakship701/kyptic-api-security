import unittest
from datetime import datetime
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sqlalchemy.pool import StaticPool
from app.database import Base, get_db
from app.main import app
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.services.report_service import ReportService, calculate_risk_score, map_owasp_category


class TestReportService(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
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

        # Seed test project, scan, and findings
        self.project = Project(
            name="Report Test Application",
            technology="Python/React",
            source_type="ZIP",
            source_status="READY",
        )
        self.db.add(self.project)
        self.db.commit()
        self.db.refresh(self.project)

        self.scan = Scan(project_id=self.project.id, status=ScanStatus.COMPLETED)
        self.db.add(self.scan)
        self.db.commit()

        self.f1 = Finding(
            project_id=self.project.id,
            scan_id=self.scan.id,
            title="SQL Injection Vulnerability",
            description="Dynamic SQL query concatenation detected.",
            severity=FindingSeverity.CRITICAL,
            cvss=9.8,
            category="A03:2021-Injection",
            file_path="app/db.py",
            line_number=42,
            status=FindingStatus.OPEN,
            source=FindingSource.SAST,
            rule_id="SAST-SQL-INJECTION",
            code_snippet="query = 'SELECT * FROM users WHERE id=' + user_id",
        )
        self.f2 = Finding(
            project_id=self.project.id,
            scan_id=self.scan.id,
            title="Hardcoded AWS Secret Access Key",
            description="Exposed AWS secret key token found.",
            severity=FindingSeverity.HIGH,
            cvss=8.1,
            category="A02:2021-Cryptographic Failures",
            file_path="config.py",
            line_number=10,
            status=FindingStatus.OPEN,
            source=FindingSource.SECRETS,
            rule_id="SECRET-AWS-KEY",
            code_snippet="AWS_SECRET = '[MASKED]'",
        )
        self.f3 = Finding(
            project_id=self.project.id,
            scan_id=self.scan.id,
            title="Vulnerable Dependency: requests",
            description="CVE-2023-32681 in requests 2.25.0",
            severity=FindingSeverity.MEDIUM,
            cvss=6.1,
            category="Dependency Vulnerability",
            file_path="requirements.txt",
            line_number=None,
            status=FindingStatus.OPEN,
            source=FindingSource.SCA,
            rule_id="CVE-2023-32681",
            code_snippet="Package: requests@2.25.0",
        )
        self.db.add_all([self.f1, self.f2, self.f3])
        self.db.commit()

        self.service = ReportService(self.db)

    def tearDown(self):
        self.db.close()

    # 1. Test deterministic risk score formula
    def test_risk_score_calculation(self):
        # 1 Critical (-15), 1 High (-8), 1 Medium (-3) => Total deduction = 26.
        # Score = 100 - 26 = 74 -> Grade C
        score, grade, counts = calculate_risk_score([self.f1, self.f2, self.f3])
        self.assertEqual(score, 74)
        self.assertEqual(grade, "C (Needs Improvement)")
        self.assertEqual(counts["critical"], 1)
        self.assertEqual(counts["high"], 1)
        self.assertEqual(counts["medium"], 1)

    # 2. Test OWASP category mapping
    def test_owasp_mapping(self):
        self.assertEqual(map_owasp_category("A03:2021-Injection", "SQLi"), "A03:2021 - Injection")
        self.assertEqual(map_owasp_category("Cryptographic Failures", "AWS Key"), "A02:2021 - Cryptographic Failures")
        self.assertEqual(map_owasp_category("Dependency Vulnerability", "CVE-2023"), "A06:2021 - Vulnerable & Outdated Components")

    # 3. Test JSON report generation
    def test_json_report_generation(self):
        res = self.service.generate_json_report(self.project.id, "executive")
        self.assertEqual(res["project_id"], self.project.id)
        self.assertEqual(res["project_name"], "Report Test Application")
        self.assertEqual(res["metrics"]["security_score"], 74)
        self.assertEqual(len(res["findings"]), 3)

    # 4. Test HTML report generation
    def test_html_report_generation(self):
        res_html = self.service.generate_html_report(self.project.id, "developer")
        self.assertIn("<!DOCTYPE html>", res_html)
        self.assertIn("Report Test Application", res_html)
        self.assertIn("SQL Injection Vulnerability", res_html)
        self.assertIn("74/100", res_html)

    # 5. Test PDF report binary generation
    def test_pdf_report_generation(self):
        pdf_bytes = self.service.generate_pdf_report(self.project.id, "executive")
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1."))
        self.assertGreater(len(pdf_bytes), 1000)

    # 6. Test FastAPI endpoints via TestClient
    def test_api_endpoints(self):
        client = TestClient(app)
        
        # GET /api/v1/reports/templates
        res_templates = client.get("/api/v1/reports/templates")
        self.assertEqual(res_templates.status_code, 200)
        self.assertGreaterEqual(len(res_templates.json()), 4)

        # POST /api/v1/reports/generate (json)
        res_gen_json = client.post(
            "/api/v1/reports/generate",
            json={"project_id": self.project.id, "report_type": "executive", "format": "json"}
        )
        self.assertEqual(res_gen_json.status_code, 200)
        self.assertEqual(res_gen_json.json()["metrics"]["security_score"], 74)

        # POST /api/v1/reports/generate (pdf)
        res_gen_pdf = client.post(
            "/api/v1/reports/generate",
            json={"project_id": self.project.id, "report_type": "developer", "format": "pdf"}
        )
        self.assertEqual(res_gen_pdf.status_code, 200)
        self.assertEqual(res_gen_pdf.headers["content-type"], "application/pdf")
        self.assertTrue(res_gen_pdf.content.startswith(b"%PDF-1."))

    def tearDown(self):
        self.db.close()
        app.dependency_overrides.clear()


if __name__ == "__main__":
    unittest.main()
