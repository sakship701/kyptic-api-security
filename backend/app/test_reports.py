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
from app.models.user import User
from app.services.auth_service import create_access_token, hash_password
from app.config import settings
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

        # Seed test user
        self.user = User(
            email=settings.BOOTSTRAP_OWNER_EMAIL,
            password_hash=hash_password("Password123!"),
            is_active=True,
        )
        self.db.add(self.user)
        self.db.commit()
        self.db.refresh(self.user)
        self.token = create_access_token({"user_id": self.user.id, "email": self.user.email}, db=self.db)

        # Seed test project, scan, and findings
        self.project = Project(
            name="Report Test Application",
            technology="Python/React",
            user_id=self.user.id,
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
        app.dependency_overrides.clear()

    # 1. Test deterministic risk score formula
    def test_risk_score_calculation(self):
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

    # 3. Test Executive Report Content (Requirement A)
    def test_executive_report_differentiation(self):
        json_rep = self.service.generate_json_report(self.project.id, "executive")
        self.assertEqual(json_rep["report_type"], "executive")
        self.assertIn("top_strategic_risks", json_rep)
        self.assertIn("remediation_priorities", json_rep)
        self.assertNotIn("technical_details", json_rep)
        self.assertNotIn("compliance_summary", json_rep)
        self.assertNotIn("owasp_summary", json_rep)

        html_rep = self.service.generate_html_report(self.project.id, "executive")
        self.assertIn("Executive Summary & Risk Posture", html_rep)
        self.assertIn("Top Strategic Risks", html_rep)
        self.assertIn("Leadership Remediation Priorities", html_rep)

        pdf_bytes = self.service.generate_pdf_report(self.project.id, "executive")
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1."))

    # 4. Test Developer Report Content (Requirement B)
    def test_developer_report_differentiation(self):
        json_rep = self.service.generate_json_report(self.project.id, "developer")
        self.assertEqual(json_rep["report_type"], "developer")
        self.assertIn("technical_details", json_rep)
        self.assertIn("grouped_by_file", json_rep["technical_details"])
        self.assertNotIn("top_strategic_risks", json_rep)
        self.assertNotIn("compliance_summary", json_rep)

        html_rep = self.service.generate_html_report(self.project.id, "developer")
        self.assertIn("Developer Technical Deep-Dive", html_rep)
        self.assertIn("app/db.py", html_rep)
        self.assertIn("SAST-SQL-INJECTION", html_rep)

        pdf_bytes = self.service.generate_pdf_report(self.project.id, "developer")
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1."))

    # 5. Test Compliance Report Content (Requirement C)
    def test_compliance_report_differentiation(self):
        json_rep = self.service.generate_json_report(self.project.id, "compliance")
        self.assertEqual(json_rep["report_type"], "compliance")
        self.assertIn("compliance_summary", json_rep)
        self.assertIn("controls", json_rep)
        self.assertEqual(json_rep["compliance_summary"]["framework"], "PCI_DSS")
        self.assertIn("coverage_percentage", json_rep["compliance_summary"])

        html_rep = self.service.generate_html_report(self.project.id, "compliance")
        self.assertIn("Regulatory Compliance Assessment", html_rep)
        self.assertIn("Control Evaluation Trail", html_rep)

        pdf_bytes = self.service.generate_pdf_report(self.project.id, "compliance")
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1."))

    # 6. Test OWASP Report Content (Requirement D)
    def test_owasp_report_differentiation(self):
        json_rep = self.service.generate_json_report(self.project.id, "owasp")
        self.assertEqual(json_rep["report_type"], "owasp")
        self.assertIn("owasp_summary", json_rep)
        self.assertIn("categories", json_rep["owasp_summary"])

        html_rep = self.service.generate_html_report(self.project.id, "owasp")
        self.assertIn("OWASP Top 10 Security Threat Distribution", html_rep)

        pdf_bytes = self.service.generate_pdf_report(self.project.id, "owasp")
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1."))

    # 7. Test Same Project ID and Real Findings Across All 4 Report Types (Requirement E, F)
    def test_all_report_types_use_same_project_id_and_findings(self):
        for rtype in ["executive", "developer", "compliance", "owasp"]:
            res = self.service.generate_json_report(self.project.id, rtype)
            self.assertEqual(res["project_id"], self.project.id)
            self.assertEqual(res["project_name"], "Report Test Application")
            self.assertEqual(len(res["findings"]), 3)

    # 8. Test Invalid Report Type Handling (Requirement G)
    def test_invalid_report_type_raises_error(self):
        with self.assertRaises(ValueError):
            self.service.generate_json_report(self.project.id, "invalid_type")

        with self.assertRaises(ValueError):
            self.service.generate_html_report(self.project.id, "unknown_type")

        with self.assertRaises(ValueError):
            self.service.generate_pdf_report(self.project.id, "malformed")

    # 9. Test PDF Generation for All 4 Types (Requirement H)
    def test_pdf_generation_succeeds_for_all_types(self):
        for rtype in ["executive", "developer", "compliance", "owasp"]:
            pdf_bytes = self.service.generate_pdf_report(self.project.id, rtype)
            self.assertTrue(pdf_bytes.startswith(b"%PDF-1."))
            self.assertGreater(len(pdf_bytes), 1000)

    # 10. Test HTML and JSON Generation for All 4 Types (Requirement I)
    def test_html_and_json_generation_succeeds_for_all_types(self):
        for rtype in ["executive", "developer", "compliance", "owasp"]:
            json_res = self.service.generate_json_report(self.project.id, rtype)
            self.assertEqual(json_res["report_type"], rtype)
            html_res = self.service.generate_html_report(self.project.id, rtype)
            self.assertIn("KYPTIC SECURITY REPORT", html_res)

    # 11. Test FastAPI Endpoints via TestClient
    def test_api_endpoints_all_report_types(self):
        client = TestClient(app)
        headers = {"Authorization": f"Bearer {self.token}"}

        # GET /api/v1/reports/templates
        res_templates = client.get("/api/v1/reports/templates", headers=headers)
        self.assertEqual(res_templates.status_code, 200)

        for rtype in ["executive", "developer", "compliance", "owasp"]:
            # JSON format
            res_json = client.post(
                "/api/v1/reports/generate",
                json={"project_id": self.project.id, "report_type": rtype, "format": "json"},
                headers=headers
            )
            self.assertEqual(res_json.status_code, 200)
            self.assertEqual(res_json.json()["report_type"], rtype)

            # PDF format
            res_pdf = client.post(
                "/api/v1/reports/generate",
                json={"project_id": self.project.id, "report_type": rtype, "format": "pdf"},
                headers=headers
            )
            self.assertEqual(res_pdf.status_code, 200)
            self.assertEqual(res_pdf.headers["content-type"], "application/pdf")
            self.assertTrue(res_pdf.content.startswith(b"%PDF-1."))


if __name__ == "__main__":
    unittest.main()
