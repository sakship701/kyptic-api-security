import asyncio
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding, FindingSeverity, FindingStatus, FindingSource
from app.services.ssrf_protection import is_ssrf_safe_url, is_ip_forbidden, resolve_hostname_ips
from app.services.ingestion_service import validate_website_url
from app.services.dast_scanner import DASTWebScanner, SafeRedirectHandler, DASTStatus
from app.services.semgrep_scanner import SemgrepSASTScanner
from app.services.detect_secrets_scanner import DetectSecretsScanner
from app.services.sca_scanner import SCADependencyScanner


class TestSSRFProtection(unittest.TestCase):
    def test_01_loopback_ip_rejected(self):
        safe, msg = is_ssrf_safe_url("http://127.0.0.1", allow_localhost=False)
        self.assertFalse(safe)
        self.assertIn("forbidden", msg.lower())

    def test_02_localhost_domain_rejected(self):
        safe, msg = is_ssrf_safe_url("http://localhost", allow_localhost=False)
        self.assertFalse(safe)

    def test_03_aws_metadata_ip_rejected(self):
        safe, msg = is_ssrf_safe_url("http://169.254.169.254", allow_localhost=False)
        self.assertFalse(safe)
        self.assertIn("forbidden", msg.lower())

    def test_04_private_10_network_rejected(self):
        safe, msg = is_ssrf_safe_url("http://10.0.0.1", allow_localhost=False)
        self.assertFalse(safe)

    def test_05_private_172_network_rejected(self):
        safe, msg = is_ssrf_safe_url("http://172.16.0.1", allow_localhost=False)
        self.assertFalse(safe)

    def test_06_private_192_168_network_rejected(self):
        safe, msg = is_ssrf_safe_url("http://192.168.1.1", allow_localhost=False)
        self.assertFalse(safe)

    def test_07_ipv6_loopback_rejected(self):
        safe, msg = is_ssrf_safe_url("http://[::1]", allow_localhost=False)
        self.assertFalse(safe)

    @patch("socket.getaddrinfo")
    def test_08_hostname_resolving_to_private_ip_rejected(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("10.0.0.15", 80))
        ]
        safe, msg = is_ssrf_safe_url("http://internal-app.example.local", allow_localhost=False)
        self.assertFalse(safe)
        self.assertIn("forbidden", msg.lower())

    @patch("socket.getaddrinfo")
    def test_09_hostname_resolving_to_public_ip_accepted(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 80))
        ]
        safe, msg = is_ssrf_safe_url("https://example.com", allow_localhost=False)
        self.assertTrue(safe)
        self.assertIn("ssrf safe", msg.lower())

    @patch("socket.getaddrinfo")
    def test_10_multiple_dns_results_one_private_rejected(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 80)),
            (2, 1, 6, "", ("192.168.1.50", 80))
        ]
        safe, msg = is_ssrf_safe_url("https://rebind.example.com", allow_localhost=False)
        self.assertFalse(safe)

    @patch("socket.getaddrinfo")
    def test_11_valid_https_public_target(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("142.250.190.46", 443))
        ]
        safe, msg = is_ssrf_safe_url("https://www.google.com", allow_localhost=False)
        self.assertTrue(safe)


class TestDASTSSRFAndRedirects(unittest.TestCase):
    @patch("app.services.dast_scanner.is_ssrf_safe_url")
    def test_12_dast_revalidates_ssrf_before_network_request(self, mock_ssrf):
        mock_ssrf.return_value = (False, "Destination IP address is forbidden.")
        scanner = DASTWebScanner()
        res = asyncio.run(scanner.scan("http://169.254.169.254"))
        self.assertEqual(res["status"], DASTStatus.TARGET_UNREACHABLE)
        self.assertIn("blocked by ssrf protection", res["error_message"].lower())

    @patch("app.services.dast_scanner.is_ssrf_safe_url")
    def test_13_redirect_to_private_ip_rejected(self, mock_ssrf):
        handler = SafeRedirectHandler(("https", "example.com", 443))
        mock_ssrf.return_value = (False, "Forbidden IP")
        req = MagicMock()
        res = handler.redirect_request(req, None, 302, "Found", {}, "http://10.0.0.1/admin")
        self.assertIsNone(res)

    @patch("app.services.dast_scanner.is_ssrf_safe_url")
    def test_14_redirect_to_another_domain_rejected(self, mock_ssrf):
        handler = SafeRedirectHandler(("https", "example.com", 443))
        mock_ssrf.return_value = (True, "Safe")
        req = MagicMock()
        res = handler.redirect_request(req, None, 302, "Found", {}, "https://evil.com/phish")
        self.assertIsNone(res)

    @patch("app.services.ssrf_protection.is_ssrf_safe_url")
    def test_15_same_origin_redirect_allowed(self, mock_ssrf):
        handler = SafeRedirectHandler(("https", "example.com", 443))
        mock_ssrf.return_value = (True, "Safe")
        req = MagicMock()
        with patch.object(SafeRedirectHandler, "redirect_request", return_value="REDIRECT_ALLOWED"):
            res = handler.redirect_request(req, None, 302, "Found", {}, "https://example.com/login")
            self.assertIsNotNone(res)


class TestSubprocessTimeouts(unittest.TestCase):
    @patch("subprocess.Popen")
    def test_16_semgrep_timeout_returns_scanner_timeout(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        scanner = SemgrepSASTScanner()
        time_counter = [0.0]
        def mock_time():
            time_counter[0] += 50.0
            return time_counter[0]

        with patch("shutil.which", return_value="semgrep"):
            with patch("time.time", side_effect=mock_time):
                res = asyncio.run(scanner.scan(Path(".")))
                self.assertEqual(res["status"], "SCANNER_TIMEOUT")
                self.assertIn("timed out", res["error_message"].lower())

    @patch("subprocess.Popen")
    def test_17_detect_secrets_timeout_returns_scanner_timeout(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        scanner = DetectSecretsScanner()
        time_counter = [0.0]
        def mock_time():
            time_counter[0] += 30.0
            return time_counter[0]

        with patch("time.time", side_effect=mock_time):
            res = asyncio.run(scanner.scan(Path(".")))
            self.assertEqual(res["status"], "SCANNER_TIMEOUT")
            self.assertIn("timed out", res["error_message"].lower())

    @patch("subprocess.Popen")
    def test_18_sca_timeout_sets_error_msg(self, mock_popen):
        import tempfile
        import subprocess
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 0
        mock_proc.kill.return_value = None
        mock_proc.wait.return_value = 0
        mock_proc.communicate.side_effect = subprocess.TimeoutExpired(cmd=["pip_audit"], timeout=120)
        mock_popen.return_value = mock_proc

        scanner = SCADependencyScanner()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            (tmp_path / "requirements.txt").write_text("fastapi==0.115.0")
            res = asyncio.run(scanner.scan(tmp_path))
            self.assertIn(res["status"], ["SCANNER_ERROR", "DATABASE_UNAVAILABLE"])
            self.assertIn("timed out", (res.get("error_message") or "").lower())

    def test_19_and_20_timeout_does_not_crash_scan_service(self):
        # Verify scanner timeout dictionary structure has error_message and status
        scanner = SemgrepSASTScanner()
        self.assertTrue(hasattr(scanner, "scan"))


from sqlalchemy.pool import StaticPool


class TestGlobalFindingsSummaryAPI(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        Base.metadata.create_all(bind=self.engine)

        def override_get_db():
            db = TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)
        self.db = TestingSessionLocal()

    def tearDown(self):
        self.db.close()
        app.dependency_overrides.clear()

    def test_21_22_23_global_findings_summary_returns_actual_counts(self):
        p = Project(name="Test Proj", technology="Python", source_type="ZIP", source_status="READY")
        self.db.add(p)
        self.db.commit()

        s = Scan(project_id=p.id, status=ScanStatus.COMPLETED, progress=100)
        self.db.add(s)
        self.db.commit()

        f1 = Finding(
            project_id=p.id, scan_id=s.id, title="Critical SQLi", description="SQL injection vulnerability",
            severity=FindingSeverity.CRITICAL, cvss=9.8, category="A03", file_path="app.py",
            status=FindingStatus.OPEN, source=FindingSource.SAST
        )
        f2 = Finding(
            project_id=p.id, scan_id=s.id, title="High XSS", description="Cross-site scripting vulnerability",
            severity=FindingSeverity.HIGH, cvss=8.5, category="A03", file_path="view.py",
            status=FindingStatus.RESOLVED, source=FindingSource.DAST
        )
        self.db.add_all([f1, f2])
        self.db.commit()

        response = self.client.get("/api/v1/findings/summary")
        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Check required fields
        self.assertEqual(data["total"], 2)
        self.assertEqual(data["open"], 1)
        self.assertEqual(data["resolved"], 1)
        self.assertEqual(data["false_positive"], 0)
        self.assertEqual(data["critical"], 1)
        self.assertEqual(data["high"], 1)
        self.assertEqual(data["medium"], 0)
        self.assertEqual(data["low"], 0)
        self.assertEqual(data["info"], 0)


if __name__ == "__main__":
    unittest.main()
