import io
import unittest
import json
import shutil
import tempfile
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding, FindingSeverity, FindingSource
from app.services.scanner_base import BaseScanner
from app.services.semgrep_scanner import SemgrepSASTScanner
from app.services.finding_normalizer import (
    normalize_semgrep_severity,
    normalize_semgrep_results,
    generate_fingerprint
)
from app.services.scan_service import _run_scan

class TestSASTEngine(unittest.TestCase):
    def setUp(self):
        # Set up a test SQLite database in memory
        self.engine = create_engine("sqlite:///:memory:")
        self.Session = sessionmaker(bind=self.engine)
        Base.metadata.create_all(self.engine)
        self.db = self.Session()

        # Create a dummy source project
        self.src_project = Project(
            name="Source Project",
            technology="Python",
            status="active",
            source_type="ZIP",
            source_status="READY"
        )
        # Create a dummy website project
        self.web_project = Project(
            name="Website Project",
            technology="Web",
            status="active",
            source_type="WEBSITE",
            source_status="READY"
        )
        self.db.add_all([self.src_project, self.web_project])
        self.db.commit()
        self.db.refresh(self.src_project)
        self.db.refresh(self.web_project)

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(self.engine)

    def test_semgrep_availability_detection(self):
        # SemgrepSASTScanner uses shutil.which to detect Semgrep presence
        # Let's mock shutil.which to return None and verify it raises error
        with patch("shutil.which", return_value=None):
            scanner = SemgrepSASTScanner()
            with self.assertRaises(RuntimeError) as context:
                asyncio.run(scanner.scan(Path("/tmp/some-path")))
            self.assertIn("Semgrep executable not found", str(context.exception))

    def test_website_project_refuses_sast(self):
        # Create a scan for the Website project
        scan = Scan(project_id=self.web_project.id, status=ScanStatus.QUEUED)
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        scan_id = scan.id

        # Run orchestrator scan
        with patch("app.services.scan_service.SessionLocal", return_value=self.db):
            asyncio.run(_run_scan(scan_id))

        # Check that scan fails with website warning by querying the db freshly
        self.db.close()
        self.db = self.Session()
        db_scan = self.db.get(Scan, scan_id)
        self.assertEqual(db_scan.status, ScanStatus.FAILED)
        self.assertIn("Website projects are DAST targets", db_scan.error_message)

    def test_missing_source_fails_sast(self):
        # Create project with missing source
        no_src_project = Project(
            name="No Source",
            technology="Python",
            status="active",
            source_type=None
        )
        self.db.add(no_src_project)
        self.db.commit()
        self.db.refresh(no_src_project)

        scan = Scan(project_id=no_src_project.id, status=ScanStatus.QUEUED)
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        scan_id = scan.id

        with patch("app.services.scan_service.SessionLocal", return_value=self.db):
            asyncio.run(_run_scan(scan_id))

        # Check that scan fails by querying the db freshly
        self.db.close()
        self.db = self.Session()
        db_scan = self.db.get(Scan, scan_id)
        self.assertEqual(db_scan.status, ScanStatus.FAILED)
        self.assertIn("Project source code is missing", db_scan.error_message)

    def test_semgrep_command_uses_shell_false(self):
        # Mock subprocess.Popen to inspect shell=False argument
        with patch("subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.poll.return_value = 0
            mock_proc.communicate.return_value = ('{"results": []}', '')
            mock_proc.returncode = 0
            mock_popen.return_value = mock_proc

            scanner = SemgrepSASTScanner()
            with patch("shutil.which", return_value="/usr/bin/semgrep"):
                asyncio.run(scanner.scan(Path("/tmp/sandbox")))

            # Verify shell=False is passed
            _, kwargs = mock_popen.call_args
            self.assertEqual(kwargs.get("shell"), False)

    def test_semgrep_severity_mapping(self):
        self.assertEqual(normalize_semgrep_severity("ERROR"), FindingSeverity.HIGH)
        self.assertEqual(normalize_semgrep_severity("WARNING"), FindingSeverity.MEDIUM)
        self.assertEqual(normalize_semgrep_severity("INFO"), FindingSeverity.LOW)
        self.assertEqual(normalize_semgrep_severity("unknown"), FindingSeverity.INFO)

    def test_fingerprint_generation_deterministic(self):
        fp1 = generate_fingerprint(1, "semgrep", "rule-1", "src/auth.py", 42, "SQL injection")
        fp2 = generate_fingerprint(1, "semgrep", "rule-1", "src/auth.py", 42, "SQL injection")
        fp3 = generate_fingerprint(1, "semgrep", "rule-2", "src/auth.py", 42, "SQL injection")

        self.assertEqual(fp1, fp2)
        self.assertNotEqual(fp1, fp3)

    def test_normalize_semgrep_results_mapping(self):
        # Sample raw Semgrep output structure
        sample_results = {
            "results": [
                {
                    "check_id": "rules.security.eval-injection",
                    "path": "src/app.py",
                    "start": {"line": 10},
                    "end": {"line": 12},
                    "extra": {
                        "message": "Dangerous eval usage",
                        "severity": "ERROR",
                        "lines": "eval(user_input)",
                        "metadata": {
                            "cwe": ["CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"],
                            "owasp": ["A03:2021-Injection"]
                        }
                    }
                }
            ]
        }

        findings = normalize_semgrep_results(sample_results, project_id=1, scan_id=1, scanner_version="1.0.0")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.project_id, 1)
        self.assertEqual(f.scan_id, 1)
        self.assertEqual(f.rule_id, "rules.security.eval-injection")
        self.assertEqual(f.file_path, "src/app.py")
        self.assertEqual(f.line_number, 10)
        self.assertEqual(f.end_line_number, 12)
        self.assertEqual(f.description, "Dangerous eval usage")
        self.assertEqual(f.severity, FindingSeverity.HIGH)
        self.assertEqual(f.cwe, "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code")
        self.assertEqual(f.owasp, "A03:2021-Injection")
        self.assertEqual(f.code_snippet, "eval(user_input)")
        self.assertEqual(f.scanner_name, "semgrep")
        self.assertEqual(f.scanner_version, "1.0.0")
        self.assertIsNotNone(f.fingerprint)

    @unittest.skipIf(shutil.which("semgrep") is None, "Semgrep CLI not installed on this machine")
    def test_integration_semgrep_run_fixture(self):
        # Create a temporary directory acting as the trusted local project workspace
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            
            # Write a deterministic vulnerable javascript file (eval injection)
            test_file = tmp_path / "app.js"
            test_file.write_text("const input = req.query.input;\neval(input);\n")

            scanner = SemgrepSASTScanner()
            results = asyncio.run(scanner.scan(tmp_path))

            self.assertIn("results", results)
            self.assertIn("exit_code", results)
            
            # Verify we parsed findings count (eval should trigger a rule on config auto)
            # Since auto-config requires network for downloading rules sometimes, if offline it might use registry cache,
            # but we can verify that execution successfully resolves without crashing.
            self.assertTrue(isinstance(results["results"], dict))

    def test_real_integration_test_project(self):
        # Resolve path to test-sast-project
        test_project_path = Path("C:/kyptic/test-sast-project")
        if not test_project_path.exists():
            self.skipTest("C:/kyptic/test-sast-project does not exist")

        # Create scanner to resolve path dynamically and verify it's available
        scanner = SemgrepSASTScanner()
        semgrep_path = scanner._resolve_semgrep_path()
        if not semgrep_path:
            self.skipTest("Semgrep executable not found in PATH")

        # Create a database record for this project to mock Kyptic project ingestion flow
        project = Project(
            name="Real Test Project",
            technology="Python",
            status="active",
            source_type="ZIP",
            source_status="READY"
        )
        self.db.add(project)
        self.db.commit()
        self.db.refresh(project)

        # Create scan record
        scan = Scan(project_id=project.id, status=ScanStatus.QUEUED)
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        scan_id = scan.id

        # Point the storage service to target_dir. We patch get_source_dir to return test_project_path!
        with patch("app.services.scan_service.get_source_dir", return_value=test_project_path):
            with patch("app.services.scan_service.SessionLocal", return_value=self.db):
                # Run scan orchestrator
                asyncio.run(_run_scan(scan_id))

        # Check status and findings by querying db freshly
        self.db.close()
        self.db = self.Session()
        db_scan = self.db.get(Scan, scan_id)
        self.assertEqual(db_scan.status, ScanStatus.COMPLETED)
        self.assertEqual(db_scan.scanner, "semgrep")
        
        # Check findings
        from sqlalchemy import select
        findings = self.db.scalars(
            select(Finding).where(Finding.scan_id == scan_id)
        ).all()

        self.assertGreaterEqual(len(findings), 1)
        
        # Find the CWE-78 finding: python.lang.security.audit.subprocess-shell-true.subprocess-shell-true
        cwe_78_finding = None
        for f in findings:
            if f.rule_id == "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true":
                cwe_78_finding = f
                break
        
        self.assertIsNotNone(cwe_78_finding, "CWE-78 finding was not detected by Semgrep!")
        self.assertEqual(cwe_78_finding.severity, FindingSeverity.HIGH)
        self.assertEqual(cwe_78_finding.line_number, 4)
        self.assertIn("subprocess.call", cwe_78_finding.code_snippet)


if __name__ == "__main__":
    unittest.main()
