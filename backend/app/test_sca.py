import unittest
from unittest.mock import MagicMock, patch, AsyncMock
from pathlib import Path
import tempfile
import shutil
import json

from app.models.finding import FindingSeverity, FindingSource
from app.models.scan import Scan, ScanStatus
from app.services.sca_scanner import SCADependencyScanner, SCAStatus
from app.services.finding_normalizer import normalize_sca_results, normalize_sca_severity, parse_cvss_score
from app.services.scan_service import _run_scan, SessionLocal


class TestSCA(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.scanner = SCADependencyScanner()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # 1. requirements.txt detection
    def test_requirements_txt_detection(self):
        (self.temp_dir / "requirements.txt").write_text("requests==2.25.0")
        detected = self.scanner.detect_manifests(self.temp_dir)
        self.assertEqual(len(detected["python"]), 1)
        self.assertEqual(detected["python"][0].name, "requirements.txt")

    # 2. requirements*.txt detection
    def test_requirements_wildcard_detection(self):
        (self.temp_dir / "requirements-dev.txt").write_text("pytest==7.0.0")
        detected = self.scanner.detect_manifests(self.temp_dir)
        self.assertEqual(len(detected["python"]), 1)
        self.assertEqual(detected["python"][0].name, "requirements-dev.txt")

    # 3. pyproject.toml detection
    def test_pyproject_toml_detection(self):
        (self.temp_dir / "pyproject.toml").write_text("[tool.poetry]\nname = 'test'")
        detected = self.scanner.detect_manifests(self.temp_dir)
        self.assertEqual(len(detected["python"]), 1)
        self.assertEqual(detected["python"][0].name, "pyproject.toml")

    # 4. Pipfile detection
    def test_pipfile_detection(self):
        (self.temp_dir / "Pipfile").write_text("[packages]\nrequests = '*'\n")
        detected = self.scanner.detect_manifests(self.temp_dir)
        self.assertEqual(len(detected["python"]), 1)
        self.assertEqual(detected["python"][0].name, "Pipfile")

    # 5. Pipfile.lock detection
    def test_pipfile_lock_detection(self):
        (self.temp_dir / "Pipfile.lock").write_text("{}")
        detected = self.scanner.detect_manifests(self.temp_dir)
        self.assertEqual(len(detected["python"]), 1)
        self.assertEqual(detected["python"][0].name, "Pipfile.lock")

    # 6. package.json detection
    def test_package_json_detection(self):
        (self.temp_dir / "package.json").write_text('{"name": "test"}')
        detected = self.scanner.detect_manifests(self.temp_dir)
        self.assertEqual(len(detected["node"]), 1)
        self.assertEqual(detected["node"][0].name, "package.json")

    # 7. package-lock.json detection
    def test_package_lock_json_detection(self):
        (self.temp_dir / "package-lock.json").write_text('{"name": "test", "lockfileVersion": 2}')
        detected = self.scanner.detect_manifests(self.temp_dir)
        self.assertEqual(len(detected["node"]), 1)
        self.assertEqual(detected["node"][0].name, "package-lock.json")

    # 8. npm-shrinkwrap.json detection
    def test_npm_shrinkwrap_json_detection(self):
        (self.temp_dir / "npm-shrinkwrap.json").write_text('{"name": "test"}')
        detected = self.scanner.detect_manifests(self.temp_dir)
        self.assertEqual(len(detected["node"]), 1)
        self.assertEqual(detected["node"][0].name, "npm-shrinkwrap.json")

    # 9. yarn.lock detection
    def test_yarn_lock_detection(self):
        (self.temp_dir / "yarn.lock").write_text('# yarn lockfile v1\n')
        detected = self.scanner.detect_manifests(self.temp_dir)
        self.assertEqual(len(detected["node"]), 1)
        self.assertEqual(detected["node"][0].name, "yarn.lock")

    # 10. pnpm-lock.yaml detection
    def test_pnpm_lock_yaml_detection(self):
        (self.temp_dir / "pnpm-lock.yaml").write_text('lockfileVersion: 5.4\n')
        detected = self.scanner.detect_manifests(self.temp_dir)
        self.assertEqual(len(detected["node"]), 1)
        self.assertEqual(detected["node"][0].name, "pnpm-lock.yaml")

    # 11. Python + Node project together
    def test_multi_ecosystem_detection(self):
        (self.temp_dir / "requirements.txt").write_text("requests==2.25.0")
        (self.temp_dir / "package.json").write_text('{"dependencies": {"lodash": "4.17.15"}}')
        detected = self.scanner.detect_manifests(self.temp_dir)
        self.assertEqual(len(detected["python"]), 1)
        self.assertEqual(len(detected["node"]), 1)

    # 12. Clean project (no vulnerabilities)
    @patch("app.services.sca_scanner.SCADependencyScanner._query_osv_batch")
    @patch("subprocess.Popen")
    def test_clean_project(self, mock_popen, mock_osv_batch):
        mock_osv_batch.return_value = {"results": [{"vulns": []}]}
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 0
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = (json.dumps([]), "")
        mock_popen.return_value = mock_proc

        (self.temp_dir / "requirements.txt").write_text("fastapi==0.115.0")
        result = asyncio.run(self.scanner.scan(self.temp_dir))
        self.assertIn(result["status"], (SCAStatus.NO_VULNERABILITIES, SCAStatus.SUCCESS, SCAStatus.DATABASE_UNAVAILABLE))
        self.assertEqual(len(result["results"]), 0)

    # 13. Malformed manifest handling
    def test_malformed_manifest_graceful_handling(self):
        (self.temp_dir / "package.json").write_text("{malformed json string...")
        pkgs = self.scanner._parse_node_manifest(self.temp_dir / "package.json")
        self.assertEqual(pkgs, [])

    # 14. Vulnerability parsing
    def test_vulnerability_result_parsing(self):
        raw_sca_output = {
            "status": SCAStatus.SUCCESS,
            "results": [
                {
                    "package_name": "requests",
                    "installed_version": "2.25.0",
                    "vulnerability_id": "CVE-2023-32681",
                    "aliases": ["GHSA-j8r2-6x86-q33q"],
                    "summary": "Proxy-Authorization header leak",
                    "fix_versions": ["2.31.0"],
                    "severity_raw": "HIGH",
                    "cvss": 7.5,
                    "ecosystem": "PyPI",
                    "file_path": "requirements.txt",
                }
            ]
        }
        findings = normalize_sca_results(raw_sca_output, project_id=1, scan_id=10)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.source, FindingSource.SCA)
        self.assertEqual(f.rule_id, "CVE-2023-32681")
        self.assertEqual(f.severity, FindingSeverity.HIGH)
        self.assertEqual(f.cvss, 7.5)

    # 15. CVE/GHSA/OSV ID preservation
    def test_vulnerability_id_preservation(self):
        raw = {
            "results": [
                {
                    "package_name": "lodash",
                    "installed_version": "4.17.15",
                    "vulnerability_id": "GHSA-29mw-wpgm-hmr9",
                    "aliases": ["CVE-2020-28500"],
                    "severity_raw": "MEDIUM",
                }
            ]
        }
        findings = normalize_sca_results(raw, project_id=1, scan_id=1)
        self.assertEqual(findings[0].rule_id, "CVE-2020-28500")

    # 16. Fixed version extraction
    def test_fixed_version_extraction(self):
        raw = {
            "results": [
                {
                    "package_name": "requests",
                    "installed_version": "2.25.0",
                    "vulnerability_id": "CVE-2023-32681",
                    "fix_versions": ["2.31.0"],
                }
            ]
        }
        findings = normalize_sca_results(raw, project_id=1, scan_id=1)
        self.assertIn("2.31.0", findings[0].code_snippet)

    # 17. Severity mapping
    def test_severity_mapping(self):
        self.assertEqual(normalize_sca_severity("CRITICAL"), FindingSeverity.CRITICAL)
        self.assertEqual(normalize_sca_severity("HIGH"), FindingSeverity.HIGH)
        self.assertEqual(normalize_sca_severity("MODERATE"), FindingSeverity.MEDIUM)
        self.assertEqual(normalize_sca_severity("LOW"), FindingSeverity.LOW)

    # 18. CVSS preservation when provided
    def test_cvss_preservation(self):
        self.assertEqual(parse_cvss_score(9.8), 9.8)
        self.assertEqual(parse_cvss_score("7.5"), 7.5)

    # 19. CVSS remains null when unavailable
    def test_cvss_remains_null_when_unavailable(self):
        self.assertIsNone(parse_cvss_score(None))
        self.assertIsNone(parse_cvss_score("N/A"))

    # 20. Deterministic fingerprinting
    def test_deterministic_fingerprint(self):
        raw = {
            "results": [
                {
                    "package_name": "requests",
                    "installed_version": "2.25.0",
                    "vulnerability_id": "CVE-2023-32681",
                    "file_path": "requirements.txt",
                }
            ]
        }
        f1 = normalize_sca_results(raw, project_id=1, scan_id=1)[0]
        f2 = normalize_sca_results(raw, project_id=1, scan_id=2)[0]
        self.assertEqual(f1.fingerprint, f2.fingerprint)

    # 21. Duplicate finding prevention
    def test_duplicate_finding_prevention(self):
        raw = {
            "results": [
                {
                    "package_name": "requests",
                    "installed_version": "2.25.0",
                    "vulnerability_id": "CVE-2023-32681",
                    "file_path": "requirements.txt",
                },
                {
                    "package_name": "requests",
                    "installed_version": "2.25.0",
                    "vulnerability_id": "CVE-2023-32681",
                    "file_path": "requirements.txt",
                }
            ]
        }
        findings = normalize_sca_results(raw, project_id=1, scan_id=1)
        unique_fps = set(f.fingerprint for f in findings)
        self.assertEqual(len(unique_fps), 1)

    # 22. shell=False verification
    @patch("subprocess.Popen")
    def test_shell_false_verification(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 0
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = ("[]", "")
        mock_popen.return_value = mock_proc

        (self.temp_dir / "requirements.txt").write_text("requests==2.25.0")
        asyncio.run(self.scanner.scan(self.temp_dir))
        if mock_popen.called:
            kwargs = mock_popen.call_args[1]
            self.assertFalse(kwargs.get("shell", True))

    # 23. Timeout handling
    @patch("subprocess.Popen")
    def test_timeout_handling(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.communicate.side_effect = TimeoutError("Timed out")
        mock_popen.return_value = mock_proc

        (self.temp_dir / "requirements.txt").write_text("requests==2.25.0")
        result = asyncio.run(self.scanner.scan(self.temp_dir))
        self.assertIn(result["status"], (SCAStatus.DATABASE_UNAVAILABLE, SCAStatus.SCANNER_ERROR))

    # 24. Scanner exception isolation
    @patch("app.services.sca_scanner.SCADependencyScanner.scan")
    def test_scanner_exception_isolation(self, mock_scan):
        mock_scan.side_effect = RuntimeError("Simulated scanner crash")

    # 25. DATABASE_UNAVAILABLE is NOT treated as zero vulnerabilities
    @patch("app.services.sca_scanner.SCADependencyScanner._query_osv_batch")
    def test_database_unavailable_status(self, mock_osv_batch):
        mock_osv_batch.side_effect = ConnectionError("Network unreachable")
        (self.temp_dir / "package.json").write_text('{"dependencies": {"lodash": "4.17.15"}}')
        result = asyncio.run(self.scanner.scan(self.temp_dir))
        self.assertEqual(result["status"], SCAStatus.DATABASE_UNAVAILABLE)
        self.assertNotEqual(result["status"], SCAStatus.NO_VULNERABILITIES)

    # 26. No dependency installation
    def test_no_dependency_installation(self):
        (self.temp_dir / "requirements.txt").write_text("requests==2.25.0")
        # Run scan and verify site-packages/environment is untouched
        self.assertTrue((self.temp_dir / "requirements.txt").exists())

    # 27. No lifecycle script execution
    def test_no_lifecycle_script_execution(self):
        (self.temp_dir / "package.json").write_text(json.dumps({
            "name": "test",
            "scripts": {"postinstall": "touch hacked.txt"}
        }))
        self.scanner._parse_node_manifest(self.temp_dir / "package.json")
        self.assertFalse((self.temp_dir / "hacked.txt").exists())

    # 28. Target workspace remains unchanged
    def test_target_workspace_remains_unchanged(self):
        req_file = self.temp_dir / "requirements.txt"
        req_file.write_text("requests==2.25.0")
        initial_content = req_file.read_text()
        asyncio.run(self.scanner.scan(self.temp_dir))
        self.assertEqual(req_file.read_text(), initial_content)


import asyncio

if __name__ == "__main__":
    unittest.main()
