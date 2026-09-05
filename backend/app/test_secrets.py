import io
import unittest
import json
import hashlib
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock
import asyncio

from app.models.finding import FindingSeverity, FindingSource
from app.services.detect_secrets_scanner import DetectSecretsScanner
from app.services.finding_normalizer import (
    find_secret_substring,
    normalize_detect_secrets_results,
    generate_fingerprint
)
from app.schemas.finding import FindingResponse

class TestSecretsEngine(unittest.TestCase):
    def test_find_secret_substring_quoted(self):
        line = 'token = "FAKE_KYPTIC_TEST_SECRET_123456"'
        raw_secret = "FAKE_KYPTIC_TEST_SECRET_123456"
        hashed_secret = hashlib.sha1(raw_secret.encode('utf-8')).hexdigest()
        
        found = find_secret_substring(line, hashed_secret)
        self.assertEqual(found, raw_secret)

    def test_find_secret_substring_unquoted(self):
        line = 'token: FAKE_KYPTIC_TEST_SECRET_123456'
        raw_secret = "FAKE_KYPTIC_TEST_SECRET_123456"
        hashed_secret = hashlib.sha1(raw_secret.encode('utf-8')).hexdigest()
        
        found = find_secret_substring(line, hashed_secret)
        self.assertEqual(found, raw_secret)

    def test_find_secret_substring_not_found(self):
        line = 'token = "something_else"'
        raw_secret = "FAKE_KYPTIC_TEST_SECRET_123456"
        hashed_secret = hashlib.sha1(raw_secret.encode('utf-8')).hexdigest()
        
        found = find_secret_substring(line, hashed_secret)
        self.assertIsNone(found)

    def test_find_secret_substring_special_chars(self):
        line = 'token = "!@#$%^&*()_+"'
        raw_secret = "!@#$%^&*()_+"
        hashed_secret = hashlib.sha1(raw_secret.encode('utf-8')).hexdigest()
        
        found = find_secret_substring(line, hashed_secret)
        self.assertEqual(found, raw_secret)

    def test_find_secret_substring_underscores_hyphens(self):
        line = 'token: my_secret-token'
        raw_secret = "my_secret-token"
        hashed_secret = hashlib.sha1(raw_secret.encode('utf-8')).hexdigest()
        
        found = find_secret_substring(line, hashed_secret)
        self.assertEqual(found, raw_secret)

    def test_secret_cannot_be_located_fallback_masks_entire_line(self):
        results = {
            "results": {
                "src/config.py": [
                    {
                        "type": "Base64 High Entropy String",
                        "filename": "src/config.py",
                        "hashed_secret": hashlib.sha1(b"missing-secret-value").hexdigest(),
                        "is_verified": False,
                        "line_number": 2
                    }
                ]
            }
        }
        
        # Line does not contain "missing-secret-value", so candidate matching fails
        file_content = '# Configuration\npassword = "different-value-here"\nport = 8080\n'
        
        with patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=file_content):
            
            findings = normalize_detect_secrets_results(
                results_dict=results,
                project_id=1,
                scan_id=42,
                scanner_version="1.5.0",
                target_dir=Path("/tmp/sandbox")
            )
            
            self.assertEqual(len(findings), 1)
            finding = findings[0]
            
            # Should fallback to masking the entire line
            self.assertEqual(finding.code_snippet, "********")

    def test_raw_secret_absent_from_all_fields_and_serialized(self):
        raw_secret = "super-secret-12345"
        hashed_secret = hashlib.sha1(raw_secret.encode('utf-8')).hexdigest()
        
        results = {
            "results": {
                "src/config.py": [
                    {
                        "type": "Base64 High Entropy String",
                        "filename": "src/config.py",
                        "hashed_secret": hashed_secret,
                        "is_verified": False,
                        "line_number": 2
                    }
                ]
            }
        }
        
        file_content = f'# Configuration\npassword = "{raw_secret}"\nport = 8080\n'
        
        with patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=file_content):
            
            findings = normalize_detect_secrets_results(
                results_dict=results,
                project_id=1,
                scan_id=42,
                scanner_version="1.5.0",
                target_dir=Path("/tmp/sandbox")
            )
            
            self.assertEqual(len(findings), 1)
            finding = findings[0]
            
            # Verify raw secret is absent from all finding fields
            self.assertNotIn(raw_secret, finding.title)
            self.assertNotIn(raw_secret, finding.description)
            self.assertNotIn(raw_secret, finding.code_snippet)
            
            # Verify raw secret is absent from serialized representation / API schema response
            from datetime import datetime
            finding.id = 1
            finding.created_at = datetime.utcnow()
            schema_response = FindingResponse.model_validate(finding)
            serialized_json = schema_response.model_dump_json()
            
            self.assertNotIn(raw_secret, serialized_json)
            self.assertIn("********", serialized_json)

    def test_normalization_fields(self):
        results = {
            "results": {
                "src/config.py": [
                    {
                        "type": "PrivateKeyDetector",
                        "filename": "src/config.py",
                        "hashed_secret": "some_hash",
                        "is_verified": False,
                        "line_number": 5
                    }
                ]
            }
        }
        
        findings = normalize_detect_secrets_results(
            results_dict=results,
            project_id=1,
            scan_id=42,
            scanner_version="1.5.0",
            target_dir=Path("/tmp/sandbox")
        )
        
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        
        self.assertEqual(finding.project_id, 1)
        self.assertEqual(finding.scan_id, 42)
        self.assertEqual(finding.file_path, "src/config.py")
        self.assertEqual(finding.line_number, 5)
        self.assertEqual(finding.category, "Secrets Exposure")
        self.assertEqual(finding.source, FindingSource.SECRETS)
        self.assertEqual(finding.scanner_name, "detect-secrets")
        self.assertEqual(finding.scanner_version, "1.5.0")
        self.assertEqual(finding.severity, FindingSeverity.CRITICAL)  # PrivateKeyDetector -> CRITICAL
        self.assertEqual(finding.cvss, 9.5)
        
        # Test fingerprint stability
        fp1 = finding.fingerprint
        fp2 = generate_fingerprint(1, "detect-secrets", "PrivateKeyDetector", "src/config.py", 5, finding.title)
        self.assertEqual(fp1, fp2)

    def test_scanner_subprocess_arguments_and_no_shell(self):
        with patch("subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.poll.return_value = 0
            mock_proc.communicate.return_value = ('{"results": {}}', '')
            mock_proc.returncode = 0
            mock_popen.return_value = mock_proc

            scanner = DetectSecretsScanner()
            
            with patch.object(scanner, "get_version", return_value="1.5.0"):
                res = asyncio.run(scanner.scan(Path("/tmp/sandbox")))
                
            self.assertEqual(res["version"], "1.5.0")
            
            # Verify shell=False and arguments list
            args, kwargs = mock_popen.call_args
            cmd_list = args[0]
            self.assertEqual(kwargs.get("shell"), False)
            self.assertIn("-m", cmd_list)
            self.assertIn("detect_secrets", cmd_list)
            self.assertIn("scan", cmd_list)
            self.assertIn("--all-files", cmd_list)

    def test_scanner_malformed_json_handling(self):
        with patch("subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.poll.return_value = 0
            mock_proc.communicate.return_value = ('invalid json output', '')
            mock_proc.returncode = 0
            mock_popen.return_value = mock_proc

            scanner = DetectSecretsScanner()
            with self.assertRaises(RuntimeError) as context:
                asyncio.run(scanner.scan(Path("/tmp/sandbox")))
            self.assertIn("Failed to parse detect-secrets JSON", str(context.exception))

    def test_scanner_failure_exit_code(self):
        with patch("subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.poll.return_value = 0
            mock_proc.communicate.return_value = ('', 'fatal error')
            mock_proc.returncode = 1
            mock_popen.return_value = mock_proc

            scanner = DetectSecretsScanner()
            with self.assertRaises(RuntimeError) as context:
                asyncio.run(scanner.scan(Path("/tmp/sandbox")))
            self.assertIn("execution failed with code 1", str(context.exception))
