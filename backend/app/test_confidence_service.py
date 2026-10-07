import unittest
from app.services.confidence_service import ConfidenceService


class TestConfidenceService(unittest.TestCase):
    # A. Secret with only its own source: no false corroboration
    def test_secret_own_source_no_false_corroboration(self):
        score, level = ConfidenceService.calculate_confidence(
            source="secrets",
            scanner_name="detect-secrets",
            code_snippet="SECRET_KEY='********'",
            file_path="src/config.py",
            line_number=4,
            rule_id="Secret Keyword",
            fingerprint="fp_secret_1",
            verification_status="UNVERIFIED",
            correlation_count=0,
            correlated_sources=["Secrets"],
        )
        # Source (25) + Snippet (10) + File/Line (5) + RuleID (5) + Corroboration (0) = 45
        self.assertEqual(score, 45)
        self.assertEqual(level, "LOW")

    # B. SCA with only SCA source: no false corroboration
    def test_sca_own_source_no_false_corroboration(self):
        score, level = ConfidenceService.calculate_confidence(
            source="sca",
            scanner_name="sca-dependency",
            code_snippet="Package: lodash@4.17.15",
            file_path="package.json",
            line_number=None,
            rule_id="generic-dep-rule",
            fingerprint="fp_sca_1",
            verification_status="UNVERIFIED",
            correlation_count=0,
            correlated_sources=["SCA"],
        )
        # Source (25) + Snippet (10) + File (5) + RuleID (5) + Corroboration (0) = 45
        self.assertEqual(score, 45)
        self.assertEqual(level, "LOW")

    # C. SCA with CVE: receives authoritative advisory evidence points (+10)
    def test_sca_with_cve_advisory_evidence(self):
        score, level = ConfidenceService.calculate_confidence(
            source="sca",
            scanner_name="sca-dependency",
            code_snippet="Package: Flask@2.2.2\nFixed Version: 3.1.3",
            file_path="requirements.txt",
            line_number=None,
            rule_id="CVE-2026-27205",
            fingerprint="fp_sca_cve",
            verification_status="UNVERIFIED",
            correlation_count=0,
            correlated_sources=["SCA"],
        )
        # Source (25) + Snippet (10) + CVE (10) + File (5) + RuleID (5) + Corroboration (0) = 55
        self.assertEqual(score, 55)
        self.assertEqual(level, "MEDIUM")

    # D. SCA with GHSA: receives authoritative advisory evidence points (+10)
    def test_sca_with_ghsa_advisory_evidence(self):
        score, level = ConfidenceService.calculate_confidence(
            source="sca",
            scanner_name="sca-dependency",
            code_snippet="Package: lodash@4.17.15\nFixed Version: 4.17.21",
            file_path="package.json",
            line_number=None,
            rule_id="GHSA-29mw-wpgm-hmr9",
            fingerprint="fp_sca_ghsa",
            verification_status="UNVERIFIED",
            correlation_count=0,
            correlated_sources=["SCA"],
        )
        # Source (25) + Snippet (10) + GHSA (10) + File (5) + RuleID (5) + Corroboration (0) = 55
        self.assertEqual(score, 55)
        self.assertEqual(level, "MEDIUM")

    # E. SCA with requirements.txt and no line number: receives manifest/file evidence (+5)
    def test_sca_manifest_file_evidence_without_line_number(self):
        score, level = ConfidenceService.calculate_confidence(
            source="sca",
            scanner_name="sca-dependency",
            code_snippet="Package: requests@2.25.0",
            file_path="requirements.txt",
            line_number=None,
            rule_id="CVE-2023-32681",
            fingerprint="fp_sca_manifest",
            verification_status="UNVERIFIED",
            correlation_count=0,
            correlated_sources=["SCA"],
        )
        # Source (25) + Snippet (10) + CVE (10) + Manifest File (5) + RuleID (5) = 55
        self.assertEqual(score, 55)
        self.assertEqual(level, "MEDIUM")

    # F. SCA with genuine independent scanner corroboration: receives corroboration points (+10 or +20)
    def test_sca_independent_scanner_corroboration(self):
        score, level = ConfidenceService.calculate_confidence(
            source="sca",
            scanner_name="sca-dependency",
            code_snippet="Package: requests@2.25.0",
            file_path="requirements.txt",
            line_number=None,
            rule_id="CVE-2023-32681",
            fingerprint="fp_sca_corr",
            verification_status="CORROBORATED",
            correlation_count=1,
            correlated_sources=["SCA", "SAST"],
        )
        # Source (25) + Snippet (10) + CVE (10) + File (5) + RuleID (5) + Verif (15) + External SAST Corroboration (10) = 80
        self.assertEqual(score, 80)
        self.assertEqual(level, "HIGH")

    # G. Running confidence calculation twice: identical result
    def test_deterministic_reproducibility(self):
        kwargs = dict(
            source="sca",
            scanner_name="sca-dependency",
            code_snippet="Package: requests@2.25.1",
            file_path="requirements.txt",
            line_number=None,
            cwe="CWE-1104",
            owasp="A06:2021",
            rule_id="CVE-2024-1234",
            fingerprint="fp_test_4",
            verification_status="UNVERIFIED",
            correlation_count=0,
            correlated_sources=[],
        )
        res1 = ConfidenceService.calculate_confidence(**kwargs)
        res2 = ConfidenceService.calculate_confidence(**kwargs)
        self.assertEqual(res1, res2)

    # H. All scores remain 0-100
    def test_score_bounded_0_to_100(self):
        max_score, _ = ConfidenceService.calculate_confidence(
            source="dast",
            scanner_name="dast-active-probe",
            code_snippet="Full HTTP request/response payload proof string",
            file_path="/api/v1/login",
            line_number=10,
            cwe="CWE-89",
            owasp="A03:2021",
            rule_id="CVE-2026-9999",
            fingerprint="fp_max",
            verification_status="VERIFIED",
            correlation_count=5,
            correlated_sources=["SAST", "WEB DAST", "SECRETS"],
        )
        self.assertLessEqual(max_score, 100)

        min_score, _ = ConfidenceService.calculate_confidence(
            source="unknown",
            scanner_name="custom",
            code_snippet=None,
            file_path=None,
            line_number=None,
            verification_status="FALSE_POSITIVE",
            dast_attempted_and_failed=True,
        )
        self.assertGreaterEqual(min_score, 0)


if __name__ == "__main__":
    unittest.main()
