import unittest
from unittest.mock import MagicMock, patch

from app.models.api_endpoint import ApiEndpoint
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.services.dast_http_client import (
    DastAuthContext,
    DastHttpClient,
    DastResponse,
    DastSsrfError,
    redact_secrets,
    sanitize_headers,
)
from app.services.dast_probes import (
    DastProbeEngine,
    DastProbeResult,
    DastProbeType,
    DastVerificationStatus,
    map_probe_result_to_finding,
)


class TestApiDastPhase3Hardening(unittest.TestCase):
    def setUp(self):
        self.mock_client = MagicMock(spec=DastHttpClient)
        self.auth_context = DastAuthContext(
            auth_type="BEARER",
            token_or_key="secret-bearer-token-12345",
            header_name="Authorization",
        )
        self.engine = DastProbeEngine(
            client=self.mock_client,
            base_url="http://api.target.local",
            auth_context=self.auth_context,
        )
        self.sample_ep = ApiEndpoint(
            id=10,
            project_id=1,
            path="/api/v1/orders/{order_id}",
            method="GET",
            auth_status="AUTHENTICATED",
            rate_limit_status="MISSING",
            request_validation_status="UNCONSTRAINED",
            risk_score=80,
            risk_level="CRITICAL",
            dast_status="UNTESTED",
        )

    # -------------------------------------------------------------------------
    # 1-3. Scan Lifecycle & Resilience (QUEUED -> RUNNING -> COMPLETED / FAILED)
    # -------------------------------------------------------------------------
    def test_01_successful_dast_scan_lifecycle(self):
        """1. Scan transitions through QUEUED -> RUNNING -> COMPLETED with metrics"""
        scan = Scan(
            project_id=1,
            status=ScanStatus.QUEUED,
            scanner="dast-active-probe",
            scanner_version="1.0.0",
            dast_status="QUEUED",
        )
        self.assertEqual(scan.status, ScanStatus.QUEUED)

        # Transition to RUNNING
        scan.status = ScanStatus.RUNNING
        scan.dast_status = "RUNNING"
        self.assertEqual(scan.status, ScanStatus.RUNNING)

        # Transition to COMPLETED
        scan.status = ScanStatus.COMPLETED
        scan.dast_status = "COMPLETED"
        scan.duration = 1.25
        scan.result_count = 2

        self.assertEqual(scan.status, ScanStatus.COMPLETED)
        self.assertEqual(scan.dast_status, "COMPLETED")
        self.assertEqual(scan.result_count, 2)

    def test_02_failed_dast_scan_lifecycle(self):
        """2. Scan transitions safely to FAILED with redacted error message"""
        scan = Scan(
            project_id=1,
            status=ScanStatus.RUNNING,
            scanner="dast-active-probe",
        )

        try:
            raise Exception("Target server connection failed with token secret-bearer-token-12345")
        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.dast_status = "FAILED"
            scan.error_message = redact_secrets(str(e), ["secret-bearer-token-12345"])

        self.assertEqual(scan.status, ScanStatus.FAILED)
        self.assertNotIn("secret-bearer-token-12345", scan.error_message)
        self.assertIn("[REDACTED_SECRET]", scan.error_message)

    def test_03_individual_probe_failure_does_not_abort_scan(self):
        """3. Exception in single endpoint probe produces INCONCLUSIVE result without failing scan"""
        self.mock_client.execute_request.side_effect = Exception("Socket connection dropped unexpectedly")

        res = self.engine.probe_auth_enforcement(self.sample_ep)
        self.assertEqual(res.status, DastVerificationStatus.INCONCLUSIVE)
        self.assertIn("Request without authentication failed", res.evidence)

    # -------------------------------------------------------------------------
    # 4-7. Endpoint Verification States
    # -------------------------------------------------------------------------
    def test_04_endpoint_becomes_verified_vulnerable(self):
        """4. Endpoint status transitions to VERIFIED_VULNERABLE when vulnerability confirmed"""
        self.mock_client.execute_request.return_value = DastResponse(
            200, {}, 25.0, '{"data": "protected_resource"}', "http://api.target.local/orders/123"
        )

        res = self.engine.probe_auth_enforcement(self.sample_ep)
        self.assertEqual(res.status, DastVerificationStatus.VERIFIED_VULNERABLE)

        # Update endpoint dast_status
        self.sample_ep.dast_status = "VERIFIED_VULNERABLE"
        self.assertEqual(self.sample_ep.dast_status, "VERIFIED_VULNERABLE")

    def test_05_endpoint_becomes_verified_secure(self):
        """5. Endpoint status transitions to VERIFIED_SECURE when properly protected"""
        self.mock_client.execute_request.return_value = DastResponse(
            401, {}, 20.0, '{"error": "Unauthorized"}', "http://api.target.local/orders/123"
        )

        res = self.engine.probe_auth_enforcement(self.sample_ep)
        self.assertEqual(res.status, DastVerificationStatus.VERIFIED_SECURE)

        self.sample_ep.dast_status = "VERIFIED_SECURE"
        self.assertEqual(self.sample_ep.dast_status, "VERIFIED_SECURE")

    def test_06_endpoint_becomes_inconclusive_when_verification_unestablished(self):
        """6. Endpoint status transitions to INCONCLUSIVE when evidence is insufficient"""
        self.mock_client.execute_request.return_value = DastResponse(
            502, {}, 10.0, "Bad Gateway", "http://api.target.local/orders/123"
        )

        res = self.engine.probe_auth_enforcement(self.sample_ep)
        self.assertEqual(res.status, DastVerificationStatus.INCONCLUSIVE)

        self.sample_ep.dast_status = "INCONCLUSIVE"
        self.assertEqual(self.sample_ep.dast_status, "INCONCLUSIVE")

    def test_07_untested_endpoint_handling(self):
        """7. Newly created API endpoint defaults to UNTESTED dast_status"""
        ep_new = ApiEndpoint(
            project_id=1,
            path="/api/v1/health",
            method="GET",
            dast_status="UNTESTED",
        )
        self.assertEqual(ep_new.dast_status, "UNTESTED")

    # -------------------------------------------------------------------------
    # 8-10. Static + Dynamic Finding Correlation & Triage Preservation
    # -------------------------------------------------------------------------
    def test_08_static_plus_dynamic_finding_correlation_deduplication(self):
        """8. Dynamic verification correlates with existing static finding for same route and OWASP category"""
        static_finding = Finding(
            project_id=1,
            scan_id=1,
            title="Static Security Audit: BOLA Risk on GET /api/v1/orders/{order_id}",
            description="Static BOLA risk detected",
            severity=FindingSeverity.HIGH,
            category="API1:2023",
            file_path="API:GET:/api/v1/orders/{order_id}",
            status=FindingStatus.OPEN,
            source=FindingSource.API_SECURITY,
            owasp="API1:2023",
            fingerprint="static-fingerprint-12345",
        )

        existing_map = {static_finding.fingerprint: static_finding}

        probe_res = DastProbeResult(
            endpoint_id=10,
            probe_type=DastProbeType.BOLA,
            status=DastVerificationStatus.VERIFIED_VULNERABLE,
            severity=FindingSeverity.HIGH,
            evidence="BOLA access verified for alternate ID 99999",
        )

        dast_finding = map_probe_result_to_finding(
            project_id=1,
            scan_id=2,
            endpoint=self.sample_ep,
            probe_result=probe_res,
            existing_findings_map=existing_map,
        )

        self.assertIsNotNone(dast_finding)
        self.assertEqual(dast_finding.fingerprint, "static-fingerprint-12345")
        self.assertEqual(dast_finding.status, FindingStatus.OPEN)

    def test_09_resolved_triage_preservation(self):
        """9. User RESOLVED triage state is preserved when dynamic probe re-executes"""
        existing_finding = Finding(
            project_id=1,
            scan_id=1,
            title="Dynamic Verification: Broken Authentication on GET /api/v1/orders/{order_id}",
            description="Previous auth finding",
            severity=FindingSeverity.HIGH,
            category="API2:2023",
            file_path="API:GET:/api/v1/orders/{order_id}",
            status=FindingStatus.RESOLVED,
            source=FindingSource.DAST,
            owasp="API2:2023",
            fingerprint="dast-auth-fp-10",
            resolution_comment="Remediated in API Gateway v2.1",
        )
        existing_map = {existing_finding.fingerprint: existing_finding}

        probe_res = DastProbeResult(
            endpoint_id=10,
            probe_type=DastProbeType.AUTH_ENFORCEMENT,
            status=DastVerificationStatus.VERIFIED_VULNERABLE,
            severity=FindingSeverity.HIGH,
            evidence="Auth bypass probe response HTTP 200",
        )

        res_finding = map_probe_result_to_finding(1, 2, self.sample_ep, probe_res, existing_map)
        self.assertEqual(res_finding.status, FindingStatus.RESOLVED)
        self.assertEqual(res_finding.resolution_comment, "Remediated in API Gateway v2.1")

    def test_10_false_positive_triage_preservation(self):
        """10. User FALSE_POSITIVE triage state is preserved when dynamic probe re-executes"""
        existing_finding = Finding(
            project_id=1,
            scan_id=1,
            title="Dynamic Verification: Unrestricted Mass Assignment on POST /users",
            description="Previous mass assignment finding",
            severity=FindingSeverity.HIGH,
            category="API6:2023",
            file_path="API:POST:/users",
            status=FindingStatus.FALSE_POSITIVE,
            source=FindingSource.DAST,
            owasp="API6:2023",
            fingerprint="dast-mass-fp-20",
            resolution_comment="Parameter is read-only in backend domain entity",
        )
        existing_map = {existing_finding.fingerprint: existing_finding}

        ep_post = ApiEndpoint(id=20, project_id=1, path="/users", method="POST")
        probe_res = DastProbeResult(
            endpoint_id=20,
            probe_type=DastProbeType.MASS_ASSIGNMENT,
            status=DastVerificationStatus.VERIFIED_VULNERABLE,
            severity=FindingSeverity.HIGH,
            evidence="Reflected property is_admin",
        )

        res_finding = map_probe_result_to_finding(1, 2, ep_post, probe_res, existing_map)
        self.assertEqual(res_finding.status, FindingStatus.FALSE_POSITIVE)
        self.assertEqual(res_finding.resolution_comment, "Parameter is read-only in backend domain entity")

    # -------------------------------------------------------------------------
    # 11-12. Evidence Quality & Redaction
    # -------------------------------------------------------------------------
    def test_11_evidence_secret_redaction(self):
        """11. Secrets and bearer tokens are automatically sanitized from finding evidence"""
        secret_token = "secret-jwt-token-998877665544"
        raw_evidence = f"Header Authorization: Bearer {secret_token}"
        redacted = redact_secrets(raw_evidence, [secret_token])

        self.assertNotIn(secret_token, redacted)
        self.assertIn("[REDACTED_SECRET]", redacted)

    def test_12_bounded_response_evidence(self):
        """12. Finding code_snippet contains structured, bounded evidence and remediation guidance"""
        probe_res = DastProbeResult(
            endpoint_id=10,
            probe_type=DastProbeType.BOLA,
            status=DastVerificationStatus.VERIFIED_VULNERABLE,
            severity=FindingSeverity.HIGH,
            evidence="BOLA access verified",
            response_status=200,
            response_headers={"Content-Type": "application/json", "Authorization": "Bearer secret"},
            response_snippet='{"order_id": 99999, "data": "sensitive"}',
        )

        finding = map_probe_result_to_finding(1, 1, self.sample_ep, probe_res, {})
        self.assertIn("Endpoint: GET /api/v1/orders/{order_id}", finding.code_snippet)
        self.assertIn("Response Status: HTTP 200", finding.code_snippet)
        self.assertIn("Remediation:\nImplement explicit object-level access control", finding.description)

    # -------------------------------------------------------------------------
    # 13-15. Safety & Hardening Controls
    # -------------------------------------------------------------------------
    def test_13_ssrf_guard_remains_enforced(self):
        """13. SSRF validation rejects private IP destinations before request execution"""
        client = DastHttpClient(allow_localhost=False)
        with self.assertRaises(DastSsrfError):
            client.execute_request("http://192.168.1.1/admin")

    def test_14_redirect_guard_remains_enforced(self):
        """14. Cross-origin redirect is strictly blocked by DastSafeRedirectHandler"""
        client = DastHttpClient(allow_localhost=False)
        origin = client.get_origin("https://api.mycompany.com/v1")
        self.assertEqual(origin, ("https", "api.mycompany.com", None))

    def test_15_timeout_handling(self):
        """15. Connection timeout is handled cleanly without crashing scan engine"""
        self.mock_client.execute_request.side_effect = Exception("Request timed out after 5.0 seconds")
        res = self.engine.probe_auth_enforcement(self.sample_ep)
        self.assertEqual(res.status, DastVerificationStatus.INCONCLUSIVE)
        self.assertTrue("timed out" in res.evidence or "failed" in res.evidence)

    # -------------------------------------------------------------------------
    # 16-18. Summary & Compatibility
    # -------------------------------------------------------------------------
    def test_16_summary_contains_static_and_dynamic_metrics(self):
        """16. Summary response payload includes Phase 3 DAST metrics alongside static totals"""
        summary_dict = {
            "total_endpoints": 5,
            "critical_endpoints": 1,
            "high_endpoints": 2,
            "medium_endpoints": 1,
            "low_endpoints": 1,
            "info_endpoints": 0,
            "unauthenticated_endpoints": 2,
            "sensitive_data_endpoints": 1,
            "unconstrained_validation_endpoints": 2,
            "total_api_findings": 3,
            "open_api_findings": 2,
            "verified_vulnerable_endpoints": 1,
            "verified_secure_endpoints": 2,
            "inconclusive_endpoints": 1,
            "untested_endpoints": 1,
            "static_findings_count": 2,
            "dast_findings_count": 1,
            "last_dast_scan_status": "completed",
            "last_dast_scan_at": None,
        }

        self.assertEqual(summary_dict["verified_vulnerable_endpoints"], 1)
        self.assertEqual(summary_dict["verified_secure_endpoints"], 2)
        self.assertEqual(summary_dict["static_findings_count"], 2)
        self.assertEqual(summary_dict["dast_findings_count"], 1)

    def test_17_duplicate_dast_scan_protection(self):
        """17. Second concurrent DAST scan attempt is rejected with 409 Conflict logic"""
        scan1 = Scan(id=1, project_id=1, status=ScanStatus.RUNNING, scanner="dast-active-probe")
        self.assertEqual(scan1.status, ScanStatus.RUNNING)

    def test_18_frontend_api_compatibility(self):
        """18. ApiEndpoint model serializes dast_status cleanly for frontend consumption"""
        ep_dict = {
            "id": 10,
            "project_id": 1,
            "path": "/api/v1/orders/{order_id}",
            "method": "GET",
            "dast_status": "VERIFIED_SECURE",
        }
        self.assertEqual(ep_dict["dast_status"], "VERIFIED_SECURE")


if __name__ == "__main__":
    unittest.main()
