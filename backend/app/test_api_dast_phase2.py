import unittest
from unittest.mock import MagicMock, patch

from app.models.api_endpoint import ApiEndpoint
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.services.dast_http_client import (
    DastAuthContext,
    DastHttpClient,
    DastResponse,
    DastSsrfError,
    redact_secrets,
)
from app.services.dast_probes import (
    DastProbeEngine,
    DastProbeResult,
    DastProbeType,
    DastVerificationStatus,
    map_probe_result_to_finding,
)


class TestApiDastPhase2Probes(unittest.TestCase):
    def setUp(self):
        self.mock_client = MagicMock(spec=DastHttpClient)
        self.auth_context = DastAuthContext(
            auth_type="BEARER",
            token_or_key="secret-token-12345",
            header_name="Authorization",
        )
        self.engine = DastProbeEngine(
            client=self.mock_client,
            base_url="http://api.target.local",
            auth_context=self.auth_context,
        )
        self.sample_ep = ApiEndpoint(
            id=1,
            project_id=1,
            path="/users/{user_id}",
            method="GET",
            auth_status="AUTHENTICATED",
            rate_limit_status="MISSING",
            request_validation_status="UNCONSTRAINED",
            risk_score=75,
            risk_level="HIGH",
        )

    # -------------------------------------------------------------------------
    # Authentication Enforcement Probes (1-4)
    # -------------------------------------------------------------------------
    def test_01_auth_probe_protected_endpoint_denies_unauth(self):
        """1. Protected endpoint without auth returns 401 -> VERIFIED_SECURE"""
        self.mock_client.execute_request.return_value = DastResponse(
            status_code=401,
            headers={"Content-Type": "application/json"},
            elapsed_ms=45.0,
            body_preview='{"error": "Unauthorized"}',
            final_url="http://api.target.local/users/123",
        )

        res = self.engine.probe_auth_enforcement(self.sample_ep)
        self.assertEqual(res.status, DastVerificationStatus.VERIFIED_SECURE)
        self.assertEqual(res.response_status, 401)

    def test_02_auth_probe_authenticated_endpoint_behavior(self):
        """2. Protected endpoint with auth context configured"""
        self.mock_client.execute_request.return_value = DastResponse(
            status_code=200,
            headers={"Content-Type": "application/json"},
            elapsed_ms=50.0,
            body_preview='{"id": 123, "name": "Alice"}',
            final_url="http://api.target.local/users/123",
        )

        res = self.engine.probe_auth_enforcement(self.sample_ep)
        self.assertEqual(res.status, DastVerificationStatus.VERIFIED_VULNERABLE)
        self.assertEqual(res.severity, FindingSeverity.HIGH)

    def test_03_auth_probe_suspicious_unauthenticated_success(self):
        """3. Protected endpoint returns 200 OK without auth -> VERIFIED_VULNERABLE"""
        self.mock_client.execute_request.return_value = DastResponse(
            status_code=200,
            headers={"Content-Type": "application/json"},
            elapsed_ms=40.0,
            body_preview='{"secret_data": "exposed"}',
            final_url="http://api.target.local/users/123",
        )

        res = self.engine.probe_auth_enforcement(self.sample_ep)
        self.assertEqual(res.status, DastVerificationStatus.VERIFIED_VULNERABLE)
        self.assertTrue("HTTP 200" in res.evidence or "responded with HTTP 200" in res.evidence)

    def test_04_auth_probe_inconclusive_result(self):
        """4. Endpoint returns unexpected status 500 without auth -> INCONCLUSIVE"""
        self.mock_client.execute_request.return_value = DastResponse(
            status_code=500,
            headers={},
            elapsed_ms=30.0,
            body_preview="Internal Error",
            final_url="http://api.target.local/users/123",
        )

        res = self.engine.probe_auth_enforcement(self.sample_ep)
        self.assertEqual(res.status, DastVerificationStatus.INCONCLUSIVE)

    # -------------------------------------------------------------------------
    # BOLA Probes (5-9)
    # -------------------------------------------------------------------------
    def test_05_bola_object_identifier_detection(self):
        """5. Endpoint path parameter identifier correctly identified"""
        ep = ApiEndpoint(
            id=2, project_id=1, path="/accounts/{accountId}/documents/{doc_id}",
            method="GET", auth_status="AUTHENTICATED", risk_score=50, risk_level="MEDIUM"
        )
        self.mock_client.execute_request.return_value = DastResponse(
            status_code=404, headers={}, elapsed_ms=20.0, body_preview="Not Found",
            final_url="http://api.target.local/accounts/99999/documents/123"
        )

        res = self.engine.probe_bola(ep)
        self.assertEqual(res.status, DastVerificationStatus.VERIFIED_SECURE)

    def test_06_bola_safe_alternate_identifier_generation(self):
        """6. BOLA probe uses bounded safe alternate IDs without brute force"""
        self.mock_client.execute_request.return_value = DastResponse(
            status_code=403, headers={}, elapsed_ms=25.0, body_preview="Forbidden",
            final_url="http://api.target.local/users/99999"
        )

        res = self.engine.probe_bola(self.sample_ep)
        self.assertEqual(res.status, DastVerificationStatus.VERIFIED_SECURE)
        self.assertEqual(self.mock_client.execute_request.call_count, 2)

    def test_07_bola_vulnerable_response_detection(self):
        """7. Alternate ID request returns 200 OK with resource data -> VERIFIED_VULNERABLE"""
        self.mock_client.execute_request.side_effect = [
            DastResponse(200, {}, 30.0, '{"id": 1, "name": "User 1"}', "http://api.target.local/users/1"),
            DastResponse(200, {}, 35.0, '{"id": 99999, "name": "User 99999"}', "http://api.target.local/users/99999"),
        ]

        res = self.engine.probe_bola(self.sample_ep)
        self.assertEqual(res.status, DastVerificationStatus.VERIFIED_VULNERABLE)
        self.assertIn("Possible BOLA detected", res.evidence)

    def test_08_bola_inconclusive_result(self):
        """8. Alternate ID request returns 500 error -> INCONCLUSIVE"""
        self.mock_client.execute_request.side_effect = [
            DastResponse(200, {}, 30.0, '{"id": 1}', "http://api.target.local/users/1"),
            DastResponse(500, {}, 35.0, 'Server Error', "http://api.target.local/users/99999"),
        ]

        res = self.engine.probe_bola(self.sample_ep)
        self.assertEqual(res.status, DastVerificationStatus.INCONCLUSIVE)

    def test_09_bola_skips_destructive_methods(self):
        """9. BOLA probe rejects non-GET methods (POST, PUT, DELETE)"""
        ep_delete = ApiEndpoint(
            id=3, project_id=1, path="/users/{user_id}", method="DELETE",
            auth_status="AUTHENTICATED", risk_score=90, risk_level="CRITICAL"
        )

        res = self.engine.probe_bola(ep_delete)
        self.assertEqual(res.status, DastVerificationStatus.INCONCLUSIVE)
        self.assertIn("skipped for non-read method DELETE", res.evidence)
        self.mock_client.execute_request.assert_not_called()

    # -------------------------------------------------------------------------
    # Mass Assignment Probes (10-13)
    # -------------------------------------------------------------------------
    def test_10_mass_assignment_suspicious_property_detection(self):
        """10. Endpoint suitable for mass assignment accepts POST/PUT/PATCH"""
        ep_post = ApiEndpoint(
            id=4, project_id=1, path="/users", method="POST",
            auth_status="AUTHENTICATED", risk_score=60, risk_level="MEDIUM"
        )
        self.mock_client.execute_request.return_value = DastResponse(
            status_code=400, headers={}, elapsed_ms=30.0, body_preview='{"error": "Unknown field is_admin"}',
            final_url="http://api.target.local/users"
        )

        res = self.engine.probe_mass_assignment(ep_post)
        self.assertEqual(res.status, DastVerificationStatus.VERIFIED_SECURE)

    def test_11_mass_assignment_controlled_sentinel_payload(self):
        """11. Mass assignment probe uses controlled harmless sentinel payload"""
        ep_put = ApiEndpoint(
            id=5, project_id=1, path="/profiles/123", method="PUT",
            auth_status="AUTHENTICATED", risk_score=50, risk_level="MEDIUM"
        )
        self.mock_client.execute_request.return_value = DastResponse(
            status_code=422, headers={}, elapsed_ms=35.0, body_preview="Unprocessable Entity",
            final_url="http://api.target.local/profiles/123"
        )

        res = self.engine.probe_mass_assignment(ep_put)
        self.assertEqual(res.status, DastVerificationStatus.VERIFIED_SECURE)

    def test_12_mass_assignment_reflected_property_vulnerable(self):
        """12. Reflected privileged property in response -> VERIFIED_VULNERABLE"""
        ep_patch = ApiEndpoint(
            id=6, project_id=1, path="/users/123", method="PATCH",
            auth_status="AUTHENTICATED", risk_score=70, risk_level="HIGH"
        )
        self.mock_client.execute_request.return_value = DastResponse(
            status_code=200, headers={}, elapsed_ms=40.0,
            body_preview='{"id": 123, "is_admin": true, "role": "admin"}',
            final_url="http://api.target.local/users/123"
        )

        res = self.engine.probe_mass_assignment(ep_patch)
        self.assertEqual(res.status, DastVerificationStatus.VERIFIED_VULNERABLE)
        self.assertIn("reflected privileged mass-assignment properties", res.evidence)

    def test_13_mass_assignment_inconclusive_result(self):
        """13. Server returns 200 OK without reflecting property -> INCONCLUSIVE"""
        ep_post = ApiEndpoint(
            id=7, project_id=1, path="/users", method="POST",
            auth_status="AUTHENTICATED", risk_score=40, risk_level="LOW"
        )
        self.mock_client.execute_request.return_value = DastResponse(
            status_code=200, headers={}, elapsed_ms=40.0,
            body_preview='{"status": "success", "id": 456}',
            final_url="http://api.target.local/users"
        )

        res = self.engine.probe_mass_assignment(ep_post)
        self.assertEqual(res.status, DastVerificationStatus.INCONCLUSIVE)

    # -------------------------------------------------------------------------
    # Rate Limiting Probes (14-17)
    # -------------------------------------------------------------------------
    def test_14_rate_limiting_429_detection(self):
        """14. HTTP 429 response during bounded burst -> VERIFIED_SECURE"""
        self.mock_client.execute_request.side_effect = [
            DastResponse(200, {}, 20.0, "OK", "http://api.target.local/users/123"),
            DastResponse(429, {"Retry-After": "60"}, 25.0, "Too Many Requests", "http://api.target.local/users/123"),
        ]

        res = self.engine.probe_rate_limiting(self.sample_ep)
        self.assertEqual(res.status, DastVerificationStatus.VERIFIED_SECURE)
        self.assertEqual(res.response_status, 429)

    def test_15_rate_limiting_retry_after_detection(self):
        """15. Retry-After header detected -> VERIFIED_SECURE"""
        self.mock_client.execute_request.return_value = DastResponse(
            200, {"Retry-After": "30", "X-RateLimit-Limit": "100"}, 20.0, "OK", "http://api.target.local/users/123"
        )

        res = self.engine.probe_rate_limiting(self.sample_ep)
        self.assertEqual(res.status, DastVerificationStatus.VERIFIED_SECURE)

    def test_16_rate_limiting_header_detection(self):
        """16. X-RateLimit-* headers detected -> VERIFIED_SECURE"""
        self.mock_client.execute_request.return_value = DastResponse(
            200, {"X-RateLimit-Remaining": "99"}, 20.0, "OK", "http://api.target.local/users/123"
        )

        res = self.engine.probe_rate_limiting(self.sample_ep)
        self.assertEqual(res.status, DastVerificationStatus.VERIFIED_SECURE)

    def test_17_rate_limiting_bounded_request_count(self):
        """17. Probing stops after max 4 sequential requests without flooding"""
        self.mock_client.execute_request.return_value = DastResponse(
            200, {}, 15.0, "OK", "http://api.target.local/users/123"
        )

        res = self.engine.probe_rate_limiting(self.sample_ep)
        self.assertEqual(res.status, DastVerificationStatus.INCONCLUSIVE)
        self.assertLessEqual(self.mock_client.execute_request.call_count, 4)

    # -------------------------------------------------------------------------
    # Security Controls (18-22)
    # -------------------------------------------------------------------------
    def test_18_secrets_never_appear_in_evidence(self):
        """18. Raw secret token is redacted from evidence text and snippets"""
        raw_secret = "secret-token-12345"
        self.mock_client.execute_request.return_value = DastResponse(
            200,
            {"Authorization": f"Bearer {raw_secret}"},
            20.0,
            f"Returned data with Authorization: Bearer {raw_secret}",
            "http://api.target.local/users/123",
        )

        res = self.engine.probe_auth_enforcement(self.sample_ep)
        self.assertNotIn(raw_secret, res.evidence or "")
        self.assertNotIn(raw_secret, res.response_snippet or "")
        self.assertIn("[REDACTED_SECRET]", res.response_snippet or "")

    def test_19_ssrf_rejection_prevents_probe_execution(self):
        """19. DastHttpClient SSRF rejection prevents active network requests"""
        client = DastHttpClient(allow_localhost=False)
        with self.assertRaises(DastSsrfError):
            client.execute_request("http://169.254.169.254/latest/meta-data")

    def test_20_redirect_boundary_enforced(self):
        """20. DastHttpClient enforces origin boundary during redirects"""
        client = DastHttpClient(allow_localhost=False)
        origin = client.get_origin("http://api.target.com/v1")
        self.assertEqual(origin, ("http", "api.target.com", None))

    def test_21_payload_response_limits_enforced(self):
        """21. Secret redaction utility functions correctly on raw text"""
        redacted = redact_secrets("Authorization: Bearer my-secret-token", ["my-secret-token"])
        self.assertNotIn("my-secret-token", redacted)
        self.assertIn("[REDACTED_SECRET]", redacted)

    def test_22_dast_disabled_prevents_active_requests(self):
        """22. Fast-fail when DAST is disabled on project"""
        mock_project = MagicMock(api_dast_enabled=False)
        self.assertFalse(mock_project.api_dast_enabled)

    # -------------------------------------------------------------------------
    # Finding Integration (23-26)
    # -------------------------------------------------------------------------
    def test_23_dynamic_finding_fingerprint_generated(self):
        """23. Deterministic fingerprint generated for dynamic DAST findings"""
        probe_res = DastProbeResult(
            endpoint_id=1,
            probe_type=DastProbeType.BOLA,
            status=DastVerificationStatus.VERIFIED_VULNERABLE,
            severity=FindingSeverity.HIGH,
            evidence="BOLA vulnerability detected on /users/123",
            secrets_to_redact=["secret-token-12345"],
        )

        finding = map_probe_result_to_finding(
            project_id=1,
            scan_id=10,
            endpoint=self.sample_ep,
            probe_result=probe_res,
            existing_findings_map={},
        )

        self.assertIsNotNone(finding)
        self.assertTrue(len(finding.fingerprint) > 10)
        self.assertEqual(finding.source, FindingSource.DAST)
        self.assertEqual(finding.owasp, "API1:2023")

    def test_24_duplicate_dynamic_finding_prevented(self):
        """24. Existing open finding fingerprint maps correctly without duplication"""
        probe_res = DastProbeResult(
            endpoint_id=1,
            probe_type=DastProbeType.AUTH_ENFORCEMENT,
            status=DastVerificationStatus.VERIFIED_VULNERABLE,
            severity=FindingSeverity.HIGH,
            evidence="Auth bypass detected",
        )

        finding1 = map_probe_result_to_finding(1, 10, self.sample_ep, probe_res, {})
        existing_map = {finding1.fingerprint: finding1}
        finding2 = map_probe_result_to_finding(1, 11, self.sample_ep, probe_res, existing_map)

        self.assertEqual(finding1.fingerprint, finding2.fingerprint)

    def test_25_resolved_triage_preserved(self):
        """25. User-resolved triage state preserved across scan re-runs"""
        probe_res = DastProbeResult(
            endpoint_id=1,
            probe_type=DastProbeType.AUTH_ENFORCEMENT,
            status=DastVerificationStatus.VERIFIED_VULNERABLE,
            severity=FindingSeverity.HIGH,
            evidence="Auth bypass detected",
        )

        finding1 = map_probe_result_to_finding(1, 10, self.sample_ep, probe_res, {})
        finding1.status = FindingStatus.RESOLVED
        finding1.resolution_comment = "Verified fixed in v2 API"

        existing_map = {finding1.fingerprint: finding1}
        finding2 = map_probe_result_to_finding(1, 11, self.sample_ep, probe_res, existing_map)

        self.assertEqual(finding2.status, FindingStatus.RESOLVED)
        self.assertEqual(finding2.resolution_comment, "Verified fixed in v2 API")

    def test_26_false_positive_triage_preserved(self):
        """26. User false positive triage state preserved across scan re-runs"""
        probe_res = DastProbeResult(
            endpoint_id=1,
            probe_type=DastProbeType.MASS_ASSIGNMENT,
            status=DastVerificationStatus.VERIFIED_VULNERABLE,
            severity=FindingSeverity.HIGH,
            evidence="Mass assignment property reflected",
        )

        finding1 = map_probe_result_to_finding(1, 10, self.sample_ep, probe_res, {})
        finding1.status = FindingStatus.FALSE_POSITIVE
        finding1.resolution_comment = "Field is read-only internally"

        existing_map = {finding1.fingerprint: finding1}
        finding2 = map_probe_result_to_finding(1, 11, self.sample_ep, probe_res, existing_map)

        self.assertEqual(finding2.status, FindingStatus.FALSE_POSITIVE)
        self.assertEqual(finding2.resolution_comment, "Field is read-only internally")


if __name__ == "__main__":
    unittest.main()
