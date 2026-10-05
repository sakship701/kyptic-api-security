import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional

from app.models.api_endpoint import ApiEndpoint
from app.models.finding import FindingSeverity
from app.security.base_verifier import BaseVulnerabilityVerifier
from app.services.dast_http_client import DastAuthContext, DastHttpClient, DastResponse
from app.services.dast_probes import DastProbeResult, DastVerificationStatus, DastProbeType


class SqlInjectionVerifier(BaseVulnerabilityVerifier):
    @property
    def vulnerability_id(self) -> str:
        return "SQL_INJECTION"

    @property
    def display_name(self) -> str:
        return "SQL Injection"

    def verify(
        self,
        endpoint: ApiEndpoint,
        client: DastHttpClient,
        base_url: str,
        auth_context: DastAuthContext,
        params: Optional[Dict[str, Any]] = None,
    ) -> DastProbeResult:
        """
        Executes controlled, non-destructive SQL Injection verification via
        explicit database syntax error detection and baseline-aligned boolean logic comparison.
        Does NOT rely solely on response length differences or generic HTTP 500 status codes.
        """
        param_name = (params.get("parameter") if params else None) or "id"
        test_val = (params.get("test_value") if params else None) or "1"

        target_url = f"{base_url.rstrip('/')}/{endpoint.path.lstrip('/')}"
        target_url = re.sub(r"\{[^}]+\}", "1", target_url)
        secrets = auth_context.get_secrets_to_redact()

        responses_observed: List[Dict[str, Any]] = []

        def build_url(val: str) -> str:
            sep = "&" if "?" in target_url else "?"
            encoded_val = urllib.parse.quote(val)
            return f"{target_url}{sep}{param_name}={encoded_val}"

        def record_response(resp: DastResponse):
            responses_observed.append({
                "status_code": resp.status_code,
                "headers": resp.headers,
                "body_snippet": resp.body_preview,
                "final_url": resp.final_url,
            })

        # Step 1: Baseline Request
        try:
            base_url_test = build_url(test_val)
            base_resp = client.execute_request(url=base_url_test, method=endpoint.method, auth_context=auth_context, timeout=5.0)
            record_response(base_resp)
        except Exception as e:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"Baseline SQLi request failed: {str(e)}",
                secrets_to_redact=secrets,
                requests_attempted=len(responses_observed) or 1,
                responses_observed=responses_observed,
            )

        # Step 2: True Condition Probe (<test_val>' AND '1'='1)
        true_url = build_url(f"{test_val}' AND '1'='1")
        # Step 3: False Condition Probe (<test_val>' AND '1'='2)
        false_url = build_url(f"{test_val}' AND '1'='2")

        try:
            true_resp = client.execute_request(url=true_url, method=endpoint.method, auth_context=auth_context, timeout=5.0)
            record_response(true_resp)
            false_resp = client.execute_request(url=false_url, method=endpoint.method, auth_context=auth_context, timeout=5.0)
            record_response(false_resp)
        except Exception as e:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"SQLi test probes failed: {str(e)}",
                secrets_to_redact=secrets,
                requests_attempted=len(responses_observed) or 3,
                responses_observed=responses_observed,
            )

        # Explicit SQL database syntax error pattern matching
        sql_errors = [
            "you have an error in your sql syntax",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "sqlite3.operationalerror",
            "pg_query(): query failed",
            "ora-00933: sql command not properly ended",
            "mysql_fetch_array() expects parameter",
            "syntax error in string constant",
            "unrecognized token",
        ]

        if base_resp.body_preview or true_resp.body_preview or false_resp.body_preview:
            body_check = (
                (base_resp.body_preview or "").lower() + " " +
                (true_resp.body_preview or "").lower() + " " +
                (false_resp.body_preview or "").lower()
            )
            for err in sql_errors:
                if err in body_check:
                    return DastProbeResult(
                        endpoint_id=endpoint.id,
                        probe_type=DastProbeType.BOLA,
                        status=DastVerificationStatus.VERIFIED_VULNERABLE,
                        severity=FindingSeverity.CRITICAL,
                        evidence=f"SQL Injection confirmed: Server returned database syntax error pattern ('{err}') when probe payload was injected into parameter '{param_name}'.",
                        response_status=true_resp.status_code,
                        response_snippet=true_resp.body_preview,
                        confidence="HIGH",
                        secrets_to_redact=secrets,
                        requests_attempted=len(responses_observed),
                        responses_observed=responses_observed,
                    )

        # Baseline vs True vs False Boolean Logic Evaluation
        # True condition must match Baseline status, False condition must produce distinct query outcome (e.g. 404/400 or empty dataset)
        true_body = (true_resp.body_preview or "").strip()
        false_body = (false_resp.body_preview or "").strip()
        base_body = (base_resp.body_preview or "").strip()

        # Check structural data array difference (e.g. true returns records, false returns [])
        true_is_empty = true_body in ("[]", "{}", "null", "")
        false_is_empty = false_body in ("[]", "{}", "null", "")

        if (true_resp.status_code == base_resp.status_code == 200) and (
            false_resp.status_code in (404, 400) or (not true_is_empty and false_is_empty)
        ):
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_VULNERABLE,
                severity=FindingSeverity.CRITICAL,
                evidence=f"SQL Injection confirmed: Baseline & True SQL probes returned valid data on parameter '{param_name}', whereas False SQL probe failed/returned empty dataset.",
                response_status=true_resp.status_code,
                response_snippet=true_resp.body_preview,
                confidence="HIGH",
                secrets_to_redact=secrets,
                requests_attempted=len(responses_observed),
                responses_observed=responses_observed,
            )

        # Generic HTTP 500 without database error pattern is ambiguous -> INCONCLUSIVE
        if true_resp.status_code == 500 or false_resp.status_code == 500:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"SQLi verification inconclusive. Server returned generic HTTP 500 status without explicit database syntax error signature.",
                response_status=true_resp.status_code,
                confidence="LOW",
                secrets_to_redact=secrets,
                requests_attempted=len(responses_observed),
                responses_observed=responses_observed,
            )

        # Identical responses across baseline, true, and false probes -> VERIFIED_SECURE
        if true_resp.status_code == false_resp.status_code == base_resp.status_code == 200:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_SECURE,
                evidence=f"Tested query parameter '{param_name}' with boolean logic SQL payloads. No database error syntax or boolean differentials observed.",
                response_status=true_resp.status_code,
                confidence="HIGH",
                secrets_to_redact=secrets,
                requests_attempted=len(responses_observed),
                responses_observed=responses_observed,
            )

        return DastProbeResult(
            endpoint_id=endpoint.id,
            probe_type=DastProbeType.BOLA,
            status=DastVerificationStatus.INCONCLUSIVE,
            evidence=f"SQLi verification inconclusive on parameter '{param_name}'. Baseline HTTP {base_resp.status_code}, True HTTP {true_resp.status_code}, False HTTP {false_resp.status_code}.",
            response_status=true_resp.status_code,
            confidence="LOW",
            secrets_to_redact=secrets,
            requests_attempted=len(responses_observed),
            responses_observed=responses_observed,
        )
