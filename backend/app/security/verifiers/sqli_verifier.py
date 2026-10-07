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
        explicit database syntax error detection and baseline-aligned boolean logic comparison
        (supporting both AND-conjunction and quote-breakout OR-tautology probes).
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

        # Step 2: AND-based Boolean Probes (<test_val>' AND '1'='1 vs <test_val>' AND '1'='2)
        true_and_url = build_url(f"{test_val}' AND '1'='1")
        false_and_url = build_url(f"{test_val}' AND '1'='2")

        # Step 3: Quote-Breakout OR-Tautology Probes (' OR '1'='1 vs ' OR '1'='2)
        true_or_url = build_url("' OR '1'='1")
        false_or_url = build_url("' OR '1'='2")

        try:
            true_and_resp = client.execute_request(url=true_and_url, method=endpoint.method, auth_context=auth_context, timeout=5.0)
            record_response(true_and_resp)

            false_and_resp = client.execute_request(url=false_and_url, method=endpoint.method, auth_context=auth_context, timeout=5.0)
            record_response(false_and_resp)

            true_or_resp = client.execute_request(url=true_or_url, method=endpoint.method, auth_context=auth_context, timeout=5.0)
            record_response(true_or_resp)

            false_or_resp = client.execute_request(url=false_or_url, method=endpoint.method, auth_context=auth_context, timeout=5.0)
            record_response(false_or_resp)
        except Exception as e:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"SQLi test probes failed: {str(e)}",
                secrets_to_redact=secrets,
                requests_attempted=len(responses_observed) or 5,
                responses_observed=responses_observed,
            )

        # Explicit SQL database syntax error pattern matching across all observed responses
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

        all_previews = [r.get("body_snippet") or "" for r in responses_observed]
        combined_body_check = " ".join(all_previews).lower()
        for err in sql_errors:
            if err in combined_body_check:
                return DastProbeResult(
                    endpoint_id=endpoint.id,
                    probe_type=DastProbeType.BOLA,
                    status=DastVerificationStatus.VERIFIED_VULNERABLE,
                    severity=FindingSeverity.CRITICAL,
                    evidence=f"SQL Injection confirmed: Server returned database syntax error pattern ('{err}') when probe payload was injected into parameter '{param_name}'.",
                    response_status=true_and_resp.status_code,
                    response_snippet=true_and_resp.body_preview,
                    confidence="HIGH",
                    secrets_to_redact=secrets,
                    requests_attempted=len(responses_observed),
                    responses_observed=responses_observed,
                )

        # Helper to check if body snippet represents an empty dataset/record set
        def is_empty_body(body: Optional[str]) -> bool:
            b = (body or "").strip()
            return b in ("[]", "{}", "null", "")

        base_is_empty = is_empty_body(base_resp.body_preview)
        true_and_is_empty = is_empty_body(true_and_resp.body_preview)
        false_and_is_empty = is_empty_body(false_and_resp.body_preview)
        true_or_is_empty = is_empty_body(true_or_resp.body_preview)
        false_or_is_empty = is_empty_body(false_or_resp.body_preview)

        # Check 1: AND-based Boolean Differential
        # True AND probe matches non-empty baseline or valid data, while False AND probe fails or yields empty dataset
        if (true_and_resp.status_code == base_resp.status_code == 200) and (
            false_and_resp.status_code in (404, 400) or (not true_and_is_empty and false_and_is_empty)
        ):
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_VULNERABLE,
                severity=FindingSeverity.CRITICAL,
                evidence=f"SQL Injection confirmed: Baseline & True SQL AND probes returned valid data on parameter '{param_name}', whereas False SQL AND probe returned empty dataset or failed.",
                response_status=true_and_resp.status_code,
                response_snippet=true_and_resp.body_preview,
                confidence="HIGH",
                secrets_to_redact=secrets,
                requests_attempted=len(responses_observed),
                responses_observed=responses_observed,
            )

        # Check 2: OR-Tautology Boolean Differential
        # Tautology True probe (' OR '1'='1) returns valid data (HTTP 200, non-empty), whereas Tautology False probe (' OR '1'='2) returns empty dataset or status 400/404
        if (true_or_resp.status_code == 200 and not true_or_is_empty) and (
            false_or_resp.status_code in (404, 400) or false_or_is_empty
        ):
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_VULNERABLE,
                severity=FindingSeverity.CRITICAL,
                evidence=f"SQL Injection confirmed: Quote-breakout tautology probe (' OR '1'='1) returned valid records on parameter '{param_name}', whereas False tautology probe (' OR '1'='2) returned empty dataset.",
                response_status=true_or_resp.status_code,
                response_snippet=true_or_resp.body_preview,
                confidence="HIGH",
                secrets_to_redact=secrets,
                requests_attempted=len(responses_observed),
                responses_observed=responses_observed,
            )

        # Generic HTTP 500 status without database error signature -> INCONCLUSIVE
        if any(r.status_code == 500 for r in [true_and_resp, false_and_resp, true_or_resp, false_or_resp]):
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"SQLi verification inconclusive. Server returned generic HTTP 500 status without explicit database syntax error signature.",
                response_status=true_and_resp.status_code,
                confidence="LOW",
                secrets_to_redact=secrets,
                requests_attempted=len(responses_observed),
                responses_observed=responses_observed,
            )

        # All probes executed cleanly with HTTP 200 and no boolean logic differentials or syntax errors -> VERIFIED_SECURE
        if all(r.status_code == 200 for r in [base_resp, true_and_resp, false_and_resp, true_or_resp, false_or_resp]):
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_SECURE,
                evidence=f"Tested query parameter '{param_name}' with boolean logic SQL probes. No database error syntax or boolean differentials observed.",
                response_status=true_and_resp.status_code,
                confidence="HIGH",
                secrets_to_redact=secrets,
                requests_attempted=len(responses_observed),
                responses_observed=responses_observed,
            )

        return DastProbeResult(
            endpoint_id=endpoint.id,
            probe_type=DastProbeType.BOLA,
            status=DastVerificationStatus.INCONCLUSIVE,
            evidence=f"SQLi verification inconclusive on parameter '{param_name}'. Probes produced inconsistent HTTP response statuses.",
            response_status=true_and_resp.status_code,
            confidence="LOW",
            secrets_to_redact=secrets,
            requests_attempted=len(responses_observed),
            responses_observed=responses_observed,
        )
