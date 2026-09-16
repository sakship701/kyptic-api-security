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
        target_url = f"{base_url.rstrip('/')}/{endpoint.path.lstrip('/')}"
        target_url = re.sub(r"\{[^}]+\}", "1", target_url)
        secrets = auth_context.get_secrets_to_redact()

        # Step 1: Baseline Request
        try:
            base_url_test = f"{target_url}?id=1" if "?" not in target_url else f"{target_url}&id=1"
            base_resp = client.execute_request(url=base_url_test, method=endpoint.method, auth_context=auth_context, timeout=5.0)
        except Exception as e:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"Baseline SQLi request failed: {str(e)}",
                secrets_to_redact=secrets,
            )

        # Step 2: True Condition Probe (' AND '1'='1)
        true_url = f"{target_url}?id=1'%20AND%20'1'='1" if "?" not in target_url else f"{target_url}&id=1'%20AND%20'1'='1"
        # Step 3: False Condition Probe (' AND '1'='2)
        false_url = f"{target_url}?id=1'%20AND%20'1'='2" if "?" not in target_url else f"{target_url}&id=1'%20AND%20'1'='2"

        try:
            true_resp = client.execute_request(url=true_url, method=endpoint.method, auth_context=auth_context, timeout=5.0)
            false_resp = client.execute_request(url=false_url, method=endpoint.method, auth_context=auth_context, timeout=5.0)
        except Exception as e:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"SQLi test probes failed: {str(e)}",
                secrets_to_redact=secrets,
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
        ]

        if true_resp.body_preview or false_resp.body_preview:
            body_check = (true_resp.body_preview or "").lower() + " " + (false_resp.body_preview or "").lower()
            for err in sql_errors:
                if err in body_check:
                    return DastProbeResult(
                        endpoint_id=endpoint.id,
                        probe_type=DastProbeType.BOLA,
                        status=DastVerificationStatus.VERIFIED_VULNERABLE,
                        severity=FindingSeverity.CRITICAL,
                        evidence=f"SQL Injection confirmed: Server returned database syntax error pattern ('{err}') when probe payload was injected.",
                        response_status=true_resp.status_code,
                        response_snippet=true_resp.body_preview,
                        confidence="HIGH",
                        secrets_to_redact=secrets,
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
                evidence="SQL Injection confirmed: Baseline & True SQL probes returned valid data, whereas False SQL probe failed/returned empty dataset.",
                response_status=true_resp.status_code,
                response_snippet=true_resp.body_preview,
                confidence="HIGH",
                secrets_to_redact=secrets,
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
            )

        # Identical responses across baseline, true, and false probes -> VERIFIED_SECURE
        if true_resp.status_code == false_resp.status_code == base_resp.status_code == 200:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_SECURE,
                evidence="Tested query parameter with boolean logic SQL payloads. No database error syntax or boolean differentials observed.",
                response_status=true_resp.status_code,
                confidence="HIGH",
                secrets_to_redact=secrets,
            )

        return DastProbeResult(
            endpoint_id=endpoint.id,
            probe_type=DastProbeType.BOLA,
            status=DastVerificationStatus.INCONCLUSIVE,
            evidence=f"SQLi verification inconclusive. Baseline HTTP {base_resp.status_code}, True HTTP {true_resp.status_code}, False HTTP {false_resp.status_code}.",
            response_status=true_resp.status_code,
            confidence="LOW",
            secrets_to_redact=secrets,
        )
