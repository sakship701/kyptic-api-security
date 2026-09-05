import json
import re
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from app.models.api_endpoint import ApiEndpoint
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.services.dast_http_client import (
    DastAuthContext,
    DastHttpClient,
    DastResponse,
    redact_secrets,
    sanitize_headers,
)
from app.services.finding_normalizer import generate_fingerprint


class DastVerificationStatus(str, Enum):
    UNTESTED = "UNTESTED"
    VERIFIED_SECURE = "VERIFIED_SECURE"
    VERIFIED_VULNERABLE = "VERIFIED_VULNERABLE"
    INCONCLUSIVE = "INCONCLUSIVE"


class DastProbeType(str, Enum):
    AUTH_ENFORCEMENT = "AUTH_ENFORCEMENT"
    BOLA = "BOLA"
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"
    RATE_LIMITING = "RATE_LIMITING"


OBJECT_ID_PARAM_PATTERNS = [
    r"^(?:user|account|order|document|profile|customer|resource|item|patient|transaction|file)_?id$",
    r"^id$",
    r"^uuid$",
    r"^guid$",
    r".*Id$",
    r".*_id$",
]

SUSPICIOUS_MASS_ASSIGNMENT_PROPERTIES = {
    "is_admin": True,
    "admin": True,
    "role": "admin",
    "roles": ["admin"],
    "permissions": ["admin", "all"],
    "account_status": "active",
    "status": "active",
    "balance": 999999,
    "credit_limit": 999999,
    "verified": True,
    "is_verified": True,
    "owner_id": 1,
    "ownerId": 1,
    "user_type": "admin",
    "privilege": "admin",
    "internal": True,
    "system": True,
    "created_by": 1,
}


class DastProbeResult:
    def __init__(
        self,
        endpoint_id: int,
        probe_type: DastProbeType,
        status: DastVerificationStatus,
        severity: FindingSeverity = FindingSeverity.INFO,
        evidence: Optional[str] = None,
        response_status: Optional[int] = None,
        response_headers: Optional[Dict[str, str]] = None,
        response_snippet: Optional[str] = None,
        confidence: str = "LOW",
        secrets_to_redact: Optional[List[str]] = None,
    ):
        self.endpoint_id = endpoint_id
        self.probe_type = probe_type
        self.status = status
        self.severity = severity
        self.secrets_to_redact = secrets_to_redact or []
        self.evidence = redact_secrets(evidence, self.secrets_to_redact) if evidence else None
        self.response_status = response_status
        self.response_headers = sanitize_headers(response_headers or {})
        self.response_snippet = redact_secrets(response_snippet[:500], self.secrets_to_redact) if response_snippet else None
        self.confidence = confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint_id": self.endpoint_id,
            "probe_type": self.probe_type.value,
            "status": self.status.value,
            "severity": self.severity.value if isinstance(self.severity, FindingSeverity) else str(self.severity),
            "evidence": self.evidence,
            "response_status": self.response_status,
            "response_headers": self.response_headers,
            "response_snippet": self.response_snippet,
            "confidence": self.confidence,
        }


class DastProbeEngine:
    def __init__(
        self,
        client: DastHttpClient,
        base_url: str,
        auth_context: Optional[DastAuthContext] = None,
    ):
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.auth_context = auth_context or DastAuthContext(auth_type="NONE")
        self.secrets = self.auth_context.get_secrets_to_redact()

    def _build_full_url(self, path: str, path_params: Optional[Dict[str, str]] = None) -> str:
        formatted_path = path
        if path_params:
            for k, v in path_params.items():
                formatted_path = formatted_path.replace(f"{{{k}}}", str(v))
        return f"{self.base_url}/{formatted_path.lstrip('/')}"

    # -------------------------------------------------------------------------
    # PHASE 2A — API2 AUTHENTICATION ENFORCEMENT
    # -------------------------------------------------------------------------
    def probe_auth_enforcement(self, endpoint: ApiEndpoint) -> DastProbeResult:
        # Check if endpoint appears to require authentication according to OpenAPI spec / static scan
        is_protected_static = endpoint.auth_status in ("AUTHENTICATED", "PROTECTED", "REQUIRED")
        
        # Test 1: Send request WITHOUT authentication
        unauth_url = self._build_full_url(endpoint.path)
        # Substitute sample path variables if any exist
        unauth_url = re.sub(r"\{[^}]+\}", "123", unauth_url)

        try:
            unauth_resp = self.client.execute_request(
                url=unauth_url,
                method=endpoint.method,
                auth_context=DastAuthContext(auth_type="NONE"),
                timeout=5.0,
            )
        except Exception as e:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.AUTH_ENFORCEMENT,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"Request without authentication failed: {str(e)}",
                confidence="LOW",
                secrets_to_redact=self.secrets,
            )

        # If static analysis didn't mark it protected, and unauthenticated returned 2xx/401/403:
        if not is_protected_static:
            if unauth_resp.status_code in (401, 403):
                return DastProbeResult(
                    endpoint_id=endpoint.id,
                    probe_type=DastProbeType.AUTH_ENFORCEMENT,
                    status=DastVerificationStatus.VERIFIED_SECURE,
                    evidence=f"Endpoint static status was '{endpoint.auth_status}', but active probe returned HTTP {unauth_resp.status_code} when accessed without auth.",
                    response_status=unauth_resp.status_code,
                    response_headers=unauth_resp.headers,
                    response_snippet=unauth_resp.body_preview,
                    confidence="HIGH",
                    secrets_to_redact=self.secrets,
                )
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.AUTH_ENFORCEMENT,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"Endpoint is documented as unauthenticated. Active request returned HTTP {unauth_resp.status_code}.",
                response_status=unauth_resp.status_code,
                response_headers=unauth_resp.headers,
                response_snippet=unauth_resp.body_preview,
                confidence="LOW",
                secrets_to_redact=self.secrets,
            )

        # Endpoint is marked as requiring authentication.
        if unauth_resp.status_code in (401, 403):
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.AUTH_ENFORCEMENT,
                status=DastVerificationStatus.VERIFIED_SECURE,
                evidence=f"Protected endpoint properly denied unauthenticated access with HTTP {unauth_resp.status_code}.",
                response_status=unauth_resp.status_code,
                response_headers=unauth_resp.headers,
                response_snippet=unauth_resp.body_preview,
                confidence="HIGH",
                secrets_to_redact=self.secrets,
            )

        # Unauthenticated request returned 2xx (Success) to protected endpoint!
        if unauth_resp.status_code and 200 <= unauth_resp.status_code < 300:
            # If configured auth type is set, compare with authenticated request
            if self.auth_context.auth_type != "NONE":
                try:
                    auth_resp = self.client.execute_request(
                        url=unauth_url,
                        method=endpoint.method,
                        auth_context=self.auth_context,
                        timeout=5.0,
                    )
                    # If both unauth and auth succeed with protected data or behave identically
                    evidence_msg = (
                        f"CRITICAL: Endpoint '{endpoint.method} {endpoint.path}' is marked as protected in spec, "
                        f"but responded with HTTP {unauth_resp.status_code} without authentication tokens. "
                        f"Authenticated response status: HTTP {auth_resp.status_code}."
                    )
                    return DastProbeResult(
                        endpoint_id=endpoint.id,
                        probe_type=DastProbeType.AUTH_ENFORCEMENT,
                        status=DastVerificationStatus.VERIFIED_VULNERABLE,
                        severity=FindingSeverity.HIGH,
                        evidence=evidence_msg,
                        response_status=unauth_resp.status_code,
                        response_headers=unauth_resp.headers,
                        response_snippet=unauth_resp.body_preview,
                        confidence="HIGH",
                        secrets_to_redact=self.secrets,
                    )
                except Exception as e:
                    pass

            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.AUTH_ENFORCEMENT,
                status=DastVerificationStatus.VERIFIED_VULNERABLE,
                severity=FindingSeverity.HIGH,
                evidence=f"Endpoint is documented as requiring authentication, but returned HTTP {unauth_resp.status_code} when called without credentials.",
                response_status=unauth_resp.status_code,
                response_headers=unauth_resp.headers,
                response_snippet=unauth_resp.body_preview,
                confidence="HIGH",
                secrets_to_redact=self.secrets,
            )

        return DastProbeResult(
            endpoint_id=endpoint.id,
            probe_type=DastProbeType.AUTH_ENFORCEMENT,
            status=DastVerificationStatus.INCONCLUSIVE,
            evidence=f"Protected endpoint returned unexpected HTTP status {unauth_resp.status_code} without auth.",
            response_status=unauth_resp.status_code,
            response_headers=unauth_resp.headers,
            response_snippet=unauth_resp.body_preview,
            confidence="LOW",
            secrets_to_redact=self.secrets,
        )

    # -------------------------------------------------------------------------
    # PHASE 2B — API1 BOLA
    # -------------------------------------------------------------------------
    def probe_bola(self, endpoint: ApiEndpoint) -> DastProbeResult:
        # BOLA probing must be NON-DESTRUCTIVE: read-only GET/HEAD methods only
        if endpoint.method.upper() not in ("GET", "HEAD"):
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"BOLA active probing skipped for non-read method {endpoint.method}. Only GET/HEAD are probed.",
                confidence="LOW",
                secrets_to_redact=self.secrets,
            )

        # Identify path parameter that looks like an object identifier
        path_params = re.findall(r"\{([^}]+)\}", endpoint.path)
        if not path_params:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence="No object identifier path parameters found in endpoint route.",
                confidence="LOW",
                secrets_to_redact=self.secrets,
            )

        target_param = None
        for param in path_params:
            for pattern in OBJECT_ID_PARAM_PATTERNS:
                if re.match(pattern, param, re.IGNORECASE):
                    target_param = param
                    break
            if target_param:
                break

        if not target_param:
            target_param = path_params[0]  # Fallback to first path parameter

        # Generate 2 safe alternate object identifiers for bounded read testing
        original_id = "1"
        alt_ids = ["99999", "10000000000000000000"]

        # Step 1: Send request with baseline/original ID
        baseline_url = self._build_full_url(endpoint.path, {target_param: original_id})
        try:
            baseline_resp = self.client.execute_request(
                url=baseline_url,
                method=endpoint.method,
                auth_context=self.auth_context,
                timeout=5.0,
            )
        except Exception as e:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"Baseline request to {baseline_url} failed: {str(e)}",
                confidence="LOW",
                secrets_to_redact=self.secrets,
            )

        # Step 2: Send bounded request with safe alternate ID
        alt_url = self._build_full_url(endpoint.path, {target_param: alt_ids[0]})
        try:
            alt_resp = self.client.execute_request(
                url=alt_url,
                method=endpoint.method,
                auth_context=self.auth_context,
                timeout=5.0,
            )
        except Exception as e:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"Alternate ID request to {alt_url} failed: {str(e)}",
                confidence="LOW",
                secrets_to_redact=self.secrets,
            )

        # Behavior evaluation
        # If alternate ID returns 403 or 404 cleanly without exposing unauthorized resources
        if alt_resp.status_code in (403, 404):
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_SECURE,
                evidence=f"Alternate resource request with ID '{alt_ids[0]}' correctly yielded HTTP {alt_resp.status_code}.",
                response_status=alt_resp.status_code,
                response_headers=alt_resp.headers,
                response_snippet=alt_resp.body_preview,
                confidence="HIGH",
                secrets_to_redact=self.secrets,
            )

        # If alternate ID returns 200 with object data identical or successfully accessible
        if alt_resp.status_code and 200 <= alt_resp.status_code < 300:
            if baseline_resp.status_code and 200 <= baseline_resp.status_code < 300:
                evidence_msg = (
                    f"Possible BOLA detected: Endpoint '{endpoint.method} {endpoint.path}' granted 200 OK access "
                    f"for alternate object identifier '{alt_ids[0]}' under the current auth context."
                )
                return DastProbeResult(
                    endpoint_id=endpoint.id,
                    probe_type=DastProbeType.BOLA,
                    status=DastVerificationStatus.VERIFIED_VULNERABLE,
                    severity=FindingSeverity.HIGH,
                    evidence=evidence_msg,
                    response_status=alt_resp.status_code,
                    response_headers=alt_resp.headers,
                    response_snippet=alt_resp.body_preview,
                    confidence="HIGH",
                    secrets_to_redact=self.secrets,
                )

        return DastProbeResult(
            endpoint_id=endpoint.id,
            probe_type=DastProbeType.BOLA,
            status=DastVerificationStatus.INCONCLUSIVE,
            evidence=f"Alternate resource ID returned HTTP {alt_resp.status_code}. Unable to conclusively establish authorization failure.",
            response_status=alt_resp.status_code,
            response_headers=alt_resp.headers,
            response_snippet=alt_resp.body_preview,
            confidence="LOW",
            secrets_to_redact=self.secrets,
        )

    # -------------------------------------------------------------------------
    # PHASE 2C — API6 MASS ASSIGNMENT
    # -------------------------------------------------------------------------
    def probe_mass_assignment(self, endpoint: ApiEndpoint) -> DastProbeResult:
        # Mass assignment probes apply to POST, PUT, PATCH methods
        if endpoint.method.upper() not in ("POST", "PUT", "PATCH"):
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.MASS_ASSIGNMENT,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"Mass assignment probe skipped for HTTP method '{endpoint.method}'. Only POST/PUT/PATCH are probed.",
                confidence="LOW",
                secrets_to_redact=self.secrets,
            )

        # Build sentinel payload with harmless privileged properties
        sentinel_payload = {
            "name": "kyptic_test_sentinel",
            "is_admin": True,
            "role": "admin",
            "account_status": "active",
        }
        json_body = json.dumps(sentinel_payload)

        url = self._build_full_url(endpoint.path)
        url = re.sub(r"\{[^}]+\}", "123", url)

        try:
            resp = self.client.execute_request(
                url=url,
                method=endpoint.method,
                headers={"Content-Type": "application/json"},
                body=json_body,
                auth_context=self.auth_context,
                timeout=5.0,
            )
        except Exception as e:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.MASS_ASSIGNMENT,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"Sentinel request failed: {str(e)}",
                confidence="LOW",
                secrets_to_redact=self.secrets,
            )

        # Check response body for reflected sentinel properties
        if resp.status_code and 200 <= resp.status_code < 300:
            if resp.body_preview:
                body_lower = resp.body_preview.lower()
                reflected = [
                    prop for prop in ["is_admin", "role", "account_status"]
                    if prop in body_lower and ("true" in body_lower or "admin" in body_lower or "active" in body_lower)
                ]
                if reflected:
                    return DastProbeResult(
                        endpoint_id=endpoint.id,
                        probe_type=DastProbeType.MASS_ASSIGNMENT,
                        status=DastVerificationStatus.VERIFIED_VULNERABLE,
                        severity=FindingSeverity.HIGH,
                        evidence=f"Endpoint accepted and reflected privileged mass-assignment properties: {', '.join(reflected)} in HTTP {resp.status_code} response.",
                        response_status=resp.status_code,
                        response_headers=resp.headers,
                        response_snippet=resp.body_preview,
                        confidence="HIGH",
                        secrets_to_redact=self.secrets,
                    )

        if resp.status_code in (400, 422, 403):
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.MASS_ASSIGNMENT,
                status=DastVerificationStatus.VERIFIED_SECURE,
                evidence=f"Server properly rejected unauthorized mass assignment sentinel payload with HTTP {resp.status_code}.",
                response_status=resp.status_code,
                response_headers=resp.headers,
                response_snippet=resp.body_preview,
                confidence="HIGH",
                secrets_to_redact=self.secrets,
            )

        return DastProbeResult(
            endpoint_id=endpoint.id,
            probe_type=DastProbeType.MASS_ASSIGNMENT,
            status=DastVerificationStatus.INCONCLUSIVE,
            evidence=f"Server returned HTTP {resp.status_code} for sentinel payload. Could not verify if property binding occurred.",
            response_status=resp.status_code,
            response_headers=resp.headers,
            response_snippet=resp.body_preview,
            confidence="LOW",
            secrets_to_redact=self.secrets,
        )

    # -------------------------------------------------------------------------
    # PHASE 2D — API4 RATE LIMITING
    # -------------------------------------------------------------------------
    def probe_rate_limiting(self, endpoint: ApiEndpoint) -> DastProbeResult:
        # Bounded rate-limiting verification: send at most 3-5 sequential requests
        request_count = 4
        target_url = self._build_full_url(endpoint.path)
        target_url = re.sub(r"\{[^}]+\}", "123", target_url)

        last_resp: Optional[DastResponse] = None
        throttled = False
        rate_limit_headers_detected = False

        for i in range(request_count):
            try:
                resp = self.client.execute_request(
                    url=target_url,
                    method=endpoint.method,
                    auth_context=self.auth_context,
                    timeout=3.0,
                )
                last_resp = resp

                # Inspect headers for rate limiting controls
                headers_lower = {str(k).lower(): str(v) for k, v in resp.headers.items()}
                has_rl_header = any(
                    hk in ("retry-after", "x-ratelimit-limit", "x-ratelimit-remaining", "x-rate-limit-limit", "x-rate-limit-remaining")
                    or hk.startswith("x-ratelimit") or hk.startswith("x-rate-limit")
                    for hk in headers_lower
                )
                if has_rl_header:
                    rate_limit_headers_detected = True

                # Check HTTP 429 Too Many Requests
                if resp.status_code == 429:
                    throttled = True
                    break  # Stop immediately on throttling
            except Exception as e:
                return DastProbeResult(
                    endpoint_id=endpoint.id,
                    probe_type=DastProbeType.RATE_LIMITING,
                    status=DastVerificationStatus.INCONCLUSIVE,
                    evidence=f"Rate limit verification sequence interrupted: {str(e)}",
                    confidence="LOW",
                    secrets_to_redact=self.secrets,
                )

        if throttled or (last_resp and last_resp.status_code == 429):
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.RATE_LIMITING,
                status=DastVerificationStatus.VERIFIED_SECURE,
                evidence=f"Rate limiting active: Server returned HTTP 429 (Too Many Requests) during bounded request burst.",
                response_status=429,
                response_headers=last_resp.headers if last_resp else {},
                response_snippet=last_resp.body_preview if last_resp else None,
                confidence="HIGH",
                secrets_to_redact=self.secrets,
            )

        if rate_limit_headers_detected:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.RATE_LIMITING,
                status=DastVerificationStatus.VERIFIED_SECURE,
                evidence="Rate limiting headers (e.g. X-RateLimit-* / Retry-After) present in server response.",
                response_status=last_resp.status_code if last_resp else None,
                response_headers=last_resp.headers if last_resp else {},
                response_snippet=last_resp.body_preview if last_resp else None,
                confidence="HIGH",
                secrets_to_redact=self.secrets,
            )

        return DastProbeResult(
            endpoint_id=endpoint.id,
            probe_type=DastProbeType.RATE_LIMITING,
            status=DastVerificationStatus.INCONCLUSIVE,
            evidence=f"No rate-limiting headers or HTTP 429 observed during small {request_count}-request sample.",
            response_status=last_resp.status_code if last_resp else None,
            response_headers=last_resp.headers if last_resp else {},
            response_snippet=last_resp.body_preview if last_resp else None,
            confidence="LOW",
            secrets_to_redact=self.secrets,
        )


REMEDIATION_GUIDANCE = {
    "API1:2023": "Implement explicit object-level access control checks (BOLA) verifying user authorization before accessing resources.",
    "API2:2023": "Enforce valid authentication tokens/headers across all non-public API routes and deny access with HTTP 401/403.",
    "API4:2023": "Enforce rate-limiting policies (HTTP 429 Too Many Requests and X-RateLimit headers) for resource-intensive routes.",
    "API6:2023": "Use strict DTO schema binding and property whitelisting to prevent unauthorized parameter assignment.",
}


def map_probe_result_to_finding(
    project_id: int,
    scan_id: int,
    endpoint: ApiEndpoint,
    probe_result: DastProbeResult,
    existing_findings_map: Dict[str, Finding],
) -> Optional[Finding]:
    """
    Converts a VERIFIED_VULNERABLE DastProbeResult into a Finding model.
    Correlates with existing static findings and preserves RESOLVED / FALSE_POSITIVE triage states.
    """
    if probe_result.status != DastVerificationStatus.VERIFIED_VULNERABLE:
        return None

    probe_mapping = {
        DastProbeType.AUTH_ENFORCEMENT: ("API2:2023", "Broken Authentication", "CWE-306"),
        DastProbeType.BOLA: ("API1:2023", "Broken Object Level Authorization (BOLA)", "CWE-639"),
        DastProbeType.MASS_ASSIGNMENT: ("API6:2023", "Unrestricted Mass Assignment", "CWE-915"),
        DastProbeType.RATE_LIMITING: ("API4:2023", "Unrestricted Resource Consumption", "CWE-770"),
    }

    owasp_cat, title_suffix, cwe_id = probe_mapping.get(
        probe_result.probe_type,
        ("API-SECURITY", "Dynamic Security Vulnerability", "CWE-200")
    )

    rule_id = f"dast-active-{probe_result.probe_type.value.lower()}"
    title = f"Dynamic Verification: {title_suffix} on {endpoint.method} {endpoint.path}"
    file_path = f"API:{endpoint.method}:{endpoint.path}"
    remediation = REMEDIATION_GUIDANCE.get(owasp_cat, "Review API endpoint access controls and input validation.")

    message = f"{probe_result.evidence or title}\n\nRemediation:\n{remediation}"

    fingerprint = generate_fingerprint(
        project_id=project_id,
        scanner_name="dast-active-probe",
        rule_id=rule_id,
        file_path=file_path,
        line_number=None,
        message=title,
    )

    # 1. Check exact fingerprint match or static correlation match
    existing = existing_findings_map.get(fingerprint)
    if not existing:
        # Check for correlated static finding (same route and OWASP category)
        for ef in existing_findings_map.values():
            if ef.file_path == file_path and (ef.owasp == owasp_cat or ef.category == owasp_cat):
                existing = ef
                break

    # Determine status preserving user triage
    target_status = FindingStatus.OPEN
    resolution_comment = None
    resolved_at = None

    if existing:
        fingerprint = existing.fingerprint or fingerprint
        if existing.status in (FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE):
            target_status = existing.status
            resolution_comment = existing.resolution_comment
            resolved_at = existing.resolved_at

    headers_str = json.dumps(probe_result.response_headers) if probe_result.response_headers else "{}"
    evidence_snippet = (
        f"Endpoint: {endpoint.method} {endpoint.path}\n"
        f"Verification Status: {probe_result.status.value}\n"
        f"Response Status: HTTP {probe_result.response_status}\n"
        f"Response Headers: {headers_str}\n"
    )
    if probe_result.response_snippet:
        evidence_snippet += f"Response Snippet: {probe_result.response_snippet}\n"

    return Finding(
        project_id=project_id,
        scan_id=scan_id,
        title=title,
        description=redact_secrets(message, probe_result.secrets_to_redact),
        severity=probe_result.severity,
        cvss=8.0,
        category=owasp_cat,
        file_path=file_path,
        line_number=None,
        status=target_status,
        source=FindingSource.DAST,
        rule_id=rule_id,
        cwe=cwe_id,
        owasp=owasp_cat,
        code_snippet=redact_secrets(evidence_snippet, probe_result.secrets_to_redact),
        scanner_name="dast-active-probe",
        scanner_version="1.0.0",
        fingerprint=fingerprint,
        resolution_comment=resolution_comment,
        resolved_at=resolved_at,
    )
