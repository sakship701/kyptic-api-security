import re
import urllib.parse
from typing import Any, Dict, Optional

from app.models.api_endpoint import ApiEndpoint
from app.models.finding import FindingSeverity
from app.security.base_verifier import BaseVulnerabilityVerifier
from app.services.dast_http_client import DastAuthContext, DastHttpClient
from app.services.dast_probes import DastProbeResult, DastVerificationStatus, DastProbeType


class CommandInjectionVerifier(BaseVulnerabilityVerifier):
    @property
    def vulnerability_id(self) -> str:
        return "COMMAND_INJECTION"

    @property
    def display_name(self) -> str:
        return "OS Command Injection"

    def verify(
        self,
        endpoint: ApiEndpoint,
        client: DastHttpClient,
        base_url: str,
        auth_context: DastAuthContext,
        params: Optional[Dict[str, Any]] = None,
    ) -> DastProbeResult:
        """
        Executes SAFE, non-destructive OS Command Injection verification.
        Distinguishes simple parameter reflection from true expression/command evaluation.
        NEVER executes host subshells, spawns shells, or runs destructive host binaries.
        """
        target_url = f"{base_url.rstrip('/')}/{endpoint.path.lstrip('/')}"
        target_url = re.sub(r"\{[^}]+\}", "1", target_url)
        secrets = auth_context.get_secrets_to_redact()

        # Step 1: Parameter reflection baseline test
        canary_text = "kyptic_cmd_reflect_canary"
        try:
            reflect_resp = client.execute_request(
                url=f"{target_url}?cmd={canary_text}",
                method=endpoint.method,
                auth_context=auth_context,
                timeout=5.0,
            )
        except Exception as e:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"Command injection reflection check failed: {str(e)}",
                secrets_to_redact=secrets,
            )

        # Step 2: Expression evaluation payload e.g. expr 834192 + 1 -> 834193
        expr_payload = "1%3Bexpr%20834192%20%2B%201"
        eval_result = "834193"
        raw_expr_str = "expr 834192 + 1"

        try:
            eval_resp = client.execute_request(
                url=f"{target_url}?cmd={expr_payload}",
                method=endpoint.method,
                auth_context=auth_context,
                timeout=5.0,
            )
        except Exception as e:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"Command injection expression probe failed: {str(e)}",
                secrets_to_redact=secrets,
            )

        body_eval = eval_resp.body_preview or ""

        # Deterministic Execution Evidence: Evaluated sum '834193' is present AND raw payload 'expr 834192 + 1' was NOT sent in body
        if eval_result in body_eval and raw_expr_str not in body_eval:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_VULNERABLE,
                severity=FindingSeverity.CRITICAL,
                evidence=f"OS Command Injection confirmed: Target evaluated shell expression payload and returned computed result '{eval_result}'.",
                response_status=eval_resp.status_code,
                response_snippet=eval_resp.body_preview,
                confidence="HIGH",
                secrets_to_redact=secrets,
            )

        # Parameter Reflection Resistance: If input string was merely reflected verbatim, classify as SECURE / NOT_CONFIRMED
        if canary_text in (reflect_resp.body_preview or "") or raw_expr_str in body_eval:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_SECURE,
                evidence="Input parameter is reflected as plain text parameter data. No OS command or expression evaluation observed.",
                response_status=eval_resp.status_code,
                confidence="HIGH",
                secrets_to_redact=secrets,
            )

        return DastProbeResult(
            endpoint_id=endpoint.id,
            probe_type=DastProbeType.BOLA,
            status=DastVerificationStatus.INCONCLUSIVE,
            evidence=f"Command injection verification returned HTTP {eval_resp.status_code}. Unable to confirm command execution.",
            response_status=eval_resp.status_code,
            confidence="LOW",
            secrets_to_redact=secrets,
        )


class XssVerifier(BaseVulnerabilityVerifier):
    @property
    def vulnerability_id(self) -> str:
        return "XSS"

    @property
    def display_name(self) -> str:
        return "Cross-Site Scripting (XSS)"

    def verify(
        self,
        endpoint: ApiEndpoint,
        client: DastHttpClient,
        base_url: str,
        auth_context: DastAuthContext,
        params: Optional[Dict[str, Any]] = None,
    ) -> DastProbeResult:
        """
        Executes safe reflected XSS verification using executable context tag analysis.
        Distinguishes plain text data reflection, JSON responses, and HTML entity encoding from executable tag reflection.
        """
        target_url = f"{base_url.rstrip('/')}/{endpoint.path.lstrip('/')}"
        target_url = re.sub(r"\{[^}]+\}", "1", target_url)
        secrets = auth_context.get_secrets_to_redact()

        xss_canary = "<kyptic_xss_canary_771>"
        probe_url = f"{target_url}?q={urllib.parse.quote(xss_canary)}"

        try:
            resp = client.execute_request(url=probe_url, method=endpoint.method, auth_context=auth_context, timeout=5.0)
        except Exception as e:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"XSS probe request failed: {str(e)}",
                secrets_to_redact=secrets,
            )

        body = resp.body_preview or ""
        ct = (resp.headers.get("content-type") or "").lower()

        # Rule 1: Non-executable response context (JSON, plain text API)
        if "application/json" in ct or "text/plain" in ct:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_SECURE,
                evidence=f"Reflection detected inside non-executable API response context ('{ct}'). Not exploitable as reflected XSS.",
                response_status=resp.status_code,
                confidence="HIGH",
                secrets_to_redact=secrets,
            )

        # Rule 2: HTML-entity encoded reflection
        if "&lt;kyptic_xss_canary_771&gt;" in body or "&lt;kyptic_xss_canary" in body:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_SECURE,
                evidence="Server properly HTML-entity escaped payload ('&lt;kyptic_xss_canary_771&gt;').",
                response_status=resp.status_code,
                confidence="HIGH",
                secrets_to_redact=secrets,
            )

        # Rule 3: Executable HTML tag context reflection
        if ("html" in ct or "xml" in ct) and xss_canary in body:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_VULNERABLE,
                severity=FindingSeverity.HIGH,
                evidence=f"Reflected XSS confirmed: Unescaped HTML tag '{xss_canary}' reflected in executable '{ct}' response body.",
                response_status=resp.status_code,
                response_snippet=resp.body_preview,
                confidence="HIGH",
                secrets_to_redact=secrets,
            )

        return DastProbeResult(
            endpoint_id=endpoint.id,
            probe_type=DastProbeType.BOLA,
            status=DastVerificationStatus.VERIFIED_SECURE,
            evidence="XSS canary payload sent. No unescaped executable tag reflection observed.",
            response_status=resp.status_code,
            confidence="HIGH",
            secrets_to_redact=secrets,
        )


class CsrfVerifier(BaseVulnerabilityVerifier):
    @property
    def vulnerability_id(self) -> str:
        return "CSRF"

    @property
    def display_name(self) -> str:
        return "Cross-Site Request Forgery (CSRF)"

    def verify(
        self,
        endpoint: ApiEndpoint,
        client: DastHttpClient,
        base_url: str,
        auth_context: DastAuthContext,
        params: Optional[Dict[str, Any]] = None,
    ) -> DastProbeResult:
        """
        Executes evidence-driven CSRF verification requiring the full 5-point evidence chain:
        1. State-changing HTTP method (POST, PUT, DELETE, PATCH).
        2. Session/Cookie authentication context.
        3. Successful execution of a cross-origin probe (untrusted Origin header).
        4. Absence of anti-CSRF token protection or Origin/Referer validation.
        5. Proof of actual exploitability (HTTP 2xx response to cross-origin request).
        Missing SameSite or missing anti-CSRF token alone without successful cross-origin state modification returns INCONCLUSIVE or VERIFIED_SECURE.
        """
        method_upper = endpoint.method.upper()
        if method_upper in ("GET", "HEAD", "OPTIONS"):
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"CSRF verification skipped for safe read-only HTTP method {endpoint.method}.",
            )

        secrets = auth_context.get_secrets_to_redact()
        target_url = f"{base_url.rstrip('/')}/{endpoint.path.lstrip('/')}"
        target_url = re.sub(r"\{[^}]+\}", "1", target_url)

        # Rule 1: Non-cookie authentication (Bearer/API Key) is not vulnerable to standard browser cross-origin CSRF
        if auth_context.auth_type not in ("COOKIE", "SESSION") and auth_context.auth_type != "NONE":
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_SECURE,
                evidence=f"Route relies on explicit '{auth_context.auth_type}' header authentication rather than implicit browser session cookies. Cross-origin browser CSRF is not exploitable.",
                confidence="HIGH",
                secrets_to_redact=secrets,
            )

        # Rule 2: Execute cross-origin probe request with untrusted Origin
        untrusted_origin = "https://attacker-cross-origin.com"
        try:
            resp = client.execute_request(
                url=target_url,
                method=endpoint.method,
                headers={"Origin": untrusted_origin, "Referer": f"{untrusted_origin}/exploit"},
                auth_context=auth_context,
                timeout=5.0,
            )
        except Exception as e:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"CSRF cross-origin probe request failed: {str(e)}",
                secrets_to_redact=secrets,
            )

        headers_lower = {str(k).lower(): str(v).lower() for k, v in (resp.headers or {}).items()}
        set_cookie = headers_lower.get("set-cookie", "")
        all_headers_str = " ".join(f"{k}:{v}" for k, v in headers_lower.items())
        has_samesite_strict_or_lax = "samesite=strict" in set_cookie or "samesite=lax" in set_cookie or "samesite=strict" in all_headers_str or "samesite=lax" in all_headers_str

        # Rule 3: Protected endpoint, rejected origin, or SameSite=Strict/Lax active
        if resp.status_code in (401, 403) or has_samesite_strict_or_lax:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_SECURE,
                evidence=f"Target route enforced anti-CSRF protection (HTTP {resp.status_code}) or SameSite cookie restrictions against cross-origin request from '{untrusted_origin}'.",
                response_status=resp.status_code,
                confidence="HIGH",
                secrets_to_redact=secrets,
            )

        # Rule 4: Complete evidence chain confirmed for vulnerable CSRF
        if resp.status_code and 200 <= resp.status_code < 300 and auth_context.auth_type in ("COOKIE", "SESSION"):
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_VULNERABLE,
                severity=FindingSeverity.MEDIUM,
                evidence=f"CSRF Confirmed: State-changing route '{endpoint.method} {endpoint.path}' accepted cross-origin request from '{untrusted_origin}' using session cookie without anti-CSRF token or Origin validation (HTTP {resp.status_code}).",
                response_status=resp.status_code,
                response_snippet=resp.body_preview,
                confidence="HIGH",
                secrets_to_redact=secrets,
            )

        # Rule 5: Ambiguous response (missing token/headers alone without 2xx state modification proof) -> INCONCLUSIVE
        return DastProbeResult(
            endpoint_id=endpoint.id,
            probe_type=DastProbeType.BOLA,
            status=DastVerificationStatus.INCONCLUSIVE,
            evidence=f"CSRF verification returned HTTP {resp.status_code}. Missing complete exploitability evidence chain.",
            response_status=resp.status_code,
            confidence="LOW",
            secrets_to_redact=secrets,
        )


class PathTraversalVerifier(BaseVulnerabilityVerifier):
    @property
    def vulnerability_id(self) -> str:
        return "PATH_TRAVERSAL"

    @property
    def display_name(self) -> str:
        return "Path Traversal"

    def verify(
        self,
        endpoint: ApiEndpoint,
        client: DastHttpClient,
        base_url: str,
        auth_context: DastAuthContext,
        params: Optional[Dict[str, Any]] = None,
    ) -> DastProbeResult:
        target_url = f"{base_url.rstrip('/')}/{endpoint.path.lstrip('/')}"
        target_url = re.sub(r"\{[^}]+\}", "1", target_url)
        secrets = auth_context.get_secrets_to_redact()

        # Controlled non-destructive path traversal payload
        probe_url = f"{target_url}?file=....//....//....//etc/passwd"
        try:
            resp = client.execute_request(url=probe_url, method=endpoint.method, auth_context=auth_context, timeout=5.0)
        except Exception as e:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"Path traversal probe request failed: {str(e)}",
                secrets_to_redact=secrets,
            )

        body = resp.body_preview or ""

        # Concrete system file content signatures required for CONFIRMED
        system_file_signatures = ["root:x:0:0:", "[boot loader]", "[operating systems]", "daemon:x:1:1:"]
        has_system_file = any(sig in body for sig in system_file_signatures)

        if has_system_file:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_VULNERABLE,
                severity=FindingSeverity.CRITICAL,
                evidence="Path Traversal confirmed: Server returned unescaped system file content.",
                response_status=resp.status_code,
                response_snippet=resp.body_preview,
                confidence="HIGH",
                secrets_to_redact=secrets,
            )

        if resp.status_code in (400, 403, 404) or (resp.status_code == 200 and not has_system_file):
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_SECURE,
                evidence="Path traversal payload tested. No unauthorized host system file contents returned.",
                response_status=resp.status_code,
                confidence="HIGH",
                secrets_to_redact=secrets,
            )

        return DastProbeResult(
            endpoint_id=endpoint.id,
            probe_type=DastProbeType.BOLA,
            status=DastVerificationStatus.INCONCLUSIVE,
            evidence=f"Path traversal verification returned HTTP {resp.status_code}.",
            response_status=resp.status_code,
            confidence="LOW",
            secrets_to_redact=secrets,
        )


class CorsVerifier(BaseVulnerabilityVerifier):
    @property
    def vulnerability_id(self) -> str:
        return "CORS_MISCONFIG"

    @property
    def display_name(self) -> str:
        return "CORS Misconfiguration"

    def verify(
        self,
        endpoint: ApiEndpoint,
        client: DastHttpClient,
        base_url: str,
        auth_context: DastAuthContext,
        params: Optional[Dict[str, Any]] = None,
    ) -> DastProbeResult:
        target_url = f"{base_url.rstrip('/')}/{endpoint.path.lstrip('/')}"
        target_url = re.sub(r"\{[^}]+\}", "1", target_url)
        secrets = auth_context.get_secrets_to_redact()

        untrusted_origin = "https://evt-attacker-9941.com"
        try:
            resp = client.execute_request(
                url=target_url,
                method=endpoint.method,
                headers={"Origin": untrusted_origin},
                auth_context=auth_context,
                timeout=5.0,
            )
        except Exception as e:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"CORS verification request failed: {str(e)}",
                secrets_to_redact=secrets,
            )

        headers_lower = {str(k).lower(): str(v) for k, v in resp.headers.items()}
        acao = headers_lower.get("access-control-allow-origin")
        acac = headers_lower.get("access-control-allow-credentials")

        # Case 1: Wildcard Origin + Credentials Allowed
        if acao == "*" and acac == "true":
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_VULNERABLE,
                severity=FindingSeverity.HIGH,
                evidence="CRITICAL CORS Misconfiguration: Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true.",
                response_status=resp.status_code,
                confidence="HIGH",
                secrets_to_redact=secrets,
            )

        # Case 2: Untrusted Origin Reflection + Credentials Allowed
        if acao == untrusted_origin and acac == "true":
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_VULNERABLE,
                severity=FindingSeverity.HIGH,
                evidence=f"CORS Misconfiguration: Server dynamically reflected untrusted origin '{untrusted_origin}' with credentials allowed.",
                response_status=resp.status_code,
                confidence="HIGH",
                secrets_to_redact=secrets,
            )

        # Case 3: Public CORS (ACAO: * without credentials) or Origin Rejected -> VERIFIED_SECURE
        return DastProbeResult(
            endpoint_id=endpoint.id,
            probe_type=DastProbeType.BOLA,
            status=DastVerificationStatus.VERIFIED_SECURE,
            evidence="CORS configuration verified. Untrusted origin reflection with credentials denied.",
            response_status=resp.status_code,
            confidence="HIGH",
            secrets_to_redact=secrets,
        )


class SecurityHeadersVerifier(BaseVulnerabilityVerifier):
    @property
    def vulnerability_id(self) -> str:
        return "SECURITY_HEADERS"

    @property
    def display_name(self) -> str:
        return "Missing Security Headers"

    def verify(
        self,
        endpoint: ApiEndpoint,
        client: DastHttpClient,
        base_url: str,
        auth_context: DastAuthContext,
        params: Optional[Dict[str, Any]] = None,
    ) -> DastProbeResult:
        target_url = f"{base_url.rstrip('/')}/{endpoint.path.lstrip('/')}"
        target_url = re.sub(r"\{[^}]+\}", "1", target_url)
        secrets = auth_context.get_secrets_to_redact()

        try:
            resp = client.execute_request(url=target_url, method=endpoint.method, auth_context=auth_context, timeout=5.0)
        except Exception as e:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"Security headers check failed: {str(e)}",
                secrets_to_redact=secrets,
            )

        headers_lower = {str(k).lower(): str(v) for k, v in resp.headers.items()}
        ct = headers_lower.get("content-type", "").lower()

        # Security Headers Evaluation
        csp_status = "PRESENT" if "content-security-policy" in headers_lower else "MISSING"
        xfo_status = "PRESENT" if "x-frame-options" in headers_lower else "MISSING"
        xcto_status = "PRESENT" if "x-content-type-options" in headers_lower else "MISSING"
        hsts_status = "PRESENT" if "strict-transport-security" in headers_lower else "MISSING"

        missing_critical = []
        if csp_status == "MISSING":
            missing_critical.append("Content-Security-Policy (MISSING)")
        if xfo_status == "MISSING":
            missing_critical.append("X-Frame-Options (MISSING)")
        if xcto_status == "MISSING":
            missing_critical.append("X-Content-Type-Options (MISSING)")

        # Only flag VERIFIED_VULNERABLE if response is HTML and multiple critical browser protective headers are missing
        if ("html" in ct) and len(missing_critical) >= 2:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_VULNERABLE,
                severity=FindingSeverity.LOW,
                evidence=f"Missing essential browser security headers on HTML response: {', '.join(missing_critical)}. CSP: {csp_status}, XFO: {xfo_status}, XCTO: {xcto_status}, HSTS: {hsts_status}.",
                response_status=resp.status_code,
                confidence="HIGH",
                secrets_to_redact=secrets,
            )

        return DastProbeResult(
            endpoint_id=endpoint.id,
            probe_type=DastProbeType.BOLA,
            status=DastVerificationStatus.VERIFIED_SECURE,
            evidence=f"Essential security headers evaluated. CSP: {csp_status}, XFO: {xfo_status}, XCTO: {xcto_status}, HSTS: {hsts_status}.",
            response_status=resp.status_code,
            confidence="HIGH",
            secrets_to_redact=secrets,
        )
