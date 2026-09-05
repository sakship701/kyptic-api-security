import base64
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import threading
from typing import Any, Dict, List, Set, Tuple

from app.services.ssrf_protection import is_ssrf_safe_url

DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_RESPONSE_BODY_SIZE_BYTES = 100 * 1024  # 100 KB
MAX_REQUEST_PAYLOAD_SIZE_BYTES = 500 * 1024  # 500 KB
MAX_CONCURRENT_REQUESTS = 5

SENSITIVE_HEADER_KEYS = {
    "authorization", "x-api-key", "api-key", "apikey", "secret",
    "token", "access_token", "cookie", "set-cookie", "x-auth-token"
}


# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------
class DastError(Exception):
    """Base exception for safe DAST operational failures."""
    pass


class DastTargetInvalidError(DastError):
    pass


class DastSsrfError(DastError):
    pass


class DastTimeoutError(DastError):
    pass


class DastConnectionError(DastError):
    pass


class DastPayloadTooLargeError(DastError):
    pass


class DastRedirectError(DastError):
    pass


# -----------------------------------------------------------------------------
# Secret Redaction Helper
# -----------------------------------------------------------------------------
def redact_secrets(content: Any, secrets_to_redact: List[str] | None = None) -> str:
    """
    Centralized utility to redact authorization headers, bearer tokens, API keys, and specified secret strings.
    Replaces sensitive credentials with '[REDACTED_SECRET]'.
    """
    if content is None:
        return ""

    text = str(content)

    # 1. Redact common header patterns in raw text
    text = re.sub(
        r"(?i)(authorization\s*:\s*)(bearer|basic)\s+[^\s\r\n]+",
        r"\1\2 [REDACTED_SECRET]",
        text
    )
    text = re.sub(
        r"(?i)(x-api-key|apikey|api_key|token|access_token|secret)\s*:\s*[^\s\r\n]+",
        r"\1: [REDACTED_SECRET]",
        text
    )
    text = re.sub(
        r"(?i)(cookie|set-cookie)\s*:\s*[^\s\r\n]+",
        r"\1: [REDACTED_SECRET]",
        text
    )

    # 2. Redact explicit secret strings passed in
    if secrets_to_redact:
        for secret in secrets_to_redact:
            if secret and isinstance(secret, str) and len(secret.strip()) > 2:
                text = text.replace(secret.strip(), "[REDACTED_SECRET]")

    return text


def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Filters and redacts sensitive header values for safe logging, display, or evidence capture.
    """
    sanitized = {}
    for k, v in headers.items():
        k_lower = str(k).lower()
        if k_lower in SENSITIVE_HEADER_KEYS:
            sanitized[k] = "[REDACTED_SECRET]"
        else:
            sanitized[k] = str(v)
    return sanitized


# -----------------------------------------------------------------------------
# Authentication Context
# -----------------------------------------------------------------------------
class DastAuthContext:
    """
    Safe authentication abstraction for active DAST requests.
    Supports BEARER, API_KEY, and BASIC modes.
    """
    def __init__(
        self,
        auth_type: str = "NONE",
        token_or_key: str | None = None,
        header_name: str | None = "Authorization",
        username: str | None = None,
        password: str | None = None,
    ):
        self.auth_type = (auth_type or "NONE").upper()
        self.token_or_key = token_or_key
        self.header_name = header_name or ("Authorization" if self.auth_type in ("BEARER", "BASIC") else "X-API-Key")
        self.username = username
        self.password = password

    def apply_to_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        updated = dict(headers) if headers else {}
        if self.auth_type == "BEARER" and self.token_or_key:
            updated[self.header_name] = f"Bearer {self.token_or_key.strip()}"
        elif self.auth_type == "API_KEY" and self.token_or_key:
            updated[self.header_name] = self.token_or_key.strip()
        elif self.auth_type == "BASIC":
            if self.username or self.password:
                raw_userpass = f"{self.username or ''}:{self.password or ''}"
                encoded = base64.b64encode(raw_userpass.encode("utf-8")).decode("utf-8")
                updated[self.header_name] = f"Basic {encoded}"
            elif self.token_or_key:
                updated[self.header_name] = f"Basic {self.token_or_key.strip()}"
        return updated

    def get_secrets_to_redact(self) -> List[str]:
        secrets = []
        if self.token_or_key:
            secrets.append(self.token_or_key)
        if self.password:
            secrets.append(self.password)
        return secrets


# -----------------------------------------------------------------------------
# Redirect Safety Handler
# -----------------------------------------------------------------------------
class DastSafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    Strict redirect policy enforcing same-origin (scheme/host/port) boundaries and SSRF re-validation.
    """
    def __init__(self, target_origin: Tuple[str, str, int | None], allow_localhost: bool = False):
        super().__init__()
        self.target_origin = target_origin
        self.allow_localhost = allow_localhost

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # 1. Re-validate destination URL against SSRF protection engine
        is_safe, err_desc = is_ssrf_safe_url(newurl, allow_localhost=self.allow_localhost)
        if not is_safe:
            return None

        # 2. Enforce strict same-origin match (scheme, hostname, port)
        try:
            parsed = urllib.parse.urlparse(newurl)
            new_scheme = parsed.scheme.lower() if parsed.scheme else ""
            new_host = parsed.hostname.lower() if parsed.hostname else ""
            new_port = parsed.port or (443 if new_scheme == "https" else 80)

            target_scheme, target_host, raw_target_port = self.target_origin
            target_port = raw_target_port or (443 if target_scheme == "https" else 80)

            if new_scheme != target_scheme or new_port != target_port:
                return None

            if self.allow_localhost and target_host in ("localhost", "127.0.0.1") and new_host in ("localhost", "127.0.0.1"):
                return super().redirect_request(req, fp, code, msg, headers, newurl)

            if new_host == target_host:
                return super().redirect_request(req, fp, code, msg, headers, newurl)
        except Exception:
            return None

        return None


# -----------------------------------------------------------------------------
# Bounded Response Representation
# -----------------------------------------------------------------------------
class DastResponse:
    """
    Bounded, safe response representation for DAST probe evaluation.
    Enforces maximum payload memory limits and header sanitization.
    """
    def __init__(
        self,
        status_code: int | None,
        headers: Dict[str, str],
        elapsed_ms: float,
        body_preview: str | None,
        final_url: str | None,
        redirected: bool = False,
        error_message: str | None = None,
    ):
        self.status_code = status_code
        self.headers = sanitize_headers(headers or {})
        self.elapsed_ms = round(elapsed_ms, 2)
        self.body_preview = redact_secrets(body_preview[:MAX_RESPONSE_BODY_SIZE_BYTES]) if body_preview else None
        self.final_url = redact_secrets(final_url) if final_url else None
        self.redirected = redirected
        self.error_message = redact_secrets(error_message) if error_message else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "elapsed_ms": self.elapsed_ms,
            "body_preview": self.body_preview,
            "final_url": self.final_url,
            "redirected": self.redirected,
            "error_message": self.error_message,
        }


# -----------------------------------------------------------------------------
# Secure DAST HTTP Client
# -----------------------------------------------------------------------------
class DastHttpClient:
    """
    Controlled HTTP execution service for active DAST scanning.
    Enforces pre-request SSRF validation, connection timeouts, payload boundaries, bounded concurrency, and secret redaction.
    """
    def __init__(self, allow_localhost: bool = False, max_concurrency: int = MAX_CONCURRENT_REQUESTS):
        self.allow_localhost = allow_localhost
        self.semaphore = threading.Semaphore(max_concurrency)

    def get_origin(self, url: str) -> Tuple[str, str, int | None]:
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower() if parsed.scheme else "http"
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        port = parsed.port
        return (scheme, hostname, port)

    def execute_request(
        self,
        url: str,
        method: str = "GET",
        headers: Dict[str, str] | None = None,
        body: bytes | str | None = None,
        auth_context: DastAuthContext | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> DastResponse:
        method_upper = (method or "GET").upper()
        allowed_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
        if method_upper not in allowed_methods:
            raise DastTargetInvalidError(f"HTTP method '{method}' is not permitted for DAST testing.")

        # 1. Pre-request SSRF & Target Validation
        is_safe, err_msg = is_ssrf_safe_url(url, allow_localhost=self.allow_localhost)
        if not is_safe:
            raise DastSsrfError(redact_secrets(f"Target URL SSRF validation failed: {err_msg}"))

        # 2. Check Payload Size Limit
        body_bytes = None
        if body is not None:
            if isinstance(body, str):
                body_bytes = body.encode("utf-8")
            elif isinstance(body, bytes):
                body_bytes = body
            else:
                raise DastTargetInvalidError("Request body must be string or bytes.")

            if len(body_bytes) > MAX_REQUEST_PAYLOAD_SIZE_BYTES:
                raise DastPayloadTooLargeError(
                    f"Request payload size ({len(body_bytes)} bytes) exceeds maximum limit of {MAX_REQUEST_PAYLOAD_SIZE_BYTES} bytes."
                )

        # 3. Apply Authentication Headers
        secrets_to_redact = []
        req_headers = {
            "User-Agent": "Kyptic-API-DAST-Scanner/1.0",
            "Accept": "application/json, text/plain, */*",
        }
        if headers:
            req_headers.update(headers)

        if auth_context:
            req_headers = auth_context.apply_to_headers(req_headers)
            secrets_to_redact.extend(auth_context.get_secrets_to_redact())

        # 4. Target Origin Scope setup
        target_origin = self.get_origin(url)

        # 5. Acquire Concurrency Semaphore
        acquired = self.semaphore.acquire(timeout=timeout)
        if not acquired:
            raise DastTimeoutError("Request concurrency limit reached. Probing paused.")

        start_time = time.time()
        try:
            req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method_upper)
            opener = urllib.request.build_opener(DastSafeRedirectHandler(target_origin, allow_localhost=self.allow_localhost))

            open_kwargs: Dict[str, Any] = {"timeout": timeout}
            if target_origin[0] == "https":
                ssl_ctx = ssl.create_default_context()
                open_kwargs["context"] = ssl_ctx

            with opener.open(req, **open_kwargs) as response:
                elapsed_ms = (time.time() - start_time) * 1000.0
                status_code = response.status
                resp_headers = dict(response.headers)
                final_url = response.geturl()
                redirected = final_url.lower().rstrip("/") != url.lower().rstrip("/")

                # Read bounded response payload (max 100 KB)
                raw_bytes = response.read(MAX_RESPONSE_BODY_SIZE_BYTES)
                body_preview = raw_bytes.decode("utf-8", errors="ignore")

                return DastResponse(
                    status_code=status_code,
                    headers=resp_headers,
                    elapsed_ms=elapsed_ms,
                    body_preview=redact_secrets(body_preview, secrets_to_redact),
                    final_url=final_url,
                    redirected=redirected,
                    error_message=None
                )
        except urllib.error.HTTPError as http_err:
            elapsed_ms = (time.time() - start_time) * 1000.0
            resp_headers = dict(http_err.headers) if http_err.headers else {}
            final_url = http_err.geturl() if hasattr(http_err, "geturl") else url
            body_bytes = http_err.read(MAX_RESPONSE_BODY_SIZE_BYTES) if hasattr(http_err, "read") else b""
            body_preview = body_bytes.decode("utf-8", errors="ignore")

            return DastResponse(
                status_code=http_err.code,
                headers=resp_headers,
                elapsed_ms=elapsed_ms,
                body_preview=redact_secrets(body_preview, secrets_to_redact),
                final_url=final_url,
                redirected=False,
                error_message=None
            )
        except socket.timeout:
            raise DastTimeoutError(f"HTTP request to target timed out after {timeout} seconds.")
        except urllib.error.URLError as url_err:
            err_str = str(url_err.reason) if hasattr(url_err, "reason") else str(url_err)
            raise DastConnectionError(redact_secrets(f"Connection failed: {err_str}", secrets_to_redact))
        except Exception as e:
            raise DastConnectionError(redact_secrets(f"Operational DAST error: {str(e)}", secrets_to_redact))
        finally:
            self.semaphore.release()
