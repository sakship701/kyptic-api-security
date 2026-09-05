import asyncio
import html
import re
import ssl
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from app.services.scanner_base import BaseScanner


class DASTStatus:
    SUCCESS = "SUCCESS"
    NO_VULNERABILITIES = "NO_VULNERABILITIES"
    TARGET_UNREACHABLE = "TARGET_UNREACHABLE"
    SCANNER_ERROR = "SCANNER_ERROR"


from app.services.ssrf_protection import is_ssrf_safe_url


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, target_origin: Tuple[str, str, int | None]):
        super().__init__()
        self.target_origin = target_origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # 1. Re-validate redirect destination for SSRF safety
        is_safe, _ = is_ssrf_safe_url(newurl, allow_localhost=True)
        if not is_safe:
            return None

        # 2. Enforce strict target origin scope
        parsed = urllib.parse.urlparse(newurl)
        new_scheme = parsed.scheme.lower() if parsed.scheme else ""
        new_host = parsed.hostname.lower() if parsed.hostname else ""
        new_port = parsed.port

        target_scheme, target_host, target_port = self.target_origin
        if new_scheme != target_scheme or new_port != target_port:
            return None

        if target_host in ("localhost", "127.0.0.1") and new_host in ("localhost", "127.0.0.1"):
            return super().redirect_request(req, fp, code, msg, headers, newurl)

        if new_host == target_host:
            return super().redirect_request(req, fp, code, msg, headers, newurl)

        # Block redirect to off-target origin
        return None


class DASTWebScanner(BaseScanner):
    def name(self) -> str:
        return "dast-web"

    def get_origin(self, url: str) -> Tuple[str, str, int | None]:
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower() if parsed.scheme else "http"
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        port = parsed.port
        return (scheme, hostname, port)

    def is_same_origin(self, url: str, target_origin: Tuple[str, str, int | None]) -> bool:
        try:
            parsed = urllib.parse.urlparse(url)
            scheme = parsed.scheme.lower() if parsed.scheme else ""
            hostname = parsed.hostname.lower() if parsed.hostname else ""
            port = parsed.port
            
            target_scheme, target_host, target_port = target_origin
            if scheme != target_scheme or port != target_port:
                return False
                
            if target_host in ("localhost", "127.0.0.1") and hostname in ("localhost", "127.0.0.1"):
                return True
                
            return hostname == target_host
        except Exception:
            return False

    def _make_request(
        self,
        url: str,
        target_origin: Tuple[str, str, int | None],
        method: str = "GET",
        headers: Dict[str, str] | None = None,
        timeout: int = 5
    ) -> Tuple[int | None, Dict[str, str], List[Tuple[str, str]], str | None, str | None]:
        """
        Safely execute non-destructive HTTP/HTTPS request within target_origin scope.
        Returns (status_code, headers_dict, raw_headers_list, body_text_preview, error_msg).
        """
        if not self.is_same_origin(url, target_origin):
            return (None, {}, [], None, "Blocked request outside target origin scope.")

        req_headers = {
            "User-Agent": "Kyptic-DAST-Scanner/1.0",
            "Accept": "*/*",
        }
        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(url, headers=req_headers, method=method.upper())

        # SSL context
        ssl_ctx = None
        if target_origin[0] == "https":
            ssl_ctx = ssl.create_default_context()
            # Do not bypass certificate checks for HTTPS testing

        opener = urllib.request.build_opener(SafeRedirectHandler(target_origin))

        open_kwargs = {"timeout": timeout}
        if target_origin[0] == "https" and ssl_ctx:
            open_kwargs["context"] = ssl_ctx

        try:
            with opener.open(req, **open_kwargs) as response:
                status_code = response.status
                headers_dict = dict(response.headers)
                raw_headers = response.headers.items()
                
                # Limit body reading to 64KB for inspection without holding large payloads
                body_bytes = response.read(65536)
                body_text = body_bytes.decode("utf-8", errors="ignore")
                return (status_code, headers_dict, raw_headers, body_text, None)
        except urllib.error.HTTPError as http_err:
            headers_dict = dict(http_err.headers) if http_err.headers else {}
            raw_headers = http_err.headers.items() if http_err.headers else []
            body_bytes = http_err.read(65536) if hasattr(http_err, "read") else b""
            body_text = body_bytes.decode("utf-8", errors="ignore")
            return (http_err.code, headers_dict, raw_headers, body_text, None)
        except (urllib.error.URLError, TimeoutError, ConnectionRefusedError, socket_err := Exception) as err:
            return (None, {}, [], None, str(err))

    async def scan(self, target_url: str) -> Dict[str, Any]:
        """
        Execute non-destructive DAST scan on live web target_url.
        """
        if not target_url or not isinstance(target_url, str):
            return {
                "status": DASTStatus.TARGET_UNREACHABLE,
                "results": [],
                "crawled_pages": [],
                "version": "dast-web 1.0.0",
                "error_message": "Invalid target URL provided."
            }

        target_url = target_url.strip()
        parsed_target = urllib.parse.urlparse(target_url)
        if not parsed_target.scheme or not parsed_target.netloc:
            return {
                "status": DASTStatus.TARGET_UNREACHABLE,
                "results": [],
                "crawled_pages": [],
                "version": "dast-web 1.0.0",
                "error_message": f"Malformed target URL: {target_url}"
            }

        # SSRF revalidation check immediately before network request
        is_safe, ssrf_err = is_ssrf_safe_url(target_url, allow_localhost=True)
        if not is_safe:
            return {
                "status": DASTStatus.TARGET_UNREACHABLE,
                "results": [],
                "crawled_pages": [],
                "version": "dast-web 1.0.0",
                "error_message": f"Target URL blocked by SSRF protection: {ssrf_err}"
            }

        target_origin = self.get_origin(target_url)
        is_https = (target_origin[0] == "https")

        raw_findings = []
        crawled_urls: Set[str] = set()

        # 1. Target Reachability Check
        status_code, headers_dict, raw_headers, body_text, err_msg = self._make_request(
            target_url, target_origin, method="GET", timeout=5
        )

        if status_code is None:
            # Check for SSL verification errors specifically on HTTPS
            if is_https and err_msg and ("CERTIFICATE_VERIFY_FAILED" in err_msg or "SSL" in err_msg):
                raw_findings.append({
                    "rule_id": "DAST-TLS-CERT-VERIFY-FAILED",
                    "title": "HTTPS TLS Certificate Verification Failed",
                    "summary": f"The HTTPS target '{target_url}' presented an invalid or untrusted TLS certificate: {err_msg}",
                    "severity": "HIGH",
                    "category": "A02:2021-Cryptographic Failures",
                    "url": target_url,
                    "evidence_snippet": f"Target: {target_url}\nSSL Error: {err_msg}",
                })
                # Re-attempt reachability check with unverified SSL to allow remaining passive checks
                try:
                    ctx_unverified = ssl._create_unverified_context()
                    req = urllib.request.Request(target_url, headers={"User-Agent": "Kyptic-DAST/1.0"})
                    with urllib.request.urlopen(req, timeout=5, context=ctx_unverified) as res:
                        status_code = res.status
                        headers_dict = dict(res.headers)
                        raw_headers = res.headers.items()
                        body_text = res.read(65536).decode("utf-8", errors="ignore")
                except Exception:
                    pass

            if status_code is None:
                return {
                    "status": DASTStatus.TARGET_UNREACHABLE,
                    "results": raw_findings,
                    "crawled_pages": [],
                    "version": "dast-web 1.0.0",
                    "error_message": f"Target URL '{target_url}' is unreachable: {err_msg}"
                }

        crawled_urls.add(target_url)

        # 2. HTTP vs HTTPS Enforcement Check
        if not is_https:
            raw_findings.append({
                "rule_id": "DAST-HTTP-WITHOUT-HTTPS",
                "title": "HTTP Usage Without Mandatory HTTPS Enforcement",
                "summary": f"The target '{target_url}' transmits data over unencrypted HTTP. Sensitive data may be exposed in transit.",
                "severity": "LOW",
                "category": "A02:2021-Cryptographic Failures",
                "url": target_url,
                "evidence_snippet": f"Scheme: {target_origin[0]}\nTarget: {target_url}\nStatus: {status_code}",
            })

        # 3. Security Headers Audit
        header_keys_lower = {k.lower(): (k, v) for k, v in headers_dict.items()}

        # Content-Security-Policy
        if "content-security-policy" not in header_keys_lower:
            raw_findings.append({
                "rule_id": "DAST-MISSING-CSP",
                "title": "Missing Content-Security-Policy (CSP) Header",
                "summary": "The web application does not return a Content-Security-Policy header, increasing risk of Cross-Site Scripting (XSS).",
                "severity": "MEDIUM",
                "category": "A05:2021-Security Misconfiguration",
                "url": target_url,
                "evidence_snippet": f"HTTP/{status_code}\nMissing Header: Content-Security-Policy",
            })

        # Strict-Transport-Security (HTTPS targets ONLY)
        if is_https and "strict-transport-security" not in header_keys_lower:
            raw_findings.append({
                "rule_id": "DAST-MISSING-HSTS",
                "title": "Missing HTTP Strict Transport Security (HSTS) Header",
                "summary": "The HTTPS target does not enforce HSTS, leaving users vulnerable to SSL stripping attacks.",
                "severity": "MEDIUM",
                "category": "A05:2021-Security Misconfiguration",
                "url": target_url,
                "evidence_snippet": f"HTTPS Target: {target_url}\nMissing Header: Strict-Transport-Security",
            })

        # X-Frame-Options
        if "x-frame-options" not in header_keys_lower and "content-security-policy" not in header_keys_lower:
            raw_findings.append({
                "rule_id": "DAST-MISSING-X-FRAME-OPTIONS",
                "title": "Missing Anti-Clickjacking Header (X-Frame-Options)",
                "summary": "The target does not specify X-Frame-Options or CSP frame-ancestors, allowing the page to be embedded in malicious iframes.",
                "severity": "LOW",
                "category": "A05:2021-Security Misconfiguration",
                "url": target_url,
                "evidence_snippet": f"Missing Header: X-Frame-Options / CSP frame-ancestors",
            })

        # X-Content-Type-Options
        if "x-content-type-options" not in header_keys_lower:
            raw_findings.append({
                "rule_id": "DAST-MISSING-X-CONTENT-TYPE-OPTIONS",
                "title": "Missing X-Content-Type-Options Header",
                "summary": "The target does not set X-Content-Type-Options: nosniff, allowing browsers to MIME-sniff response content.",
                "severity": "INFO",
                "category": "A05:2021-Security Misconfiguration",
                "url": target_url,
                "evidence_snippet": f"Missing Header: X-Content-Type-Options: nosniff",
            })

        # Server Banner / Technology Disclosure
        server_header = header_keys_lower.get("server", (None, None))[1]
        powered_by_header = header_keys_lower.get("x-powered-by", (None, None))[1]
        if server_header and re.search(r"\d+\.\d+", server_header):
            raw_findings.append({
                "rule_id": "DAST-SERVER-BANNER-LEAK",
                "title": "Detailed Server Version Disclosure",
                "summary": f"The Server header discloses explicit software version information: '{server_header}'.",
                "severity": "INFO",
                "category": "A05:2021-Security Misconfiguration",
                "url": target_url,
                "evidence_snippet": f"Server: {server_header}",
            })
        if powered_by_header:
            raw_findings.append({
                "rule_id": "DAST-X-POWERED-BY-LEAK",
                "title": "X-Powered-By Header Information Disclosure",
                "summary": f"The X-Powered-By header discloses underlying technology details: '{powered_by_header}'.",
                "severity": "INFO",
                "category": "A05:2021-Security Misconfiguration",
                "url": target_url,
                "evidence_snippet": f"X-Powered-By: {powered_by_header}",
            })

        # 4. Set-Cookie Flag Audit (Parse multiple Set-Cookie headers independently)
        set_cookie_headers = [v for k, v in raw_headers if k.lower() == "set-cookie"]
        for cookie_str in set_cookie_headers:
            cookie_name = cookie_str.split("=")[0].strip() if "=" in cookie_str else "cookie"
            cookie_lower = cookie_str.lower()
            
            missing_flags = []
            if "httponly" not in cookie_lower:
                missing_flags.append("HttpOnly")
            if is_https and "secure" not in cookie_lower:
                missing_flags.append("Secure")
            if "samesite" not in cookie_lower:
                missing_flags.append("SameSite")

            if missing_flags:
                raw_findings.append({
                    "rule_id": f"DAST-INSECURE-COOKIE-{cookie_name.upper()}",
                    "title": f"Insecure Cookie Flags on '{cookie_name}'",
                    "summary": f"Cookie '{cookie_name}' is missing recommended security flags: {', '.join(missing_flags)}.",
                    "severity": "LOW",
                    "category": "A05:2021-Security Misconfiguration",
                    "url": target_url,
                    "evidence_snippet": f"Set-Cookie: {cookie_name}=...; Missing: {', '.join(missing_flags)}",
                })

        # 5. CORS Policy Audit
        cors_status, cors_headers, _, _, _ = self._make_request(
            target_url, target_origin, method="GET", headers={"Origin": "https://evil-attacker.example.com"}
        )
        cors_origin = dict(cors_headers).get("Access-Control-Allow-Origin")
        cors_creds = dict(cors_headers).get("Access-Control-Allow-Credentials")
        if cors_origin == "*" and cors_creds == "true":
            raw_findings.append({
                "rule_id": "DAST-CORS-WILDCARD-CREDENTIALS",
                "title": "Overly Permissive CORS Policy with Credentials",
                "summary": "Target allows wildcard Access-Control-Allow-Origin combined with Access-Control-Allow-Credentials: true.",
                "severity": "HIGH",
                "category": "A01:2021-Broken Access Control",
                "url": target_url,
                "evidence_snippet": "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
            })
        elif cors_origin == "https://evil-attacker.example.com":
            raw_findings.append({
                "rule_id": "DAST-CORS-REFLECTED-ORIGIN",
                "title": "Reflected Arbitrary Origin in CORS Policy",
                "summary": "Target reflects arbitrary untrusted Origin header values in Access-Control-Allow-Origin.",
                "severity": "HIGH",
                "category": "A01:2021-Broken Access Control",
                "url": target_url,
                "evidence_snippet": f"Request Origin: https://evil-attacker.example.com\nResponse Access-Control-Allow-Origin: {cors_origin}",
            })

        # 6. Sensitive File Probing (Strictly limited to target origin scope, NO SECRET BODIES PERSISTED!)
        sensitive_paths = [
            ("/.env", "DAST-EXPOSED-ENV-FILE", "Exposed .env Configuration File", "CRITICAL"),
            ("/.git/HEAD", "DAST-EXPOSED-GIT-REPO", "Exposed .git Repository Directory", "HIGH"),
            ("/wp-config.php.bak", "DAST-EXPOSED-WP-CONFIG", "Exposed WordPress Backup File", "HIGH"),
            ("/.ds_store", "DAST-EXPOSED-DS-STORE", "Exposed macOS .DS_Store Metadata File", "MEDIUM"),
        ]

        base_target_prefix = f"{target_origin[0]}://{target_origin[1]}" + (f":{target_origin[2]}" if target_origin[2] else "")

        for probe_path, rule_id, title, sev in sensitive_paths:
            probe_url = urllib.parse.urljoin(base_target_prefix, probe_path)
            p_code, p_headers, _, p_body, _ = self._make_request(probe_url, target_origin, method="GET", timeout=4)
            if p_code == 200 and p_body:
                # Verify non-empty body and signature matching without recording secret contents
                is_match = False
                if probe_path == "/.env" and ("=" in p_body or "APP_KEY" in p_body or "DB_" in p_body):
                    is_match = True
                elif probe_path == "/.git/HEAD" and ("ref: refs/" in p_body or "master" in p_body or "main" in p_body):
                    is_match = True
                elif probe_path in ("/.ds_store", "/wp-config.php.bak") and len(p_body) > 10:
                    is_match = True

                if is_match:
                    raw_findings.append({
                        "rule_id": rule_id,
                        "title": title,
                        "summary": f"Sensitive path '{probe_path}' is publicly accessible on target web server.",
                        "severity": sev,
                        "category": "A05:2021-Security Misconfiguration",
                        "url": probe_url,
                        "evidence_snippet": f"GET {probe_path} HTTP/1.1\nHost: {target_origin[1]}\nHTTP/1.1 200 OK\n[Sensitive File Exposed - Body Redacted]",
                    })

        # 7. Safe Link Crawling (Bounded depth = 2, max pages = 10)
        if body_text:
            hrefs = re.findall(r'href=["\'](.*?)["\']', body_text, re.IGNORECASE)
            for href in hrefs:
                if len(crawled_urls) >= 10:
                    break
                full_url = urllib.parse.urljoin(target_url, href)
                # Strip fragment
                full_url = full_url.split("#")[0]
                if self.is_same_origin(full_url, target_origin) and full_url not in crawled_urls:
                    crawled_urls.add(full_url)
                    # Crawl page non-destructively
                    c_code, c_headers, _, _, _ = self._make_request(full_url, target_origin, method="GET", timeout=4)

        final_status = DASTStatus.SUCCESS if raw_findings else DASTStatus.NO_VULNERABILITIES

        return {
            "status": final_status,
            "results": raw_findings,
            "crawled_pages": list(crawled_urls),
            "version": "dast-web 1.0.0",
            "error_message": None
        }
