import asyncio
import json
import logging
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

from app.models.api_endpoint import ApiEndpoint
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.services.dast_http_client import DastAuthContext, redact_secrets
from app.services.finding_normalizer import generate_fingerprint
from app.services.ssrf_protection import is_ssrf_safe_url

logger = logging.getLogger(__name__)


class BrowserDastResult:
    def __init__(
        self,
        target_url: str,
        status: str = "COMPLETED",
        visited_urls: Optional[List[str]] = None,
        discovered_routes: Optional[List[str]] = None,
        forms_discovered: Optional[List[Dict[str, Any]]] = None,
        findings: Optional[List[Finding]] = None,
        logs: Optional[List[str]] = None,
        error_msg: Optional[str] = None,
    ):
        self.target_url = target_url
        self.status = status
        self.visited_urls = visited_urls or []
        self.discovered_routes = discovered_routes or []
        self.forms_discovered = forms_discovered or []
        self.findings = findings or []
        self.logs = logs or []
        self.error_msg = error_msg

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "status": self.status,
            "visited_urls": self.visited_urls,
            "discovered_routes": self.discovered_routes,
            "forms_discovered": self.forms_discovered,
            "findings_count": len(self.findings),
            "logs": self.logs,
            "error_msg": self.error_msg,
        }


def get_origin(url: str) -> Tuple[str, str, int]:
    try:
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower() if parsed.scheme else "http"
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        port = parsed.port or (443 if scheme == "https" else 80)
        return (scheme, hostname, port)
    except Exception:
        return ("http", "", 80)


def is_same_origin(url: str, target_origin: Tuple[str, str, int]) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower() if parsed.scheme else ""
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        port = parsed.port or (443 if scheme == "https" else 80)
        t_scheme, t_host, t_port = target_origin
        if scheme != t_scheme or port != t_port:
            return False
        if t_host in ("localhost", "127.0.0.1") and hostname in ("localhost", "127.0.0.1"):
            return True
        return hostname == t_host
    except Exception:
        return False


class BrowserDastService:
    """
    Production-grade Browser-Based DAST Execution Engine using Playwright.
    Executes headless Chromium browsing, same-origin link & SPA route crawling,
    safe DOM form discovery, and deterministic DOM XSS execution verification.
    """

    def __init__(
        self,
        max_pages: int = 15,
        max_depth: int = 2,
        page_timeout_ms: int = 10000,
        total_timeout_s: int = 30,
    ):
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.page_timeout_ms = page_timeout_ms
        self.total_timeout_s = total_timeout_s

    @staticmethod
    def is_playwright_installed() -> bool:
        try:
            import playwright.async_api  # type: ignore # noqa: F401
            return True
        except ImportError:
            return False

    async def run_browser_dast(
        self,
        target_url: str,
        project_id: int = 0,
        scan_id: int = 0,
        auth_context: Optional[DastAuthContext] = None,
        greybox_contexts: Optional[List[Any]] = None,
    ) -> BrowserDastResult:
        logs: List[str] = []
        logs.append(f"Initializing Browser DAST for target: {target_url}")

        # 1. SSRF Safety Control
        is_safe, ssrf_reason = is_ssrf_safe_url(target_url, allow_localhost=False)
        if not is_safe:
            msg = f"Target URL '{target_url}' blocked by SSRF safety guard: {ssrf_reason}"
            logs.append(msg)
            return BrowserDastResult(target_url=target_url, status="SKIPPED_SSRF_BLOCKED", logs=logs, error_msg=msg)

        # 2. Check Playwright Availability
        if not self.is_playwright_installed():
            msg = "Playwright library is not installed. Browser DAST skipped gracefully."
            logs.append(msg)
            return BrowserDastResult(target_url=target_url, status="SKIPPED_BROWSER_UNAVAILABLE", logs=logs)

        target_origin = get_origin(target_url)
        visited_urls: Set[str] = set()
        discovered_routes: Set[str] = set()
        forms_discovered: List[Dict[str, Any]] = []
        findings: List[Finding] = []

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return BrowserDastResult(target_url=target_url, status="SKIPPED_BROWSER_UNAVAILABLE", logs=logs)

        secrets_to_redact = auth_context.get_secrets_to_redact() if auth_context else []

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
                )
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent="Kyptic-Browser-DAST/1.0 (Headless Chromium)",
                )

                # Configure auth headers if provided
                if auth_context and auth_context.token_or_key:
                    header_name = auth_context.header_name or "Authorization"
                    header_val = auth_context.token_or_key
                    if auth_context.auth_type == "BEARER" and not header_val.lower().startswith("bearer "):
                        header_val = f"Bearer {header_val}"
                    await context.set_extra_http_headers({header_name: header_val})

                # Crawl Queue: (url, depth)
                queue: List[Tuple[str, int]] = [(target_url, 0)]

                while queue and len(visited_urls) < self.max_pages:
                    curr_url, curr_depth = queue.pop(0)
                    if curr_url in visited_urls:
                        continue
                    if not is_same_origin(curr_url, target_origin):
                        continue

                    # SSRF Guard for each navigated link
                    link_safe, _ = is_ssrf_safe_url(curr_url, allow_localhost=False)
                    if not link_safe:
                        continue

                    visited_urls.add(curr_url)
                    parsed_path = urllib.parse.urlparse(curr_url).path or "/"
                    discovered_routes.add(parsed_path)

                    page = await context.new_page()
                    try:
                        # Console log listener
                        console_msgs = []
                        page.on("console", lambda msg: console_msgs.append(msg.text))

                        # Expose kyptic_dom_xss_callback to detect browser execution
                        dom_xss_triggered = False

                        async def on_dom_xss_fired(payload_str):
                            nonlocal dom_xss_triggered
                            dom_xss_triggered = True

                        await page.expose_function("kyptic_dom_xss_callback", on_dom_xss_fired)

                        await page.goto(curr_url, timeout=self.page_timeout_ms, wait_until="domcontentloaded")
                        title = await page.title()
                        logs.append(f"Visited [{curr_depth}]: {curr_url} ('{title}')")

                        # DOM Form Discovery (Non-destructive)
                        forms = await page.evaluate("""
                            () => {
                                const formList = [];
                                const forms = document.querySelectorAll('form');
                                forms.forEach((f, idx) => {
                                    const inputs = Array.from(f.querySelectorAll('input, textarea, select')).map(i => ({
                                        name: i.getAttribute('name') || i.getAttribute('id') || 'unnamed',
                                        type: i.getAttribute('type') || i.tagName.toLowerCase(),
                                    }));
                                    formList.push({
                                        form_index: idx,
                                        action: f.getAttribute('action') || '',
                                        method: (f.getAttribute('method') || 'GET').toUpperCase(),
                                        input_count: inputs.length,
                                        inputs: inputs
                                    });
                                });
                                return formList;
                            }
                        """)
                        for f_item in forms:
                            f_item["page_url"] = curr_url
                            forms_discovered.append(f_item)

                        # Crawl same-origin links & SPA routes
                        if curr_depth < self.max_depth:
                            links = await page.evaluate("""
                                () => {
                                    const set = new Set();
                                    document.querySelectorAll('a[href]').forEach(a => set.add(a.href));
                                    document.querySelectorAll('[data-route], [routerlink]').forEach(el => {
                                        const r = el.getAttribute('data-route') || el.getAttribute('routerlink');
                                        if (r) set.add(r);
                                    });
                                    return Array.from(set);
                                }
                            """)
                            for link in links:
                                full_link = urllib.parse.urljoin(curr_url, link)
                                if is_same_origin(full_link, target_origin) and full_link not in visited_urls:
                                    queue.append((full_link, curr_depth + 1))

                        # DOM XSS Verification Probe
                        # Inject canary token callback into URL fragment / param
                        canary_payload = "<img src=x onerror=\"window.kyptic_dom_xss_callback && window.kyptic_dom_xss_callback('kyptic_dom_xss_fired')\">"
                        probe_url = f"{curr_url}#q=" + urllib.parse.quote(canary_payload) if "#" not in curr_url else f"{curr_url}&q=" + urllib.parse.quote(canary_payload)

                        probe_page = await context.new_page()
                        try:
                            await probe_page.expose_function("kyptic_dom_xss_callback", on_dom_xss_fired)
                            await probe_page.goto(probe_url, timeout=self.page_timeout_ms, wait_until="domcontentloaded")
                            await probe_page.wait_for_timeout(1000)

                            if dom_xss_triggered:
                                evidence_snippet = f"DOM XSS confirmed via Playwright browser execution: Client-side JS executed injected canary callback on route '{parsed_path}'."
                                evidence_snippet = redact_secrets(evidence_snippet, secrets_to_redact)
                                fingerprint = generate_fingerprint("DOM_XSS", f"API:GET:{parsed_path}", project_id)

                                finding = Finding(
                                    project_id=project_id,
                                    scan_id=scan_id,
                                    title="DOM-Based Cross-Site Scripting (DOM XSS)",
                                    severity=FindingSeverity.HIGH,
                                    status=FindingStatus.OPEN,
                                    category="DOM_XSS",
                                    description="Client-side JavaScript executed untrusted URL fragment payload in browser DOM context.",
                                    remediation="Sanitize all URL fragments, location parameters, and DOM sinks before rendering dynamic innerHTML.",
                                    file_path=f"API:GET:{parsed_path}",
                                    source=FindingSource.DAST,
                                    scanner_name="kyptic-browser-dast",
                                    scanner_version="1.0.0",
                                    code_snippet=evidence_snippet,
                                    fingerprint=fingerprint,
                                    cwe="CWE-79",
                                    owasp="A03:2021",
                                    confidence_score=90,
                                    confidence_level="HIGH",
                                    verification_status="VERIFIED_VULNERABLE",
                                    verification_explanation=evidence_snippet,
                                    evidence_sources="BROWSER_DAST",
                                )
                                findings.append(finding)
                                logs.append(f"DOM XSS CONFIRMED on {curr_url}")
                        finally:
                            await probe_page.close()

                    except Exception as page_err:
                        logs.append(f"Error crawling page {curr_url}: {str(page_err)}")
                    finally:
                        await page.close()

                await browser.close()
                return BrowserDastResult(
                    target_url=target_url,
                    status="COMPLETED",
                    visited_urls=list(visited_urls),
                    discovered_routes=list(discovered_routes),
                    forms_discovered=forms_discovered,
                    findings=findings,
                    logs=logs,
                )

        except Exception as err:
            logger.warning(f"Browser DAST error: {err}")
            logs.append(f"Browser execution exception: {str(err)}")
            return BrowserDastResult(
                target_url=target_url,
                status="FAILED",
                logs=logs,
                error_msg=str(err),
            )
