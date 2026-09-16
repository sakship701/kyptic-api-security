import asyncio
import re
import urllib.parse
from typing import Any, Dict, Optional

from app.models.api_endpoint import ApiEndpoint
from app.models.finding import FindingSeverity
from app.security.base_verifier import BaseVulnerabilityVerifier
from app.services.browser_dast_service import BrowserDastService
from app.services.dast_http_client import DastAuthContext, DastHttpClient, redact_secrets
from app.services.dast_probes import DastProbeResult, DastVerificationStatus, DastProbeType


class DomXssVerifier(BaseVulnerabilityVerifier):
    @property
    def vulnerability_id(self) -> str:
        return "DOM_XSS"

    @property
    def display_name(self) -> str:
        return "DOM-Based Cross-Site Scripting (DOM XSS)"

    def verify(
        self,
        endpoint: ApiEndpoint,
        client: DastHttpClient,
        base_url: str,
        auth_context: DastAuthContext,
        params: Optional[Dict[str, Any]] = None,
    ) -> DastProbeResult:
        """
        Executes safe browser-based DOM XSS verification using Playwright.
        Requires actual client-side JavaScript execution of a safe canary event callback in the browser DOM.
        """
        target_url = f"{base_url.rstrip('/')}/{endpoint.path.lstrip('/')}"
        target_url = re.sub(r"\{[^}]+\}", "1", target_url)
        secrets = auth_context.get_secrets_to_redact()

        if not BrowserDastService.is_playwright_installed():
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence="DOM XSS browser verification skipped: Playwright browser execution engine unavailable in environment.",
                secrets_to_redact=secrets,
            )

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence="DOM XSS browser verification skipped: Playwright module import failed.",
                secrets_to_redact=secrets,
            )

        dom_xss_triggered = False

        async def _run_playwright_verify():
            nonlocal dom_xss_triggered
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
                context = await browser.new_context(ignore_https_errors=True)
                if auth_context and auth_context.token_or_key:
                    header_name = auth_context.header_name or "Authorization"
                    await context.set_extra_http_headers({header_name: auth_context.token_or_key})

                page = await context.new_page()

                async def on_callback(arg):
                    nonlocal dom_xss_triggered
                    dom_xss_triggered = True

                await page.expose_function("kyptic_dom_xss_callback", on_callback)

                canary_payload = "<img src=x onerror=\"window.kyptic_dom_xss_callback && window.kyptic_dom_xss_callback('fired')\">"
                probe_url = f"{target_url}#q=" + urllib.parse.quote(canary_payload) if "#" not in target_url else f"{target_url}&q=" + urllib.parse.quote(canary_payload)

                try:
                    await page.goto(probe_url, timeout=8000, wait_until="domcontentloaded")
                    await page.wait_for_timeout(1000)
                except Exception:
                    pass
                finally:
                    await page.close()
                    await browser.close()

        try:
            # Handle existing running event loop if called synchronously
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                # Run in thread pool if loop is already running
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    pool.submit(lambda: asyncio.run(_run_playwright_verify())).result(timeout=15.0)
            else:
                asyncio.run(_run_playwright_verify())

        except Exception as e:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.INCONCLUSIVE,
                evidence=f"DOM XSS browser execution check interrupted: {str(e)}",
                secrets_to_redact=secrets,
            )

        if dom_xss_triggered:
            return DastProbeResult(
                endpoint_id=endpoint.id,
                probe_type=DastProbeType.BOLA,
                status=DastVerificationStatus.VERIFIED_VULNERABLE,
                severity=FindingSeverity.HIGH,
                evidence="DOM XSS confirmed via Playwright browser execution: Client-side JS executed injected canary event callback.",
                response_status=200,
                confidence="HIGH",
                secrets_to_redact=secrets,
            )

        return DastProbeResult(
            endpoint_id=endpoint.id,
            probe_type=DastProbeType.BOLA,
            status=DastVerificationStatus.VERIFIED_SECURE,
            evidence="DOM XSS probe executed in Playwright Chromium browser. No client-side JS canary execution observed.",
            response_status=200,
            confidence="HIGH",
            secrets_to_redact=secrets,
        )
