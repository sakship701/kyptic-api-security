# Kyptic Browser-Based DAST Engine (Playwright Integration)

Kyptic includes a production-grade **Browser-Based DAST Execution Engine** powered by Playwright and headless Chromium. This document outlines the architecture, setup, crawling rules, DOM XSS browser execution verifier, safety controls, and execution limits.

---

## 1. Architecture Overview

While HTTP DAST (`dast_scanner.py`) operates as a fast, stateless HTTP client using `httpx`/`urllib`, **Browser DAST (`browser_dast_service.py`)** launches a real headless Chromium browser instance via Playwright to:

- Render dynamic Single-Page Applications (React, Angular, Vue, Next.js).
- Execute client-side JavaScript.
- Discover DOM event listeners and client-side SPA routes (`data-route`, `routerlink`).
- Perform non-destructive DOM form element discovery (`input`, `textarea`, `select`, `button`).
- Verify DOM-based Cross-Site Scripting (DOM XSS) through deterministic browser event callbacks.

```text
HTTP DAST (httpx)  ──┐
                     ├──► Unified Normalization ──► Deduplication ──► Phase 2 Cross-Validation ──► Finding
Browser DAST (Chromium) ┘
```

---

## 2. Playwright Installation & Setup

Playwright is included as an optional backend dependency in `backend/requirements.txt`:

```bash
pip install playwright>=1.40.0
playwright install chromium
```

### Graceful Fallback Strategy
If Playwright or the Chromium binary is not installed in the execution environment, the Kyptic Orchestrator:
1. Logs a clean warning (`Browser DAST skipped: Playwright engine unavailable`).
2. Marks the Browser DAST stage as `SKIPPED_BROWSER_UNAVAILABLE`.
3. Permits the HTTP DAST, SAST, SCA, and API Security scans to complete successfully without throwing exceptions or failing the overall scan.

---

## 3. Crawling & Resource Safety Controls

To run safely on developer workstations and production test environments, Browser DAST enforces strict resource boundaries:

| Resource Guard | Default Setting | Purpose |
| :--- | :--- | :--- |
| **Same-Origin Constraint** | Strictly Enforced | Blocks off-target navigation & cross-origin link crawling. |
| **SSRF Safety Guard** | `is_ssrf_safe_url` | Prevents browser navigation to private/loopback IP ranges (`10.0.0.0/8`, `127.0.0.1`, `169.254.169.254`). |
| **Max Crawl Pages** | `15 pages` | Caps the number of visited URLs per scan job. |
| **Max Crawl Depth** | `2 levels` | Limits link depth recursion. |
| **Page Load Timeout** | `10,000 ms` | Aborts slow/hanging page loads gracefully. |
| **Total Task Timeout** | `30 seconds` | Ensures strict job execution bounds. |

---

## 4. Deterministic DOM XSS Execution Verifier

Kyptic enforces **Reflection is NOT Execution**. Simple string reflection of a marker in DOM text does **NOT** produce a `CONFIRMED` finding.

### Verification Mechanism:
1. The engine registers a browser callback function (`kyptic_dom_xss_callback`) inside the Playwright Chromium context using `page.expose_function`.
2. A harmless canary payload is injected into the URL fragment / parameter:
   ```html
   <img src=x onerror="window.kyptic_dom_xss_callback && window.kyptic_dom_xss_callback('fired')">
   ```
3. The Playwright browser navigates to the probe URL and waits for DOM JavaScript execution.
4. **Result Classification**:
   - `VERIFIED_VULNERABLE` (CONFIRMED): Triggered **ONLY** if the browser client-side JavaScript engine actually invokes `kyptic_dom_xss_callback` in DOM context.
   - `VERIFIED_SECURE` (NOT CONFIRMED): Input string is reflected as harmless text or escaped without JS execution.
   - `INCONCLUSIVE`: Page load timeout or browser launch interruption.

---

## 5. Security & Authentication Controls

- **Secret Redaction**: All cookies, bearer tokens, and credentials passed via `DastAuthContext` are automatically redacted from evidence snippets via `redact_secrets`.
- **Form Safety**: Form elements are discovered and inventoried for audit, but forms are **NEVER** submitted automatically to prevent unintended state mutation.
- **Process Lifecycle Safety**: All browser contexts and Chromium instances are wrapped in `try...finally` blocks to guarantee process termination upon completion or timeout.
