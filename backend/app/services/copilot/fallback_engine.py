from typing import Optional
from app.models.finding import Finding
from app.schemas.copilot import CopilotCodeBlock


DETERMINISTIC_REMEDIATION_MAP = {
    "CWE-89": (
        "SQL Injection",
        "Use parameterized queries (prepared statements) or ORM parameter bindings. Never concatenate un-sanitized user inputs into SQL strings.",
        "SELECT * FROM users WHERE username = ? AND password = ?",
    ),
    "CWE-79": (
        "Cross-Site Scripting (XSS)",
        "Encode output based on context (HTML, attribute, JavaScript) using context-aware escaping libraries or standard template engines.",
        "const safeOutput = DOMPurify.sanitize(userInput);",
    ),
    "CWE-639": (
        "Broken Object Level Authorization (BOLA)",
        "Enforce authorization checks on every resource request. Ensure the authenticated user identity matches requested resource tenant/owner ID.",
        "if (resource.userId !== currentUser.id) { throw new UnauthorizedException(); }",
    ),
    "CWE-307": (
        "Improper Restriction of Excessive Authentication Attempts",
        "Implement rate limiting per IP and account identifier using Redis token buckets or gateway throttles.",
        "const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });",
    ),
    "CWE-287": (
        "Improper Authentication",
        "Validate authentication tokens (JWTs, session tokens) on every protected endpoint and enforce strong signature algorithms.",
        "const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });",
    ),
    "CWE-915": (
        "Improper Dynamic Direct Object References (Mass Assignment)",
        "Use strict schema DTO validation and whitelist allowed request body attributes before database persistence.",
        "const safeData = pick(req.body, ['name', 'email']);",
    ),
}


class FallbackEngine:
    """Generates static deterministic advisories when LLM providers are unavailable."""

    @classmethod
    def generate_advisory(cls, finding: Optional[Finding], user_message: str) -> tuple[str, Optional[CopilotCodeBlock]]:
        if not finding:
            msg = (
                "### Security Advisory (Copilot Fallback Mode)\n\n"
                "The Copilot AI engine is currently unavailable or operating offline.\n\n"
                "**General Security Guidance**:\n"
                "1. Always validate and sanitize all external inputs.\n"
                "2. Enforce strict authentication and authorization checks at API gateways.\n"
                "3. Apply defense-in-depth principles across data access and dependency management.\n\n"
                "*Note: Deterministic security guidance shown above.*"
            )
            return msg, None

        cwe_key = finding.cwe or "CWE-GENERAL"
        matched = DETERMINISTIC_REMEDIATION_MAP.get(cwe_key)

        title = finding.title
        severity = (finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)).upper()
        cwe_str = finding.cwe or "N/A"
        owasp_str = finding.owasp or "N/A"
        status_str = finding.verification_status
        confidence_str = f"{finding.confidence_score}%"

        if matched:
            vuln_name, strategy, code_fix = matched
            code_block = CopilotCodeBlock(
                file=finding.file_path or "remediation_patch",
                code=code_fix,
                lang="javascript" if finding.file_path and finding.file_path.endswith(".js") else "code",
            )
        else:
            strategy = "Review file context and ensure input validation, explicit authorization, and safe API patterns."
            code_block = None

        content = (
            f"### Security Advisory (Copilot Fallback Mode)\n\n"
            f"**Finding**: {title}\n"
            f"**Severity**: {severity} | **Confidence**: {confidence_str} | **Status**: {status_str}\n"
            f"**CWE**: {cwe_str} | **OWASP**: {owasp_str}\n\n"
            f"**Deterministic Remediation Strategy**:\n"
            f"{strategy}\n\n"
            f"**Location**: `{finding.file_path}` (Line {finding.line_number or 'N/A'})\n\n"
            f"*Note: Copilot LLM provider is unavailable. Authoritative scanner finding results are displayed using static remediation rules.*"
        )

        return content, code_block
