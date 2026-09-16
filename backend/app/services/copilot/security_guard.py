import re


class SecurityGuard:
    """
    Handles secret redaction and prompt injection containment
    before content reaches the LLM provider.
    """

    # Secret redaction regular expression rules
    SECRET_PATTERNS = [
        # AWS Access Key ID
        (re.compile(r'\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b'), '[REDACTED_AWS_KEY]'),
        # AWS Secret Key / Generic Base64 Secret
        (re.compile(r'(?i)(aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'), r'\1: "[REDACTED_SECRET]"'),
        # Generic API Key / Token assignments
        (re.compile(r'(?i)(api[_-]?key|access[_-]?token|bearer[_-]?token|auth[_-]?token|private[_-]?key)\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{12,})["\']?'), r'\1: "[REDACTED_SECRET]"'),
        # Bearer / JWT Tokens in Headers or Strings
        (re.compile(r'(?i)bearer\s+(ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'), 'Bearer [REDACTED_JWT]'),
        # GitHub Personal Access Tokens
        (re.compile(r'\b(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b'), '[REDACTED_GITHUB_TOKEN]'),
        # Slack Tokens
        (re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9a-zA-Z]{24}'), '[REDACTED_SLACK_TOKEN]'),
        # Database URIs / Connection Strings
        (re.compile(r'(?i)(postgres|mysql|mongodb|redis|sqlite):\/\/[^:\s]+:([^@\s]+)@'), r'\1://[REDACTED_USER]:[REDACTED_PASSWORD]@'),
        # Private Keys
        (re.compile(r'-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PRIVATE)\s+KEY-----[\s\S]+?-----END\s+\1\s+KEY-----'), '[REDACTED_PRIVATE_KEY]'),
    ]

    @classmethod
    def redact_secrets(cls, text: str | None) -> str:
        """Scan text and replace sensitive credentials with redaction markers."""
        if not text:
            return ""
        sanitized = text
        for pattern, replacement in cls.SECRET_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized

    @classmethod
    def wrap_untrusted_data(cls, tag_name: str, content: str | None, max_chars: int = 4000) -> str:
        """
        Enclose untrusted user inputs/code/evidence in explicit XML data tags,
        escaping nested closing tags to prevent delimiter-hijacking prompt injection.
        """
        if not content:
            return f"<{tag_name}>\n[NO_DATA_PROVIDED]\n</{tag_name}>"

        redacted = cls.redact_secrets(content)
        # Escape any attempts to break out of the tag structure
        safe_content = redacted.replace(f"</{tag_name}>", f"&lt;/{tag_name}&gt;")

        if len(safe_content) > max_chars:
            safe_content = safe_content[:max_chars] + "\n...[TRUNCATED_FOR_CONTEXT_LIMIT]"

        return f"<{tag_name}>\n{safe_content}\n</{tag_name}>"
