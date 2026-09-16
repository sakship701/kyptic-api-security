from typing import Dict, List, Optional


class FrameworkControlDefinition:
    def __init__(
        self,
        control_id: str,
        control_name: str,
        framework: str,
        description: str,
        cwes: List[str],
        owasps: List[str],
        remediation_reference: str,
    ) -> None:
        self.control_id = control_id
        self.control_name = control_name
        self.framework = framework
        self.description = description
        self.cwes = cwes
        self.owasps = owasps
        self.remediation_reference = remediation_reference


class ComplianceRegistry:
    FRAMEWORKS = {
        "OWASP_API_TOP_10": "OWASP API Security Top 10 (2023)",
        "OWASP_TOP_10": "OWASP Web Security Top 10 (2021)",
        "PCI_DSS": "PCI DSS v4.0 Security Controls",
        "SOC_2": "SOC 2 Type II Trust Services Criteria",
        "ISO_27001": "ISO/IEC 27001:2022 Information Security Controls",
        "CWE": "Common Weakness Enumeration Taxonomy",
    }

    CONTROLS: List[FrameworkControlDefinition] = [
        # PCI DSS v4.0 Controls
        FrameworkControlDefinition(
            control_id="PCI-6.2.4",
            control_name="Software Engineering & Injection Defense",
            framework="PCI_DSS",
            description="Prevent software vulnerabilities including SQL injection, command injection, and script injection in web applications.",
            cwes=["CWE-89", "CWE-78", "CWE-79", "CWE-94"],
            owasps=["A03:2021", "API3:2023"],
            remediation_reference="Use parameterized SQL queries, context-aware encoding, and strict input validation schemas.",
        ),
        FrameworkControlDefinition(
            control_id="PCI-6.4.1",
            control_name="Public Facing Web Application Protection",
            framework="PCI_DSS",
            description="Protect web endpoints against automated attacks, broken authorization, and data tampering.",
            cwes=["CWE-639", "CWE-284", "CWE-285", "CWE-915"],
            owasps=["API1:2023", "API5:2023", "A01:2021"],
            remediation_reference="Enforce object-level access control checks on every API request endpoint.",
        ),
        FrameworkControlDefinition(
            control_id="PCI-8.2.1",
            control_name="Strong Authentication Management",
            framework="PCI_DSS",
            description="Enforce strong user authentication, session token protection, and cryptographic algorithm checks.",
            cwes=["CWE-287", "CWE-307", "CWE-327", "CWE-798"],
            owasps=["API2:2023", "A07:2021", "A02:2021"],
            remediation_reference="Implement strong JWT algorithms (HS256/RS256), eliminate hardcoded secrets, and throttle failed login attempts.",
        ),

        # SOC 2 Type II Controls
        FrameworkControlDefinition(
            control_id="SOC2-CC6.1",
            control_name="Access Logical Control & Authorization",
            framework="SOC_2",
            description="Logical access controls prevent unauthorized access to data, systems, and user APIs.",
            cwes=["CWE-639", "CWE-284", "CWE-287", "CWE-862"],
            owasps=["API1:2023", "API5:2023", "A01:2021"],
            remediation_reference="Enforce tenant-based data isolation and role-based access control (RBAC).",
        ),
        FrameworkControlDefinition(
            control_id="SOC2-CC6.6",
            control_name="Boundary Defense & Application Throttling",
            framework="SOC_2",
            description="Boundaries and API rate limits prevent denial of service and resource exhaustion.",
            cwes=["CWE-307", "CWE-400", "CWE-770"],
            owasps=["API4:2023", "A05:2021"],
            remediation_reference="Configure Redis rate limiters and gateway request quotas across public API routes.",
        ),
        FrameworkControlDefinition(
            control_id="SOC2-CC7.1",
            control_name="Vulnerability Monitoring & Patch Management",
            framework="SOC_2",
            description="Identify, categorize, and remediate application vulnerabilities and vulnerable software components.",
            cwes=["CWE-1104", "CWE-937"],
            owasps=["A06:2021", "API6:2023"],
            remediation_reference="Maintain automated SAST/DAST/SCA scanning pipelines and patch high-severity CVE dependencies.",
        ),

        # ISO/IEC 27001:2022 Controls
        FrameworkControlDefinition(
            control_id="ISO-A.8.8",
            control_name="Management of Technical Vulnerabilities",
            framework="ISO_27001",
            description="Information about technical vulnerabilities of information systems in use shall be obtained and evaluated.",
            cwes=["CWE-89", "CWE-78", "CWE-79", "CWE-639", "CWE-287"],
            owasps=["A03:2021", "A06:2021", "API1:2023"],
            remediation_reference="Run continuous automated security scans and maintain authoritative triage records.",
        ),
        FrameworkControlDefinition(
            control_id="ISO-A.8.24",
            control_name="Use of Cryptography",
            framework="ISO_27001",
            description="Rules for the effective use of cryptography, including key management, shall be defined and implemented.",
            cwes=["CWE-327", "CWE-798", "CWE-311"],
            owasps=["A02:2021", "API2:2023"],
            remediation_reference="Use standard TLS 1.3 encryption and secure secret vaults for API keys.",
        ),
        FrameworkControlDefinition(
            control_id="ISO-A.8.28",
            control_name="Secure Coding Principles",
            framework="ISO_27001",
            description="Secure coding principles shall be applied to software development.",
            cwes=["CWE-89", "CWE-79", "CWE-915", "CWE-502"],
            owasps=["A03:2021", "A08:2021", "API6:2023"],
            remediation_reference="Adopt safe query parameterization, strict DTO schemas, and input validation bounds.",
        ),

        # OWASP API Security Top 10 (2023)
        FrameworkControlDefinition(
            control_id="API1:2023",
            control_name="Broken Object Level Authorization (BOLA)",
            framework="OWASP_API_TOP_10",
            description="APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface for level access control issues.",
            cwes=["CWE-639", "CWE-284"],
            owasps=["API1:2023"],
            remediation_reference="Validate that the requesting user owns the requested object ID.",
        ),
        FrameworkControlDefinition(
            control_id="API2:2023",
            control_name="Broken Authentication",
            framework="OWASP_API_TOP_10",
            description="Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens.",
            cwes=["CWE-287", "CWE-307", "CWE-798"],
            owasps=["API2:2023"],
            remediation_reference="Enforce robust authentication checks and secure token verification.",
        ),
        FrameworkControlDefinition(
            control_id="API3:2023",
            control_name="Broken Object Property Level Authorization",
            framework="OWASP_API_TOP_10",
            description="Lack of validation at the property level leads to sensitive data exposure or mass assignment.",
            cwes=["CWE-915", "CWE-213"],
            owasps=["API3:2023", "API6:2023"],
            remediation_reference="Whitelist allowed parameters and sanitize property response schemas.",
        ),
        FrameworkControlDefinition(
            control_id="API4:2023",
            control_name="Unrestricted Resource Consumption",
            framework="OWASP_API_TOP_10",
            description="Exploitation of missing rate limits or payload size limits causes resource exhaustion.",
            cwes=["CWE-307", "CWE-400"],
            owasps=["API4:2023"],
            remediation_reference="Implement rate limiting and request payload limits.",
        ),

        # OWASP Web Security Top 10 (2021)
        FrameworkControlDefinition(
            control_id="A01:2021",
            control_name="Broken Access Control",
            framework="OWASP_TOP_10",
            description="Failures allow unauthorized disclosure, modification, or destruction of data outside user permissions.",
            cwes=["CWE-639", "CWE-284", "CWE-285"],
            owasps=["A01:2021"],
            remediation_reference="Enforce strict server-side access control checks.",
        ),
        FrameworkControlDefinition(
            control_id="A03:2021",
            control_name="Injection",
            framework="OWASP_TOP_10",
            description="User-supplied data is not sanitized, filtered, or evaluated by the application.",
            cwes=["CWE-89", "CWE-78", "CWE-79"],
            owasps=["A03:2021"],
            remediation_reference="Use parameterized queries and safe API frameworks.",
        ),
    ]

    @classmethod
    def get_controls_for_framework(cls, framework: str) -> List[FrameworkControlDefinition]:
        target = framework.upper()
        return [c for c in cls.CONTROLS if c.framework == target]
