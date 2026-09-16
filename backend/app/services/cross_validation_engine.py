from typing import Dict, List, Set, Tuple
from sqlalchemy.orm import Session

from app.models.finding import Finding, FindingSource


def normalize_endpoint_path(path: str) -> Tuple[str, str]:
    """
    Normalizes a file_path or endpoint string into (http_method, clean_path).
    Examples:
        "GET /users/{userId}" -> ("GET", "/users/{param}")
        "POST /api/v1/billing/123" -> ("POST", "/api/v1/billing/{param}")
        "/api/v1/users" -> ("ALL", "/api/v1/users")
        "controllers/authController.js" -> ("FILE", "controllers/authController.js")
    """
    if not path:
        return ("ALL", "")

    s = path.strip()
    method = "ALL"

    # Extract leading HTTP method if present
    parts = s.split(" ", 1)
    if len(parts) == 2 and parts[0].upper() in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
        method = parts[0].upper()
        s = parts[1].strip()

    # Parameterize dynamic path segments like IDs or UUIDs
    path_segments = s.split("/")
    norm_segments = []
    for seg in path_segments:
        if not seg:
            norm_segments.append(seg)
            continue
        if seg.startswith("{") and seg.endswith("}"):
            norm_segments.append("{param}")
        elif seg.startswith(":") and len(seg) > 1:
            norm_segments.append("{param}")
        elif seg.isdigit():
            norm_segments.append("{param}")
        elif len(seg) == 36 and seg.count("-") == 4:  # UUID check
            norm_segments.append("{param}")
        else:
            norm_segments.append(seg)

    clean_path = "/".join(norm_segments)
    return (method, clean_path)


def are_categories_compatible(cat1: str, title1: str, cat2: str, title2: str) -> bool:
    """
    Determines if two findings share a compatible vulnerability type or category.
    Prevents false correlation between unrelated issues on the same route.
    """
    c1 = ((cat1 or "") + " " + (title1 or "")).upper()
    c2 = ((cat2 or "") + " " + (title2 or "")).upper()

    # Specific injection checks to prevent SQLi / XSS / Command Injection cross-mixing
    sqli_terms = {"SQL INJECTION", "SQLI", "CWE-89"}
    xss_terms = {"XSS", "CROSS-SITE SCRIPTING", "CWE-79"}
    cmdi_terms = {"COMMAND INJECTION", "OS COMMAND", "CWE-78"}

    c1_is_sqli = any(t in c1 for t in sqli_terms)
    c2_is_sqli = any(t in c2 for t in sqli_terms)
    if c1_is_sqli or c2_is_sqli:
        return c1_is_sqli and c2_is_sqli

    c1_is_xss = any(t in c1 for t in xss_terms)
    c2_is_xss = any(t in c2 for t in xss_terms)
    if c1_is_xss or c2_is_xss:
        return c1_is_xss and c2_is_xss

    c1_is_cmdi = any(t in c1 for t in cmdi_terms)
    c2_is_cmdi = any(t in c2 for t in cmdi_terms)
    if c1_is_cmdi or c2_is_cmdi:
        return c1_is_cmdi and c2_is_cmdi

    families = [
        {"BOLA", "IDOR", "OBJECT LEVEL AUTHORIZATION", "AUTHORIZATION GAP", "API1"},
        {"SENSITIVE DATA", "DATA EXPOSURE", "CREDENTIAL", "SECRET", "PROPERTY LEVEL AUTHORIZATION", "API3"},
        {"AUTHENTICATION", "JWT", "SESSION", "CREDENTIALS", "BROKEN AUTH", "API2"},
        {"MASS ASSIGNMENT", "PROPERTY INJECTION", "SUSPICIOUS PROPERTIES", "API6"},
        {"RATE LIMIT", "RESOURCE CONSUMPTION", "THROTTLING", "UNRESTRICTED ACCESS", "API4"},
        {"SECURITY HEADER", "MISSING HEADER", "CORS", "MISCONFIGURATION", "TLS", "HTTPS", "API8"},
        {"DEPENDENCY", "SCA", "CVE", "VULNERABLE COMPONENT"},
    ]

    for fam in families:
        match1 = any(term in c1 for term in fam)
        match2 = any(term in c2 for term in fam)
        if match1 and match2:
            return True

    # Exact string match fallback if non-empty
    if cat1 and cat2 and cat1.strip().lower() == cat2.strip().lower():
        return True

    return False


def are_endpoints_compatible(method1: str, path1: str, method2: str, path2: str) -> bool:
    """
    Strict endpoint compatibility check.
    HTTP methods must match (unless one is 'ALL').
    Paths must match identically for API routes, or match controller-to-route semantics.
    """
    if method1 != "ALL" and method2 != "ALL" and method1 != method2:
        return False

    if not path1 or not path2:
        return False

    if path1 == path2:
        return True

    # File vs API Route semantic matching
    is_file1 = not path1.startswith("/") and "." in path1
    is_file2 = not path2.startswith("/") and "." in path2

    if is_file1 and not is_file2:
        file_base = path1.split("/")[-1].split(".")[0].lower().replace("controller", "").replace("handler", "").replace("router", "")
        if len(file_base) >= 3 and file_base in path2.lower():
            return True
    elif is_file2 and not is_file1:
        file_base = path2.split("/")[-1].split(".")[0].lower().replace("controller", "").replace("handler", "").replace("router", "")
        if len(file_base) >= 3 and file_base in path1.lower():
            return True

    return False


class CrossValidationEngine:
    """
    Deterministic Cross-Validation & Confidence Engine for Kyptic Platform.
    Evaluates normalized findings across multi-engine security scans (SAST, Secrets, SCA, API Security, Web/API DAST),
    identifies corroborated evidence, assigns bounded confidence scores (0-100), determines verification statuses,
    and generates human-readable explanations without LLM dependencies.
    """

    def __init__(self, db: Session | None = None):
        self.db = db

    def process_findings(
        self,
        project_id: int,
        scan_id: int,
        findings: List[Finding],
        dast_status: str | None = None,
        sca_status: str | None = None,
    ) -> List[Finding]:
        """
        Cross-validates a list of normalized findings for a scan, setting:
        - correlation_count
        - correlated_finding_ids
        - evidence_sources
        - confidence_score
        - confidence_level
        - verification_status
        - verification_explanation
        """
        if not findings:
            return []

        # Step 1: Pre-index findings
        indexed_findings = []
        for idx, f in enumerate(findings):
            m, p = normalize_endpoint_path(f.file_path)
            source_str = str(f.source.value if hasattr(f.source, "value") else f.source).lower()
            scanner_str = (f.scanner_name or source_str).lower()
            indexed_findings.append({
                "index": idx,
                "finding": f,
                "method": m,
                "path": p,
                "source": source_str,
                "scanner": scanner_str,
                "fingerprint": f.fingerprint or f"tmp_fp_{idx}",
                "category": f.category,
                "title": f.title,
                "cwe": (f.cwe or "").strip(),
                "owasp": (f.owasp or "").strip(),
            })

        # Step 2: Determine pairwise correlations
        correlations: Dict[int, List[int]] = {i: [] for i in range(len(findings))}

        for i in range(len(indexed_findings)):
            item_a = indexed_findings[i]

            for j in range(i + 1, len(indexed_findings)):
                item_b = indexed_findings[j]

                is_correlated = False

                # Criterion A: Exact Fingerprint Match
                if item_a["fingerprint"] and item_b["fingerprint"] and item_a["fingerprint"] == item_b["fingerprint"]:
                    is_correlated = True
                else:
                    # Criterion B: Compatible Vulnerability + Compatible Endpoint
                    cat_compat = are_categories_compatible(
                        item_a["category"], item_a["title"], item_b["category"], item_b["title"]
                    )
                    if cat_compat:
                        endpoint_compat = are_endpoints_compatible(
                            item_a["method"], item_a["path"], item_b["method"], item_b["path"]
                        )
                        if endpoint_compat:
                            is_correlated = True

                if is_correlated:
                    correlations[i].append(j)
                    correlations[j].append(i)

        # Step 3: Compute Confidence, Verification Status & Explanations per finding
        dast_failed = dast_status in {"FAILED", "SCANNER_ERROR"}
        dast_unavailable = dast_status in {"SKIPPED_SSRF_BLOCKED", "SKIPPED_NO_TARGET"}
        dast_untested = dast_status in {"UNTESTED", None}

        for i, item in enumerate(indexed_findings):
            f = item["finding"]
            corr_indices = correlations[i]
            correlated_items = [indexed_findings[ci] for ci in corr_indices]

            # 3a. Exclude self and duplicates in correlation count & IDs
            corr_fingerprints = []
            for ci in correlated_items:
                fp = ci["fingerprint"]
                if fp and fp != item["fingerprint"] and fp not in corr_fingerprints:
                    corr_fingerprints.append(fp)

            f.correlation_count = len(corr_fingerprints)
            f.correlated_finding_ids = ",".join(corr_fingerprints) if corr_fingerprints else None

            # 3b. Evidence sources formatting
            sources_set: Set[str] = set()

            def format_source_name(src_str: str, scn_str: str) -> str:
                if scn_str == "dast-active-probe":
                    return "API DAST Probe"
                if scn_str == "dast-web" or src_str == "dast":
                    return "Web DAST"
                if src_str == "api_security" or scn_str == "api-security":
                    return "API Security"
                if src_str == "sast" or scn_str == "semgrep":
                    return "SAST"
                if src_str == "secrets" or scn_str == "detect-secrets":
                    return "Secrets"
                if src_str == "sca" or scn_str == "sca-dependency":
                    return "SCA"
                return src_str.upper()

            sources_set.add(format_source_name(item["source"], item["scanner"]))
            for ci in correlated_items:
                sources_set.add(format_source_name(ci["source"], ci["scanner"]))

            sources_list = sorted(list(sources_set))
            evidence_sources_str = ", ".join(sources_list)
            f.evidence_sources = evidence_sources_str

            # 3c. Classification of Scanner Types
            is_active_dast_probe = item["scanner"] == "dast-active-probe"
            is_generic_web_dast = (item["source"] == "dast" or item["scanner"] == "dast-web") and not is_active_dast_probe
            is_static = item["source"] in {"sast", "secrets", "sca", "api_security"}
            is_static_only_type = item["source"] in {"secrets", "sca"}  # Dynamic probing not applicable

            has_active_dast_corroboration = any(ci["scanner"] == "dast-active-probe" for ci in correlated_items)
            has_independent_static_corroboration = any(
                ci["source"] in {"sast", "secrets", "sca", "api_security"} and ci["scanner"] != item["scanner"]
                for ci in correlated_items
            )
            has_same_scanner_corroboration = any(
                ci["scanner"] == item["scanner"] and ci["fingerprint"] != item["fingerprint"]
                for ci in correlated_items
            )

            # 3d. Base Confidence Score
            if is_active_dast_probe:
                base_score = 85
            elif is_generic_web_dast:
                base_score = 70
            elif item["source"] == "api_security":
                base_score = 65
            elif item["source"] in {"sast", "secrets", "sca"}:
                base_score = 60
            else:
                base_score = 50

            # 3e. Corroboration Bonuses
            bonus = 0
            if is_static and has_active_dast_corroboration:
                bonus += 25  # Strong Static + Active Dynamic Probe Corroboration!
            elif is_active_dast_probe and has_independent_static_corroboration:
                bonus += 10  # Active Probe corroborated static finding
            elif has_independent_static_corroboration:
                bonus += 15  # Multi-engine independent static corroboration
            elif has_same_scanner_corroboration:
                bonus += 5   # Rule correlation from same scanner engine

            # Snippet presence
            if f.code_snippet and len(f.code_snippet.strip()) > 10:
                bonus += 5

            calc_score = base_score + bonus

            # Penalties if DAST attempted but failed
            if is_static and not is_static_only_type and dast_failed:
                calc_score -= 5

            final_score = max(0, min(100, int(calc_score)))
            f.confidence_score = final_score

            # 3f. Confidence Level mapping
            if final_score >= 80:
                f.confidence_level = "HIGH"
            elif final_score >= 50:
                f.confidence_level = "MEDIUM"
            else:
                f.confidence_level = "LOW"

            # 3g. Verification Status determination
            if is_active_dast_probe or (is_static and has_active_dast_corroboration):
                f.verification_status = "VERIFIED"
            elif len(correlated_items) > 0 and (has_independent_static_corroboration or is_generic_web_dast):
                f.verification_status = "CORROBORATED"
            elif is_static and not is_static_only_type and dast_failed:
                f.verification_status = "INCONCLUSIVE"
            else:
                f.verification_status = "UNVERIFIED"

            # 3h. Generate Deterministic & Precise Explanation
            explanation_parts = []
            if f.verification_status == "VERIFIED":
                if is_active_dast_probe:
                    explanation_parts.append(f"High confidence ({final_score}/100): Direct active HTTP probe confirmed runtime vulnerability proof on target endpoint.")
                else:
                    explanation_parts.append(f"High confidence ({final_score}/100): Static analysis finding on {f.file_path} was confirmed by matching active API DAST runtime evidence ({evidence_sources_str}).")
            elif f.verification_status == "CORROBORATED":
                explanation_parts.append(f"{f.confidence_level.capitalize()} confidence ({final_score}/100): Independently corroborated by multiple security engines ({evidence_sources_str}) for the same vulnerability category.")
            elif f.verification_status == "INCONCLUSIVE":
                explanation_parts.append(f"Inconclusive ({final_score}/100): Static analysis identified potential weakness ({evidence_sources_str}), but dynamic verification was attempted and failed during scan execution.")
            else:  # UNVERIFIED
                if is_static_only_type:
                    explanation_parts.append(f"{f.confidence_level.capitalize()} confidence ({final_score}/100): Detected by static analysis ({evidence_sources_str}). Dynamic HTTP probing is not applicable for this vulnerability type.")
                elif dast_unavailable:
                    explanation_parts.append(f"{f.confidence_level.capitalize()} confidence ({final_score}/100): Detected by static analysis ({evidence_sources_str}). Dynamic verification was unavailable (target unconfigured or SSRF protection blocked reachability).")
                elif dast_untested:
                    explanation_parts.append(f"{f.confidence_level.capitalize()} confidence ({final_score}/100): Detected by a single scanner ({evidence_sources_str}). Dynamic corroboration has not been performed.")
                else:
                    explanation_parts.append(f"{f.confidence_level.capitalize()} confidence ({final_score}/100): Detected by a single scanner ({evidence_sources_str}) without independent corroborating evidence.")

            f.verification_explanation = " ".join(explanation_parts)

        return findings
