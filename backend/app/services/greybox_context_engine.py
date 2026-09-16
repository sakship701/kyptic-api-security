import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
from sqlalchemy.orm import Session

from app.models.api_endpoint import ApiEndpoint
from app.models.finding import Finding
from app.services.cross_validation_engine import are_categories_compatible, normalize_endpoint_path


@dataclass
class GreyBoxContext:
    finding_id: Optional[int]
    project_id: int
    endpoint_id: Optional[int]
    target_url: Optional[str]
    http_method: str
    path: str
    vulnerability_family: str
    recommended_probe_types: List[str]
    source_file: Optional[str]
    source_line: Optional[int]
    priority_score: int
    priority_level: str
    mapping_confidence: str
    context_reason: str

    def to_dict(self) -> Dict:
        return {
            "finding_id": self.finding_id,
            "project_id": self.project_id,
            "endpoint_id": self.endpoint_id,
            "target_url": self.target_url,
            "http_method": self.http_method,
            "path": self.path,
            "vulnerability_family": self.vulnerability_family,
            "recommended_probe_types": self.recommended_probe_types,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "priority_score": self.priority_score,
            "priority_level": self.priority_level,
            "mapping_confidence": self.mapping_confidence,
            "context_reason": self.context_reason,
        }


def extract_explicit_route_from_code(snippet: str) -> Optional[Tuple[str, str]]:
    """
    Parses code snippet or text for explicit web framework route annotations.
    Examples:
        @app.get("/users/{id}") -> ("GET", "/users/{id}")
        router.post('/api/login') -> ("POST", "/api/login")
        @GetMapping("/users/{id}") -> ("GET", "/users/{id}")
    """
    if not snippet:
        return None

    # Python / FastAPI / Flask patterns
    match_py = re.search(r"@(?:app|router|api)\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]", snippet, re.IGNORECASE)
    if match_py:
        return (match_py.group(1).upper(), match_py.group(2))

    # Express / JS router patterns
    match_js = re.search(r"(?:router|app)\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]", snippet, re.IGNORECASE)
    if match_js:
        return (match_js.group(1).upper(), match_js.group(2))

    # Java Spring Web annotations
    match_java = re.search(r"@(Get|Post|Put|Delete|Patch|Request)Mapping\(\s*(?:value\s*=\s*)?['\"]([^'\"]+)['\"]", snippet, re.IGNORECASE)
    if match_java:
        m = match_java.group(1).upper()
        if m == "REQUEST":
            m = "ALL"
        return (m, match_java.group(2))

    # Standard HTTP method + path pattern
    match_http = re.search(r"\b(GET|POST|PUT|DELETE|PATCH)\s+(/[a-zA-Z0-9_\-/{}:]+)", snippet)
    if match_http:
        return (match_http.group(1).upper(), match_http.group(2))

    return None


def classify_vulnerability_family(category: str, title: str) -> str:
    """Classifies finding category/title into vulnerability family."""
    t = ((category or "") + " " + (title or "")).upper()
    if "BOLA" in t or "IDOR" in t or "OBJECT LEVEL AUTHORIZATION" in t or "API1" in t:
        return "BOLA"
    if "AUTH" in t or "JWT" in t or "SESSION" in t or "CREDENTIAL" in t or "API2" in t:
        return "AUTH"
    if "MASS ASSIGNMENT" in t or "PROPERTY INJECTION" in t or "API6" in t:
        return "MASS_ASSIGNMENT"
    if "RATE LIMIT" in t or "RESOURCE CONSUMPTION" in t or "THROTTLING" in t or "API4" in t:
        return "RATE_LIMITING"
    if "SQL INJECTION" in t or "SQLI" in t or "CWE-89" in t:
        return "SQL_INJECTION"
    if "XSS" in t or "CROSS-SITE SCRIPTING" in t or "CWE-79" in t:
        return "XSS"
    if "SSRF" in t or "SERVER-SIDE REQUEST FORGERY" in t:
        return "SSRF"
    if "COMMAND INJECTION" in t or "CWE-78" in t:
        return "COMMAND_INJECTION"
    if "SECRET" in t or "KEY" in t or "PASSWORD" in t:
        return "SECRETS"
    if "DEPENDENCY" in t or "SCA" in t or "CVE" in t:
        return "SCA"
    return "GENERAL_SECURITY"


def map_vulnerability_to_probes(vuln_family: str) -> Tuple[List[str], str]:
    """Maps vulnerability family to available active DAST probe types."""
    if vuln_family == "BOLA":
        return (["BOLA"], "Targeted BOLA active probe scheduled to verify object access controls.")
    elif vuln_family == "AUTH":
        return (["AUTH_ENFORCEMENT"], "Targeted Auth Enforcement active probe scheduled to verify access restrictions.")
    elif vuln_family == "MASS_ASSIGNMENT":
        return (["MASS_ASSIGNMENT"], "Targeted Mass Assignment active probe scheduled to verify property binding controls.")
    elif vuln_family == "RATE_LIMITING":
        return (["RATE_LIMITING"], "Targeted Rate Limiting active probe scheduled to check request throttling.")
    elif vuln_family in {"SQL_INJECTION", "XSS", "SSRF", "COMMAND_INJECTION"}:
        return ([], f"No compatible active DAST probe is currently available for vulnerability type {vuln_family}.")
    elif vuln_family in {"SECRETS", "SCA"}:
        return ([], f"Active API probing is not applicable for {vuln_family} static findings.")
    else:
        return ([], f"No active probe mapping available for {vuln_family}.")


def calculate_priority_score(
    finding_severity: str,
    endpoint_risk_level: str,
    auth_status: str,
    bola_status: str,
    mass_assignment_status: str,
    sensitive_data_fields: Optional[str],
) -> Tuple[int, str]:
    score = 0

    # Finding Severity Signal
    sev_upper = (finding_severity or "").upper()
    if sev_upper == "CRITICAL":
        score += 35
    elif sev_upper == "HIGH":
        score += 25
    elif sev_upper == "MEDIUM":
        score += 15
    elif sev_upper == "LOW":
        score += 5

    # Endpoint Risk Level Signal
    risk_upper = (endpoint_risk_level or "").upper()
    if risk_upper == "CRITICAL":
        score += 25
    elif risk_upper == "HIGH":
        score += 20
    elif risk_upper == "MEDIUM":
        score += 10
    elif risk_upper == "LOW":
        score += 5

    # Unauthenticated Route Signal
    if (auth_status or "").upper() == "UNAUTHENTICATED":
        score += 15

    # BOLA or Mass Assignment Flagged on Endpoint
    if (bola_status or "").upper() != "NONE" or (mass_assignment_status or "").upper() != "NONE":
        score += 15

    # Sensitive Response Data Fields Signal
    if sensitive_data_fields and len(sensitive_data_fields.strip()) > 0:
        score += 10

    final_score = min(100, max(0, score))

    if final_score >= 85:
        level = "CRITICAL"
    elif final_score >= 70:
        level = "HIGH"
    elif final_score >= 50:
        level = "MEDIUM"
    else:
        level = "LOW"

    return final_score, level


class GreyBoxContextEngine:
    """
    Deterministic Grey-Box Static -> Dynamic Context Engine.
    Maps static security findings and code context to API endpoint targets,
    resolves applicable active DAST probes, and computes prioritized execution schedules.
    """

    def __init__(self, db: Session | None = None):
        self.db = db

    def build_context(
        self,
        project_id: int,
        scan_id: int,
        static_findings: List[Finding],
        endpoints: List[ApiEndpoint],
        target_url: Optional[str] = None,
    ) -> List[GreyBoxContext]:
        if not static_findings:
            return []

        # Build endpoint indexes for O(1) lookup
        exact_endpoint_map: Dict[Tuple[str, str], ApiEndpoint] = {}
        path_to_endpoints: Dict[str, List[ApiEndpoint]] = {}

        for ep in endpoints:
            m, p = normalize_endpoint_path(ep.path)
            method_key = ep.method.upper() if ep.method else m
            exact_endpoint_map[(method_key, p)] = ep
            if method_key == "ALL":
                exact_endpoint_map[("ALL", p)] = ep
            path_to_endpoints.setdefault(p, []).append(ep)

        contexts: List[GreyBoxContext] = []

        for f in static_findings:
            mapped_ep: Optional[ApiEndpoint] = None
            mapping_confidence = "UNMAPPED"
            mapping_reason = ""

            m_find, p_find = normalize_endpoint_path(f.file_path)

            # LEVEL 1 — EXACT OPENAPI/API SECURITY MAPPING
            if f.source == "api_security" or f.file_path.startswith("API:") or p_find.startswith("/"):
                if m_find != "ALL":
                    mapped_ep = exact_endpoint_map.get((m_find, p_find)) or exact_endpoint_map.get(("ALL", p_find))
                else:
                    eps_for_path = path_to_endpoints.get(p_find, [])
                    if len(eps_for_path) == 1:
                        mapped_ep = eps_for_path[0]
                if mapped_ep:
                    mapping_confidence = "EXACT_OPENAPI"
                    mapping_reason = f"Matched API Security finding to {mapped_ep.method} {mapped_ep.path} using exact OpenAPI endpoint identity."

            # LEVEL 2 — EXPLICIT CODE ROUTE MAPPING
            if not mapped_ep and f.code_snippet:
                extracted = extract_explicit_route_from_code(f.code_snippet)
                if extracted:
                    ext_method, ext_path = extracted
                    _, ext_p_norm = normalize_endpoint_path(ext_path)
                    eff_m = ext_method if ext_method != "ALL" else m_find
                    if eff_m != "ALL":
                        mapped_ep = exact_endpoint_map.get((eff_m, ext_p_norm)) or exact_endpoint_map.get(("ALL", ext_p_norm))
                    else:
                        eps_for_path = path_to_endpoints.get(ext_p_norm, [])
                        if len(eps_for_path) == 1:
                            mapped_ep = eps_for_path[0]
                    if mapped_ep:
                        mapping_confidence = "CODE_ROUTE_EXACT"
                        mapping_reason = f"Matched SAST route annotation ({ext_method} {ext_path}) directly to {mapped_ep.method} {mapped_ep.path}."

            # LEVEL 3 — CONTROLLER HEURISTIC
            if not mapped_ep and f.file_path and not f.file_path.startswith("API:"):
                file_base = f.file_path.split("/")[-1].split(".")[0].lower().replace("controller", "").replace("handler", "").replace("router", "")
                if len(file_base) >= 3:
                    file_base_stem = file_base.rstrip("s")
                    for ep in endpoints:
                        ep_path_lower = ep.path.lower()
                        if file_base in ep_path_lower or (len(file_base_stem) >= 3 and file_base_stem in ep_path_lower):
                            mapped_ep = ep
                            mapping_confidence = "HEURISTIC_CONTROLLER"
                            mapping_reason = f"Controller heuristic associated {f.file_path} with {ep.method} {ep.path}; mapping is heuristic."
                            break

            # LEVEL 4 — UNMAPPED
            if not mapped_ep:
                mapping_confidence = "UNMAPPED"
                mapping_reason = "Finding could not be reliably mapped to an API endpoint, so no targeted API DAST probe was scheduled."

            vuln_family = classify_vulnerability_family(f.category, f.title)
            recommended_probes, probe_msg = map_vulnerability_to_probes(vuln_family)

            if mapped_ep:
                priority_score, priority_level = calculate_priority_score(
                    finding_severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    endpoint_risk_level=mapped_ep.risk_level,
                    auth_status=mapped_ep.auth_status,
                    bola_status=mapped_ep.bola_status,
                    mass_assignment_status=mapped_ep.mass_assignment_status,
                    sensitive_data_fields=mapped_ep.sensitive_data_fields,
                )
                full_reason = f"{mapping_reason} {probe_msg}"
                http_m = mapped_ep.method
                http_p = mapped_ep.path
                ep_id = mapped_ep.id
            else:
                priority_score, priority_level = calculate_priority_score(
                    finding_severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    endpoint_risk_level="INFO",
                    auth_status="NONE",
                    bola_status="NONE",
                    mass_assignment_status="NONE",
                    sensitive_data_fields=None,
                )
                full_reason = f"{mapping_reason} {probe_msg}"
                http_m = m_find
                http_p = p_find
                ep_id = None

            ctx = GreyBoxContext(
                finding_id=f.id,
                project_id=project_id,
                endpoint_id=ep_id,
                target_url=target_url,
                http_method=http_m,
                path=http_p,
                vulnerability_family=vuln_family,
                recommended_probe_types=recommended_probes,
                source_file=f.file_path,
                source_line=f.line_number,
                priority_score=priority_score,
                priority_level=priority_level,
                mapping_confidence=mapping_confidence,
                context_reason=full_reason,
            )
            contexts.append(ctx)

        # Sort contexts by priority_score descending
        contexts.sort(key=lambda c: c.priority_score, reverse=True)
        return contexts
