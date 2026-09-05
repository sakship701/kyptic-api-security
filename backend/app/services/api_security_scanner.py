import re
from typing import Any, Dict, List, Set, Tuple
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.services.finding_normalizer import generate_fingerprint

SENSITIVE_PATH_PATTERNS = [
    r"/admin", r"/users?", r"/accounts?", r"/profiles?", r"/payments?",
    r"/billing", r"/orders?", r"/passwords?", r"/resets?", r"/tokens?",
    r"/credentials?", r"/private", r"/auth", r"/secrets?"
]

CREDENTIAL_FIELDS = {
    "password", "passwd", "secret", "token", "access_token",
    "refresh_token", "api_key", "apikey", "private_key", "authorization", "credential"
}

PII_FINANCIAL_FIELDS = {
    "ssn", "social_security", "credit_card", "card_number", "cvv", "cvc", "dob", "birthdate"
}

SENSITIVE_RESPONSE_FIELDS = CREDENTIAL_FIELDS | PII_FINANCIAL_FIELDS

OBJECT_IDENTIFIER_PATTERNS = [
    r"^id$", r"^user_?id$", r"^account_?id$", r"^order_?id$", r"^document_?id$",
    r"^profile_?id$", r"^customer_?id$", r"^resource_?id$", r"^uuid$", r"^guid$",
    r".*_id$", r".*Id$"
]

SUSPICIOUS_MASS_ASSIGNMENT_FIELDS = {
    "is_admin": "PRIVILEGE",
    "isadmin": "PRIVILEGE",
    "admin": "PRIVILEGE",
    "role": "PRIVILEGE",
    "roles": "PRIVILEGE",
    "permissions": "PRIVILEGE",
    "permission": "PRIVILEGE",
    "privilege": "PRIVILEGE",
    "privileges": "PRIVILEGE",
    "user_type": "PRIVILEGE",
    "usertype": "PRIVILEGE",
    "account_status": "ACCOUNT_STATE",
    "accountstatus": "ACCOUNT_STATE",
    "status": "ACCOUNT_STATE",
    "verified": "ACCOUNT_STATE",
    "is_verified": "ACCOUNT_STATE",
    "isverified": "ACCOUNT_STATE",
    "balance": "FINANCIAL",
    "credit_limit": "FINANCIAL",
    "creditlimit": "FINANCIAL",
    "owner_id": "OWNERSHIP",
    "ownerid": "OWNERSHIP",
    "created_by": "OWNERSHIP",
    "createdby": "OWNERSHIP",
    "internal": "SYSTEM",
    "system": "SYSTEM"
}

RATE_LIMIT_EXTENSIONS = {
    "x-rate-limit", "x-ratelimit", "x-rate-limit-limit", "x-rate-limit-requests",
    "x-throttle", "x-throttling", "x-rate-limit-window", "x-rate-limit-reset"
}

RESOURCE_INTENSIVE_PATH_PATTERNS = [
    r"/upload", r"/export", r"/bulk", r"/search", r"/report", r"/generate",
    r"/compute", r"/import", r"/sync", r"/download", r"/batch"
]


def is_sensitive_path(path: str) -> bool:
    path_lower = path.lower()
    for pattern in SENSITIVE_PATH_PATTERNS:
        if re.search(pattern, path_lower):
            return True
    return False


def find_sensitive_fields_in_schema(schema: Any, field_path: str = "") -> List[Tuple[str, str]]:
    """
    Recursively inspects a JSON schema for sensitive property names.
    Returns list of (field_name, field_category) tuples.
    """
    found = []
    if not isinstance(schema, dict):
        return found

    properties = schema.get("properties", {})
    if isinstance(properties, dict):
        for prop_name, prop_val in properties.items():
            current_path = f"{field_path}.{prop_name}" if field_path else prop_name
            prop_lower = prop_name.lower()

            if prop_lower in CREDENTIAL_FIELDS:
                found.append((current_path, "CREDENTIAL"))
            elif prop_lower in PII_FINANCIAL_FIELDS:
                found.append((current_path, "PII_FINANCIAL"))

            # Recurse if nested object or items
            if isinstance(prop_val, dict):
                if prop_val.get("type") == "object" or "properties" in prop_val:
                    found.extend(find_sensitive_fields_in_schema(prop_val, current_path))
                elif prop_val.get("type") == "array" and "items" in prop_val:
                    found.extend(find_sensitive_fields_in_schema(prop_val.get("items"), f"{current_path}[]"))

    return found


def find_object_identifiers(path: str, parameters: List[Dict[str, Any]]) -> List[str]:
    """
    Identifies path parameters or parameter definitions representing object identifiers for BOLA analysis.
    """
    found_ids: List[str] = []

    # 1. Extract path parameters from URI string like /users/{id}
    path_param_names = re.findall(r"\{([a-zA-Z0-9_]+)\}", path)
    for p_name in path_param_names:
        for pattern in OBJECT_IDENTIFIER_PATTERNS:
            if re.match(pattern, p_name, re.IGNORECASE):
                if p_name not in found_ids:
                    found_ids.append(p_name)
                break

    # 2. Check parameter list definitions where in == "path"
    for param in parameters:
        if isinstance(param, dict) and param.get("in") == "path":
            p_name = str(param.get("name", ""))
            if p_name and p_name not in found_ids:
                for pattern in OBJECT_IDENTIFIER_PATTERNS:
                    if re.match(pattern, p_name, re.IGNORECASE):
                        found_ids.append(p_name)
                        break

    return found_ids


def find_suspicious_mass_assignment_fields(schema: Any, field_path: str = "") -> List[Tuple[str, str]]:
    """
    Recursively inspects request body schemas for privileged, ownership, or financial properties.
    Returns list of (field_name, category) tuples.
    """
    found = []
    if not isinstance(schema, dict):
        return found

    properties = schema.get("properties", {})
    if isinstance(properties, dict):
        for prop_name, prop_val in properties.items():
            current_path = f"{field_path}.{prop_name}" if field_path else prop_name
            prop_lower = prop_name.lower()

            if prop_lower in SUSPICIOUS_MASS_ASSIGNMENT_FIELDS:
                category = SUSPICIOUS_MASS_ASSIGNMENT_FIELDS[prop_lower]
                # Avoid flagging generic "status" on non-privileged query DTOs
                if prop_lower == "status" and len(properties) <= 2 and "id" in properties:
                    pass
                else:
                    found.append((current_path, category))

            # Recurse if nested object or items
            if isinstance(prop_val, dict):
                if prop_val.get("type") == "object" or "properties" in prop_val:
                    found.extend(find_suspicious_mass_assignment_fields(prop_val, current_path))
                elif prop_val.get("type") == "array" and "items" in prop_val:
                    found.extend(find_suspicious_mass_assignment_fields(prop_val.get("items"), f"{current_path}[]"))

    return found


def check_has_rate_limit_declarations(op_dict: Dict[str, Any], path_item_dict: Dict[str, Any], root_spec_dict: Dict[str, Any]) -> bool:
    """
    Checks operation, path item, and root spec dictionaries for explicit rate-limiting vendor extensions.
    """
    dicts_to_check = [op_dict or {}, path_item_dict or {}, root_spec_dict or {}]
    for d in dicts_to_check:
        if not isinstance(d, dict):
            continue
        for key in d.keys():
            key_lower = str(key).lower()
            if key_lower in RATE_LIMIT_EXTENSIONS or any(ext in key_lower for ext in ("rate-limit", "ratelimit", "throttle")):
                return True
    return False


def is_resource_intensive_operation(path: str, method: str, ep_data: Dict[str, Any]) -> bool:
    """
    Heuristic check to determine if an operation is resource-intensive.
    """
    path_lower = path.lower()
    for pattern in RESOURCE_INTENSIVE_PATH_PATTERNS:
        if re.search(pattern, path_lower):
            return True

    # Check request body media type for file uploads
    op_dict = ep_data.get("op_dict", {})
    if isinstance(op_dict, dict) and "requestBody" in op_dict:
        rb = op_dict["requestBody"]
        if isinstance(rb, dict) and "content" in rb:
            content = rb["content"]
            if isinstance(content, dict):
                for m_type in content.keys():
                    if "multipart/form-data" in m_type or "octet-stream" in m_type:
                        return True

    # Check parameter types
    for param in ep_data.get("parameters", []):
        if isinstance(param, dict):
            p_name = str(param.get("name", "")).lower()
            p_type = str(param.get("type", "")).lower()
            if p_type == "file" or p_name in ("file", "attachment", "batch", "bulk"):
                return True

    return False


class ApiSecurityScanner:
    def __init__(self, project_id: int, scan_id: int):
        self.project_id = project_id
        self.scan_id = scan_id

    def analyze_endpoint(self, ep_data: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Finding]]:
        path = ep_data["path"]
        method = ep_data["method"]
        op_security = ep_data.get("op_security")
        global_security = ep_data.get("global_security")
        security_schemes = ep_data.get("security_schemes", {})
        parameters = ep_data.get("parameters", [])
        request_body_schema = ep_data.get("request_body_schema")
        response_schemas = ep_data.get("response_schemas", {})

        op_dict = ep_data.get("op_dict", {})
        path_item_dict = ep_data.get("path_item_dict", {})
        root_spec_dict = ep_data.get("root_spec_dict", {})

        findings: List[Finding] = []

        # ---------------------------------------------------------------------
        # 1. Authentication Status Analysis
        # ---------------------------------------------------------------------
        auth_status = "AUTHENTICATED"
        auth_type = "UNKNOWN"

        has_global_sec = bool(global_security and len(global_security) > 0)
        has_schemes = bool(security_schemes and len(security_schemes) > 0)
        has_op_sec = op_security is not None and len(op_security) > 0
        explicitly_unauthenticated = op_security is not None and len(op_security) == 0

        # Determine Auth Type if present
        active_sec = op_security if op_security is not None else global_security
        if active_sec and isinstance(active_sec, list) and len(active_sec) > 0:
            scheme_name = list(active_sec[0].keys())[0] if active_sec[0] else None
            if scheme_name and scheme_name in security_schemes:
                sec_obj = security_schemes[scheme_name]
                s_type = sec_obj.get("type", "").upper()
                s_scheme = sec_obj.get("scheme", "").upper()
                if s_type == "HTTP":
                    auth_type = s_scheme or "HTTP"
                elif s_type == "APIKEY":
                    auth_type = "API_KEY"
                elif s_type == "OAUTH2":
                    auth_type = "OAUTH2"
                else:
                    auth_type = s_type or "BEARER"
        else:
            auth_type = "NONE"

        sensitive_route = is_sensitive_path(path)

        if explicitly_unauthenticated:
            auth_status = "UNAUTHENTICATED"
            severity = FindingSeverity.HIGH if sensitive_route else FindingSeverity.MEDIUM
            owasp = "API2:2023 Broken Authentication"
            rule_id = "API-AUTH-EXPLICIT-UNAUTHENTICATED"
            title = f"Explicitly Unauthenticated API Endpoint: {method} {path}"
            desc = (
                f"The endpoint '{method} {path}' explicitly overrides security requirements with an empty security declaration ('security: []'). "
                f"{'This is a sensitive business route containing critical functionality. ' if sensitive_route else ''}"
                "Unauthenticated access allows public requests without identity verification."
            )
            evidence = (
                f"Endpoint: {method} {path}\n"
                f"Security Declaration: security: [] (Explicit Override)\n"
                f"Sensitive Path Indicator: {sensitive_route}\n"
                "Note: Static analysis indicator of missing authentication controls."
            )
            finding = self._create_finding(
                rule_id=rule_id,
                title=title,
                description=desc,
                severity=severity,
                category="API Security - Authentication",
                owasp=owasp,
                file_path=path,
                evidence=evidence,
                remediation="Add appropriate security requirements to the operation or global API specification."
            )
            findings.append(finding)

        elif not has_op_sec and not has_global_sec:
            auth_status = "UNAUTHENTICATED"
            severity = FindingSeverity.HIGH if sensitive_route else FindingSeverity.MEDIUM
            owasp = "API2:2023 Broken Authentication"
            rule_id = "API-AUTH-MISSING-SECURITY"
            title = f"Missing Authentication Requirement: {method} {path}"
            desc = (
                f"The endpoint '{method} {path}' does not specify any security requirement in the API definition. "
                f"{'Path semantics indicate this is a sensitive operation. ' if sensitive_route else ''}"
                "Endpoints lacking authentication controls expose internal application interfaces to unauthorized access."
            )
            evidence = (
                f"Endpoint: {method} {path}\n"
                f"Security Schemes Defined: {has_schemes}\n"
                f"Global Security Requirement: None\n"
                f"Operation Security Requirement: None\n"
                f"Sensitive Route Detected: {sensitive_route}"
            )
            finding = self._create_finding(
                rule_id=rule_id,
                title=title,
                description=desc,
                severity=severity,
                category="API Security - Authentication",
                owasp=owasp,
                file_path=path,
                evidence=evidence,
                remediation="Declare global or endpoint-level security schemes (e.g. Bearer JWT, OAuth2, API Key) in the OpenAPI specification."
            )
            findings.append(finding)

        elif auth_type == "BASIC":
            auth_status = "WEAK_AUTH"
            rule_id = "API-AUTH-WEAK-BASIC-AUTH"
            title = f"Weak HTTP Basic Authentication Scheme: {method} {path}"
            desc = (
                f"The endpoint '{method} {path}' uses HTTP Basic Authentication. "
                "Basic authentication transmits base64-encoded credentials which can easily be intercepted if TLS is misconfigured or terminated early."
            )
            evidence = f"Endpoint: {method} {path}\nAuthentication Scheme: HTTP Basic"
            finding = self._create_finding(
                rule_id=rule_id,
                title=title,
                description=desc,
                severity=FindingSeverity.MEDIUM,
                category="API Security - Authentication",
                owasp="API2:2023 Broken Authentication",
                file_path=path,
                evidence=evidence,
                remediation="Upgrade to a modern token-based authentication mechanism such as OAuth 2.0 or JWT Bearer tokens."
            )
            findings.append(finding)

        # ---------------------------------------------------------------------
        # 2. Excessive Data Exposure Analysis
        # ---------------------------------------------------------------------
        detected_sensitive_fields: List[str] = []
        for status_code, resp_schema in response_schemas.items():
            if status_code.startswith("2") or status_code == "default":
                sensitive_matches = find_sensitive_fields_in_schema(resp_schema)
                for field_name, category in sensitive_matches:
                    detected_sensitive_fields.append(f"{field_name} ({category})")
                    sev = FindingSeverity.HIGH if category == "CREDENTIAL" else FindingSeverity.MEDIUM
                    rule_id = f"API-DATA-EXPOSURE-{category}"
                    title = f"Sensitive Response Field Exposure '{field_name}' on {method} {path}"
                    desc = (
                        f"Response schema for HTTP {status_code} on endpoint '{method} {path}' exposes sensitive field '{field_name}'. "
                        f"Returning sensitive {category.lower()} data in API responses risks credential leakage and privacy violations."
                    )
                    evidence = (
                        f"Endpoint: {method} {path}\n"
                        f"Response Status Code: {status_code}\n"
                        f"Exposed Field Path: {field_name}\n"
                        f"Exposure Category: {category}"
                    )
                    finding = self._create_finding(
                        rule_id=rule_id,
                        title=title,
                        description=desc,
                        severity=sev,
                        category="API Security - Data Exposure",
                        owasp="API3:2023 Broken Object Property Level Authorization",
                        file_path=path,
                        evidence=evidence,
                        remediation=f"Remove '{field_name}' from the response schema or apply strict data masking before serializing."
                    )
                    findings.append(finding)

        # ---------------------------------------------------------------------
        # 3. Poor Input Validation Analysis
        # ---------------------------------------------------------------------
        unconstrained_inputs = []

        # Parameter checks
        for param in parameters:
            p_name = param.get("name", "unknown")
            p_in = param.get("in", "query")
            schema = param.get("schema", param)

            p_type = schema.get("type")
            if p_type == "string":
                if "maxLength" not in schema and "pattern" not in schema and "enum" not in schema:
                    unconstrained_inputs.append(f"Param '{p_name}' ({p_in}): unconstrained string")
            elif p_type in ("integer", "number"):
                if "minimum" not in schema and "maximum" not in schema:
                    unconstrained_inputs.append(f"Param '{p_name}' ({p_in}): unconstrained numeric bounds")

        # Request Body schema checks
        if request_body_schema and isinstance(request_body_schema, dict):
            b_type = request_body_schema.get("type", "object")
            props = request_body_schema.get("properties", {})
            if b_type == "object" and not props:
                unconstrained_inputs.append("Request Body: unconstrained generic object schema")

        request_val_status = "STRICT"
        if unconstrained_inputs:
            request_val_status = "UNCONSTRAINED"
            rule_id = "API-VAL-UNCONSTRAINED-INPUT"
            title = f"Unconstrained Input Validation Parameters: {method} {path}"
            desc = (
                f"Endpoint '{method} {path}' defines parameters or request body schemas without strict validation boundaries (e.g., missing maxLength, pattern, enum, or numeric limits). "
                "Unvalidated inputs increase susceptibility to buffer overflows, injection attacks, and resource exhaustion."
            )
            evidence = f"Endpoint: {method} {path}\nUnconstrained Items:\n" + "\n".join(f"- {i}" for i in unconstrained_inputs)
            finding = self._create_finding(
                rule_id=rule_id,
                title=title,
                description=desc,
                severity=FindingSeverity.LOW,
                category="API Security - Input Validation",
                owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                file_path=path,
                evidence=evidence,
                remediation="Define explicit schema constraints (maxLength, minimum, maximum, pattern, or enum) for all parameters and request body schemas."
            )
            findings.append(finding)

        # ---------------------------------------------------------------------
        # 4. Milestone 2: BOLA / Broken Object Level Authorization (OWASP API1:2023)
        # ---------------------------------------------------------------------
        object_ids = find_object_identifiers(path, parameters)
        bola_status = "NONE"
        if object_ids:
            bola_status = "POTENTIAL_BOLA"
            bola_sev = FindingSeverity.HIGH if (auth_status == "UNAUTHENTICATED" or sensitive_route) else FindingSeverity.MEDIUM
            rule_id = "API-BOLA-POTENTIAL-EXPOSURE"
            title = f"Potential Broken Object Level Authorization (BOLA): {method} {path}"
            desc = (
                f"The endpoint '{method} {path}' contains object-level identifier parameter(s) ({', '.join(object_ids)}). "
                "Static specification analysis indicates authorization enforcement (whether the authenticated principal is permitted to access the specific object ID) cannot be verified from the OpenAPI definition alone. "
                "Unenforced object-level authorization allows attackers to manipulate object IDs to access or modify unauthorized user data."
            )
            evidence = (
                f"Endpoint: {method} {path}\n"
                f"Detected Object Identifier(s): {', '.join(object_ids)}\n"
                f"Authentication Status: {auth_status}\n"
                f"Sensitive Path: {sensitive_route}\n"
                "Note: Static analysis heuristic indicator requiring runtime verification of server-side object ownership checks."
            )
            finding = self._create_finding(
                rule_id=rule_id,
                title=title,
                description=desc,
                severity=bola_sev,
                category="API Security - Authorization",
                owasp="API1:2023 Broken Object Level Authorization",
                file_path=path,
                evidence=evidence,
                remediation="Require server-side authorization checks ensuring the authenticated principal is permitted to access the referenced object. Do not rely only on object IDs being difficult to guess."
            )
            findings.append(finding)

        # ---------------------------------------------------------------------
        # 5. Milestone 2: Mass Assignment / Unsafe Property Binding (OWASP API6:2023)
        # ---------------------------------------------------------------------
        mass_assignment_status = "NONE"
        if method.upper() in ("POST", "PUT", "PATCH") and request_body_schema:
            suspicious_fields = find_suspicious_mass_assignment_fields(request_body_schema)
            if suspicious_fields:
                mass_assignment_status = "SUSPICIOUS_PROPERTIES_EXPOSED"
                field_names = [f[0] for f in suspicious_fields]
                has_privilege_or_ownership = any(f[1] in ("PRIVILEGE", "OWNERSHIP", "FINANCIAL") for f in suspicious_fields)
                ma_sev = FindingSeverity.HIGH if has_privilege_or_ownership else FindingSeverity.MEDIUM
                rule_id = "API-MASS-ASSIGNMENT-SUSPICIOUS-FIELD"
                title = f"Potential Mass Assignment / Unsafe Property Binding: {method} {path}"
                desc = (
                    f"The request body schema for '{method} {path}' exposes privileged or system properties ({', '.join(field_names)}) that clients can supply in requests. "
                    "If backend frameworks automatically bind request parameters directly to internal domain models or database records, attackers can manipulate administrative roles, ownership, or account states."
                )
                evidence = (
                    f"Endpoint: {method} {path}\n"
                    f"HTTP Method: {method}\n"
                    f"Exposed Privileged/Internal Field(s): {', '.join(field_names)}\n"
                    "Note: Static specification-based risk indicator. Verify backend DTO and field allowlist binding."
                )
                finding = self._create_finding(
                    rule_id=rule_id,
                    title=title,
                    description=desc,
                    severity=ma_sev,
                    category="API Security - Data Binding",
                    owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                    file_path=path,
                    evidence=evidence,
                    remediation="Use explicit allowlists/DTOs for writable fields and prevent clients from modifying server-controlled authorization, ownership, financial, or internal state fields."
                )
                findings.append(finding)
            else:
                mass_assignment_status = "SAFE"

        # ---------------------------------------------------------------------
        # 6. Milestone 2: Rate Limiting & Resource Consumption (OWASP API4:2023)
        # ---------------------------------------------------------------------
        has_rl_decl = check_has_rate_limit_declarations(op_dict, path_item_dict, root_spec_dict)
        rate_limit_status = "PRESENT" if has_rl_decl else "MISSING"

        is_resource_intensive = is_resource_intensive_operation(path, method, ep_data)
        if rate_limit_status == "MISSING" and (is_resource_intensive or sensitive_route or auth_status == "UNAUTHENTICATED"):
            rl_sev = FindingSeverity.MEDIUM if (is_resource_intensive or sensitive_route) else FindingSeverity.LOW
            rule_id = "API-RATELIMIT-MISSING-THROTTLING"
            title = f"Missing or Unclear Rate Limiting Controls: {method} {path}"
            desc = (
                f"The OpenAPI specification for '{method} {path}' does not declare explicit rate-limiting or throttling controls. "
                f"{'This operation appears to perform resource-intensive processing (file processing, bulk data, search, or report generation). ' if is_resource_intensive else ''}"
                "Unthrottled endpoints are vulnerable to Denial of Service (DoS), brute-force attacks, and resource exhaustion."
            )
            evidence = (
                f"Endpoint: {method} {path}\n"
                f"Rate Limit Extension Metadata: None declared\n"
                f"Resource Intensive Indicator: {is_resource_intensive}\n"
                f"Sensitive Path: {sensitive_route}\n"
                "Note: Static analysis cannot prove the absence of runtime rate limiting; verify API gateway throttling configuration."
            )
            finding = self._create_finding(
                rule_id=rule_id,
                title=title,
                description=desc,
                severity=rl_sev,
                category="API Security - Resource Management",
                owasp="API4:2023 Unrestricted Resource Consumption",
                file_path=path,
                evidence=evidence,
                remediation="Apply server-side throttling/rate limits, especially to authentication, expensive, bulk, search, upload, and resource-intensive endpoints."
            )
            findings.append(finding)

        # ---------------------------------------------------------------------
        # 7. Deterministic Risk Score Calculation (0 - 100)
        # ---------------------------------------------------------------------
        risk_score = 0
        score_reasons = []

        if auth_status == "UNAUTHENTICATED":
            if sensitive_route:
                risk_score += 40
                score_reasons.append("Unauthenticated sensitive route (+40)")
            else:
                risk_score += 25
                score_reasons.append("Unauthenticated route (+25)")
        elif auth_status == "WEAK_AUTH":
            risk_score += 15
            score_reasons.append("Weak Basic authentication (+15)")

        cred_exposures = [f for f in detected_sensitive_fields if "CREDENTIAL" in f]
        pii_exposures = [f for f in detected_sensitive_fields if "PII_FINANCIAL" in f]

        if cred_exposures:
            risk_score += 35
            score_reasons.append(f"Exposes credential fields ({len(cred_exposures)}) (+35)")
        if pii_exposures:
            risk_score += 20
            score_reasons.append(f"Exposes PII/financial fields ({len(pii_exposures)}) (+20)")

        if request_val_status == "UNCONSTRAINED":
            risk_score += 10
            score_reasons.append("Unconstrained input parameters (+10)")

        # Bounded Milestone 2 Risk Additions
        if bola_status == "POTENTIAL_BOLA":
            if auth_status == "UNAUTHENTICATED" or sensitive_route:
                risk_score += 25
                score_reasons.append("BOLA potential exposure on sensitive/unauthenticated route (+25)")
            else:
                risk_score += 15
                score_reasons.append("BOLA potential exposure (+15)")

        if mass_assignment_status == "SUSPICIOUS_PROPERTIES_EXPOSED":
            risk_score += 20
            score_reasons.append("Suspicious mass assignment fields exposed (+20)")

        if rate_limit_status == "MISSING" and (is_resource_intensive or sensitive_route):
            risk_score += 10
            score_reasons.append("Missing rate limiting on resource-intensive/sensitive route (+10)")

        risk_score = min(100, risk_score)

        if risk_score >= 75:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        elif risk_score > 0:
            risk_level = "LOW"
        else:
            risk_level = "INFO"

        endpoint_model_dict = {
            "project_id": self.project_id,
            "path": path,
            "method": method,
            "summary": ep_data.get("summary"),
            "operation_id": ep_data.get("operation_id"),
            "auth_status": auth_status,
            "auth_type": auth_type,
            "rate_limit_status": rate_limit_status,
            "request_validation_status": request_val_status,
            "sensitive_data_fields": ", ".join(detected_sensitive_fields) if detected_sensitive_fields else None,
            "bola_status": bola_status,
            "mass_assignment_status": mass_assignment_status,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "discovered_via": "OPENAPI_SPEC",
        }

        return endpoint_model_dict, findings

    def _create_finding(
        self,
        rule_id: str,
        title: str,
        description: str,
        severity: FindingSeverity,
        category: str,
        owasp: str,
        file_path: str,
        evidence: str,
        remediation: str
    ) -> Finding:
        full_description = f"{description}\n\nRemediation:\n{remediation}"
        fingerprint = generate_fingerprint(
            project_id=self.project_id,
            scanner_name="api-security",
            rule_id=rule_id,
            file_path=file_path,
            line_number=None,
            message=title
        )

        cvss_map = {
            FindingSeverity.CRITICAL: 9.0,
            FindingSeverity.HIGH: 7.5,
            FindingSeverity.MEDIUM: 5.0,
            FindingSeverity.LOW: 2.5,
            FindingSeverity.INFO: 0.0
        }

        return Finding(
            project_id=self.project_id,
            scan_id=self.scan_id,
            title=title[:255],
            description=full_description,
            severity=severity,
            cvss=cvss_map.get(severity, 0.0),
            category=category[:255],
            file_path=file_path[:500],
            line_number=None,
            status=FindingStatus.OPEN,
            source=FindingSource.API_SECURITY,
            rule_id=rule_id[:255],
            owasp=owasp[:255],
            code_snippet=evidence,
            scanner_name="api-security",
            scanner_version="api-security 1.0.0",
            fingerprint=fingerprint
        )
