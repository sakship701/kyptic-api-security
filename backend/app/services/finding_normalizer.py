import hashlib
from pathlib import Path
from typing import Any, Dict, List
from app.models.finding import FindingSeverity, FindingSource, FindingStatus, Finding

def normalize_semgrep_severity(severity_str: str) -> FindingSeverity:
    severity_str = severity_str.upper()
    if severity_str == "ERROR":
        return FindingSeverity.HIGH
    elif severity_str == "WARNING":
        return FindingSeverity.MEDIUM
    elif severity_str == "INFO":
        return FindingSeverity.LOW
    return FindingSeverity.INFO

def extract_cwe(extra_dict: Dict[str, Any]) -> str | None:
    metadata = extra_dict.get("metadata", {})
    cwe_list = metadata.get("cwe")
    if isinstance(cwe_list, list) and cwe_list:
        return cwe_list[0]
    elif isinstance(cwe_list, str):
        return cwe_list
    return None

def extract_owasp(extra_dict: Dict[str, Any]) -> str | None:
    metadata = extra_dict.get("metadata", {})
    owasp_list = metadata.get("owasp")
    if isinstance(owasp_list, list) and owasp_list:
        return owasp_list[0]
    elif isinstance(owasp_list, str):
        return owasp_list
    return None

def generate_fingerprint(project_id: int, scanner_name: str, rule_id: str, file_path: str, line_number: int | None, message: str) -> str:
    hasher = hashlib.sha256()
    hasher.update(str(project_id).encode())
    hasher.update(scanner_name.encode())
    hasher.update(rule_id.encode())
    hasher.update(file_path.encode())
    if line_number is not None:
        hasher.update(str(line_number).encode())
    hasher.update(message.encode())
    return hasher.hexdigest()

def normalize_semgrep_results(
    results_dict: Dict[str, Any],
    project_id: int,
    scan_id: int,
    scanner_version: str | None = None,
    target_dir: Path | None = None
) -> List[Finding]:
    findings = []
    results = results_dict.get("results", [])
    
    for r in results:
        check_id = r.get("check_id", "semgrep-rule")
        file_path = r.get("path", "unknown-file")
        start_line = r.get("start", {}).get("line")
        end_line = r.get("end", {}).get("line")
        
        extra = r.get("extra", {})
        message = extra.get("message", "No message provided")
        severity_str = extra.get("severity", "INFO")
        code_snippet = extra.get("lines", "")

        if not code_snippet or code_snippet == "requires login":
            from pathlib import Path
            try:
                full_path = Path(file_path)
                if not full_path.is_absolute():
                    if target_dir:
                        full_path = target_dir / file_path
                    else:
                        from app.services.storage_service import get_source_dir
                        full_path = get_source_dir(project_id) / file_path
                if full_path.exists():
                    file_lines = full_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                    s_line = start_line if start_line is not None else 1
                    e_line = end_line if end_line is not None else s_line
                    s_idx = max(0, s_line - 1)
                    e_idx = min(len(file_lines), e_line)
                    if s_idx < e_idx:
                        code_snippet = "\n".join(file_lines[s_idx:e_idx])
            except Exception:
                pass
        
        severity = normalize_semgrep_severity(severity_str)
        cwe = extract_cwe(extra)
        owasp = extract_owasp(extra)
        
        category = "Security Scan"
        if owasp:
            category = owasp
        elif cwe:
            category = cwe.split(":")[0]
            
        cvss_map = {
            FindingSeverity.CRITICAL: 9.0,
            FindingSeverity.HIGH: 7.5,
            FindingSeverity.MEDIUM: 5.0,
            FindingSeverity.LOW: 2.5,
            FindingSeverity.INFO: 0.0
        }
        cvss = cvss_map.get(severity, 0.0)

        fingerprint = generate_fingerprint(
            project_id=project_id,
            scanner_name="semgrep",
            rule_id=check_id,
            file_path=file_path,
            line_number=start_line,
            message=message
        )

        finding = Finding(
            project_id=project_id,
            scan_id=scan_id,
            title=message.split("\n")[0][:100],
            description=message,
            severity=severity,
            cvss=cvss,
            category=category,
            file_path=file_path,
            line_number=start_line,
            status=FindingStatus.OPEN,
            source=FindingSource.SAST,
            rule_id=check_id,
            cwe=cwe,
            owasp=owasp,
            end_line_number=end_line,
            code_snippet=code_snippet,
            scanner_name="semgrep",
            scanner_version=scanner_version,
            fingerprint=fingerprint
        )
        findings.append(finding)
        
    return findings


def get_secret_candidates(line: str) -> List[str]:
    """Extract deterministic candidate substrings from a line for secret matching."""
    candidates = []
    line_stripped = line.strip()
    if line_stripped:
        candidates.append(line_stripped)
    
    # 1. Extract quoted substrings
    import re
    quoted = re.findall(r'["\'`](.*?)["\'`]', line)
    for q in quoted:
        candidates.append(q)
        candidates.append(q.strip())
        
    # 2. Extract words split by whitespace and common symbols
    parts = line.split()
    for p in parts:
        candidates.append(p)
        p_clean = p.strip('=:;,"\'()[]{}<>')
        if p_clean:
            candidates.append(p_clean)
            
        # Split subparts by colon or equals to catch inline assignments like key:value or key=value
        for subpart in re.split(r'[:=]', p):
            sub_clean = subpart.strip('=:;,"\'()[]{}<>')
            if sub_clean:
                candidates.append(sub_clean)
                
    # Remove duplicates preserving order
    seen = set()
    unique_candidates = []
    for c in candidates:
        if c and c not in seen:
            seen.add(c)
            unique_candidates.append(c)
    return unique_candidates


def find_secret_substring(line: str, hashed_secret: str) -> str | None:
    """Find the exact substring in line that hashes to hashed_secret."""
    # Clean line (strip newline characters)
    line = line.replace("\r", "").replace("\n", "")
    
    # Bounded candidate lookup
    candidates = get_secret_candidates(line)
    for cand in candidates:
        if hashlib.sha1(cand.encode('utf-8')).hexdigest() == hashed_secret:
            return cand
            
    return None


def normalize_detect_secrets_results(
    results_dict: Dict[str, Any],
    project_id: int,
    scan_id: int,
    scanner_version: str | None = None,
    target_dir: Path | None = None
) -> List[Finding]:
    """Convert detect-secrets output into Kyptic Finding models, masking secrets."""
    findings = []
    results = results_dict.get("results", {})
    
    for file_path, matches in results.items():
        # Resolve full path to read the file lines for code snippet extraction
        full_path = Path(file_path)
        if not full_path.is_absolute() and target_dir:
            full_path = target_dir / file_path
        
        file_lines = []
        if full_path.exists():
            try:
                file_lines = full_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                pass
                
        for m in matches:
            line_no = m.get("line_number")
            detector_name = m.get("type", "Secret Detector")
            hashed_secret = m.get("hashed_secret", "")
            
            # Extract and mask code snippet
            code_snippet = ""
            if file_lines and line_no is not None and 1 <= line_no <= len(file_lines):
                raw_line = file_lines[line_no - 1]
                # Find secret in the line using our bounded scanner
                secret_sub = find_secret_substring(raw_line, hashed_secret)
                if secret_sub:
                    code_snippet = raw_line.replace(secret_sub, "********")
                else:
                    # Secret cannot be reliably located; mask the entire line
                    code_snippet = "********"
            else:
                code_snippet = "********"
            
            # Map severity based on type of secret
            # Highly sensitive credentials/keys -> CRITICAL
            # Other tokens/passwords -> HIGH
            # Generic/entropy -> MEDIUM
            severity = FindingSeverity.HIGH
            cvss = 8.1
            
            detector_lower = detector_name.lower()
            if "private key" in detector_lower or "privatekey" in detector_lower or "ssh" in detector_lower:
                severity = FindingSeverity.CRITICAL
                cvss = 9.5
            elif "entropy" in detector_lower:
                severity = FindingSeverity.MEDIUM
                cvss = 5.5
            
            # Set category
            category = "Secrets Exposure"
            
            # Map FindingSource
            source = FindingSource.SECRETS
            
            # Title & Description (without raw secret!)
            title = f"Hardcoded {detector_name} Detected"
            description = (
                f"A potential hardcoded secret of type '{detector_name}' was detected. "
                "Storing secrets in plaintext in source code poses a critical security risk."
            )
            
            fingerprint = generate_fingerprint(
                project_id=project_id,
                scanner_name="detect-secrets",
                rule_id=detector_name,
                file_path=file_path,
                line_number=line_no,
                message=title
            )
            
            finding = Finding(
                project_id=project_id,
                scan_id=scan_id,
                title=title,
                description=description,
                severity=severity,
                cvss=cvss,
                category=category,
                file_path=file_path,
                line_number=line_no,
                status=FindingStatus.OPEN,
                source=source,
                rule_id=detector_name,
                end_line_number=line_no,
                code_snippet=code_snippet,
                scanner_name="detect-secrets",
                scanner_version=scanner_version,
                fingerprint=fingerprint
            )
            findings.append(finding)
            
    return findings


def normalize_sca_severity(severity_str: str | None) -> FindingSeverity:
    if not severity_str:
        return FindingSeverity.MEDIUM
    sev_upper = str(severity_str).upper()
    if "CRITICAL" in sev_upper:
        return FindingSeverity.CRITICAL
    elif "HIGH" in sev_upper:
        return FindingSeverity.HIGH
    elif "MODERATE" in sev_upper or "MEDIUM" in sev_upper:
        return FindingSeverity.MEDIUM
    elif "LOW" in sev_upper:
        return FindingSeverity.LOW
    elif "INFO" in sev_upper:
        return FindingSeverity.INFO
    return FindingSeverity.MEDIUM


def parse_cvss_score(cvss_input: Any) -> float | None:
    """Extract float CVSS score if present; return None if unavailable. Do not fabricate."""
    if cvss_input is None:
        return None
    if isinstance(cvss_input, (int, float)):
        return float(cvss_input)
    if isinstance(cvss_input, str):
        # Check if it's a numeric string like "7.5"
        try:
            return float(cvss_input)
        except ValueError:
            pass
    return None


def normalize_sca_results(
    results_dict: Dict[str, Any],
    project_id: int,
    scan_id: int,
    scanner_version: str | None = None,
    target_dir: Path | None = None
) -> List[Finding]:
    """Convert raw SCA scan results into Kyptic Finding ORM models."""
    findings = []
    raw_results = results_dict.get("results", [])
    if not isinstance(raw_results, list):
        return findings

    for r in raw_results:
        pkg_name = r.get("package_name", "unknown-package")
        pkg_version = r.get("installed_version", "unknown-version")
        vuln_id = r.get("vulnerability_id") or "UNKNOWN-VULN"
        aliases = r.get("aliases", [])
        
        # Prefer direct CVE vulnerability_id or CVE/GHSA aliases
        cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)
        ghsa_alias = next((a for a in aliases if a.startswith("GHSA-")), None)
        display_vuln_id = vuln_id if vuln_id.startswith("CVE-") else (cve_alias or ghsa_alias or vuln_id)

        summary = r.get("summary") or f"Known vulnerability in {pkg_name}"
        fix_versions = r.get("fix_versions", [])
        fix_str = ", ".join(fix_versions) if isinstance(fix_versions, list) and fix_versions else (str(fix_versions) if fix_versions else "N/A")
        
        ecosystem = r.get("ecosystem", "Dependencies")
        file_path = r.get("file_path", "manifest")

        severity_raw = r.get("severity_raw")
        severity = normalize_sca_severity(severity_raw)
        
        # Authoritative CVSS score or None (NEVER fabricate)
        cvss = parse_cvss_score(r.get("cvss_score")) or parse_cvss_score(r.get("cvss"))

        title = f"Vulnerable Dependency: {pkg_name} ({display_vuln_id})"
        description = (
            f"Vulnerability '{display_vuln_id}' affects dependency '{pkg_name}' version '{pkg_version}'.\n"
            f"Ecosystem: {ecosystem}\n"
            f"Summary: {summary}\n"
            f"Fixed Version: {fix_str}"
        )

        code_snippet = (
            f"Package: {pkg_name}@{pkg_version}\n"
            f"Ecosystem: {ecosystem}\n"
            f"Manifest File: {file_path}\n"
            f"Vulnerability ID: {display_vuln_id}\n"
            f"Fixed Version: {fix_str}"
        )

        fingerprint = generate_fingerprint(
            project_id=project_id,
            scanner_name="sca-dependency",
            rule_id=display_vuln_id,
            file_path=file_path,
            line_number=None,
            message=f"{pkg_name}:{pkg_version}:{display_vuln_id}"
        )

        finding = Finding(
            project_id=project_id,
            scan_id=scan_id,
            title=title[:100],
            description=description,
            severity=severity,
            cvss=cvss,
            category="Dependency Vulnerability",
            file_path=file_path,
            line_number=None,
            status=FindingStatus.OPEN,
            source=FindingSource.SCA,
            rule_id=display_vuln_id,
            end_line_number=None,
            code_snippet=code_snippet,
            scanner_name="sca-dependency",
            scanner_version=scanner_version or "sca-dependency 1.0.0",
            fingerprint=fingerprint
        )
        findings.append(finding)

    return findings


def normalize_dast_results(
    results_dict: Dict[str, Any],
    project_id: int,
    scan_id: int,
    scanner_version: str | None = None,
    target_dir: Path | None = None
) -> List[Finding]:
    """Convert raw DAST dynamic web scan results into Kyptic Finding ORM models."""
    findings = []
    raw_results = results_dict.get("results", [])
    if not isinstance(raw_results, list):
        return findings

    for r in raw_results:
        rule_id = r.get("rule_id", "DAST-VULN")
        title = r.get("title", "Dynamic Web Vulnerability Detected")
        summary = r.get("summary", "A security misconfiguration or leak was detected on the target web server.")
        severity_raw = r.get("severity", "MEDIUM")
        severity = normalize_sca_severity(severity_raw)
        
        cvss = parse_cvss_score(r.get("cvss_score")) or parse_cvss_score(r.get("cvss"))
        category = r.get("category", "A05:2021-Security Misconfiguration")
        url_path = r.get("url", "web-target")
        evidence_snippet = r.get("evidence_snippet", f"Target URL: {url_path}")

        fingerprint = generate_fingerprint(
            project_id=project_id,
            scanner_name="dast-web",
            rule_id=rule_id,
            file_path=url_path,
            line_number=None,
            message=f"{rule_id}:{url_path}"
        )

        finding = Finding(
            project_id=project_id,
            scan_id=scan_id,
            title=str(title)[:255],
            description=summary,
            severity=severity,
            cvss=cvss,
            category=category[:255] if category else "Security Misconfiguration",
            file_path=str(url_path)[:500],
            line_number=None,
            status=FindingStatus.OPEN,
            source=FindingSource.DAST,
            rule_id=str(rule_id)[:255] if rule_id else "DAST-VULN",
            end_line_number=None,
            code_snippet=evidence_snippet,
            scanner_name="dast-web",
            scanner_version=scanner_version or "dast-web 1.0.0",
            fingerprint=fingerprint
        )
        findings.append(finding)

    return findings



