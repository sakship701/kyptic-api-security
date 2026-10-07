"""
Centralized, deterministic evidence-based confidence scoring service.

Confidence in Kyptic answers:
"How confident is Kyptic that this finding is a genuine security issue?"

Evaluates objective finding evidence across 5 categories:
1. Detection Source Reliability (Base score 10-30 pts)
2. Evidence Quality & Proof Payload (0-35 pts)
   - Code snippet / proof payload (>10 chars): +10 pts
   - Authoritative CVE / GHSA advisory reference: +10 pts (NVD / OSV advisory record)
   - File asset location present (line_number > 0 OR valid manifest file_path): +5 pts
   - Rule ID or fingerprint present: +5 pts
   - CWE or OWASP taxonomy mapping: +5 pts
3. Dynamic Verification & Exploitability (-35 to +25 pts)
   - VERIFIED / CONFIRMED / VERIFIED_VULNERABLE: +25 pts
   - CORROBORATED: +15 pts
   - UNVERIFIED: 0 pts
   - INCONCLUSIVE: -10 pts
   - FALSE_POSITIVE / NOT_CONFIRMED / VERIFIED_SECURE: -35 pts
4. Independent Multi-Engine Corroboration (0-20 pts)
   - A finding's own single source does NOT count as corroboration.
   - >= 2 genuinely distinct independent scanner engine types: +20 pts
   - >= 1 independent scanner engine type (excluding self-source): +10 pts
   - Same-engine rule correlation (correlation_count >= 1 but no independent engine): +5 pts
   - Self-source only: 0 pts
5. Contradictory / False Positive Penalties (-10 to 0 pts)
   - Dynamic DAST probe attempted but failed on non-secrets static finding: -10 pts

Returns normalized integer score in range [0, 100] and level ('HIGH' | 'MEDIUM' | 'LOW').
Deterministic: identical input evidence always produces the exact same score.
"""

from typing import List, Optional, Set, Tuple


class ConfidenceService:
    @classmethod
    def calculate_confidence(
        cls,
        source: str,
        scanner_name: Optional[str] = None,
        code_snippet: Optional[str] = None,
        file_path: Optional[str] = None,
        line_number: Optional[int] = None,
        cwe: Optional[str] = None,
        owasp: Optional[str] = None,
        rule_id: Optional[str] = None,
        fingerprint: Optional[str] = None,
        verification_status: Optional[str] = None,
        correlation_count: int = 0,
        correlated_sources: Optional[List[str]] = None,
        dast_attempted_and_failed: bool = False,
    ) -> Tuple[int, str]:
        source_str = (source or "").lower()
        scanner_str = (scanner_name or source_str).lower()

        # 1. Detection Source Reliability (10 - 30 pts)
        if scanner_str == "dast-active-probe":
            source_weight = 30
        elif source_str in ("secrets",) or scanner_str == "detect-secrets":
            source_weight = 25
        elif source_str in ("sca",) or scanner_str == "sca-dependency":
            source_weight = 25
        elif source_str in ("sast",) or scanner_str == "semgrep":
            source_weight = 20
        elif source_str in ("api_security",) or scanner_str == "dast-web":
            source_weight = 15
        else:
            source_weight = 10

        # 2. Evidence Quality & Proof Payload (0 - 35 pts)
        evidence_pts = 0

        # 2a. Code snippet / proof payload (+10 pts)
        if code_snippet and len(code_snippet.strip()) > 10:
            evidence_pts += 10

        # 2b. Authoritative CVE / GHSA advisory reference (+10 pts)
        # Reason: CVE/GHSA IDs in rule_id or snippet reference published vulnerability records (NVD/OSV)
        rule_upper = (rule_id or "").upper()
        if "CVE-" in rule_upper or "GHSA-" in rule_upper:
            evidence_pts += 10

        # 2c. File location asset evidence (+5 pts)
        # Line number > 0 OR non-empty file_path (e.g. requirements.txt, package.json, src/file.py)
        if (line_number is not None and line_number > 0) or (file_path and len(file_path.strip()) > 0):
            evidence_pts += 5

        # 2d. Rule ID or fingerprint present (+5 pts)
        if rule_id or fingerprint:
            evidence_pts += 5

        # 2e. CWE or OWASP taxonomy classification (+5 pts)
        if cwe or owasp:
            evidence_pts += 5

        # 3. Dynamic Verification & Exploitability (-35 to +25 pts)
        verif_str = (verification_status or "UNVERIFIED").upper()
        if verif_str in ("VERIFIED", "CONFIRMED", "VERIFIED_VULNERABLE"):
            verif_pts = 25
        elif verif_str in ("CORROBORATED",):
            verif_pts = 15
        elif verif_str in ("UNVERIFIED",):
            verif_pts = 0
        elif verif_str in ("INCONCLUSIVE",):
            verif_pts = -10
        elif verif_str in ("FALSE_POSITIVE", "NOT_CONFIRMED", "VERIFIED_SECURE"):
            verif_pts = -35
        else:
            verif_pts = 0

        # 4. Independent Multi-Engine Corroboration (0 - 20 pts)
        # A finding's own single source MUST NOT count as corroboration.
        corr_pts = 0

        def canonical_source(s_name: str) -> str:
            sn = s_name.lower().strip()
            if "dast-active" in sn or "probe" in sn:
                return "API DAST PROBE"
            if "web" in sn or "dast" in sn:
                return "WEB DAST"
            if "api" in sn:
                return "API SECURITY"
            if "semgrep" in sn or "sast" in sn:
                return "SAST"
            if "detect-secrets" in sn or "secrets" in sn:
                return "SECRETS"
            if "sca" in sn:
                return "SCA"
            return sn.upper()

        own_source = canonical_source(scanner_str or source_str)

        external_sources: Set[str] = set()
        if correlated_sources:
            for s in correlated_sources:
                cs = canonical_source(s)
                if cs != own_source:
                    external_sources.add(cs)

        if len(external_sources) >= 2:
            corr_pts = 20  # >= 2 distinct external scanner engine types
        elif len(external_sources) == 1:
            corr_pts = 10  # 1 independent external scanner engine type
        elif correlation_count >= 1:
            corr_pts = 5   # Same-engine rule correlation

        # 5. Penalties / Contradictory Evidence (-10 to 0 pts)
        penalty_pts = 0
        if dast_attempted_and_failed and source_str not in ("secrets", "sca"):
            penalty_pts += 10

        raw_score = source_weight + evidence_pts + verif_pts + corr_pts - penalty_pts
        score = max(0, min(100, int(round(raw_score))))

        if score >= 80:
            level = "HIGH"
        elif score >= 50:
            level = "MEDIUM"
        else:
            level = "LOW"

        return score, level
