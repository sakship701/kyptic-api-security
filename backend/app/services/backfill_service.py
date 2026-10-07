"""
Backfill Service: Idempotent recalculation of CVSS provenance and confidence scores for historical project findings.
"""

from typing import Any, Dict, List
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.services.confidence_service import ConfidenceService


def recalculate_project_findings(
    db: Session,
    project_id: int,
    dry_run: bool = False
) -> List[Dict[str, Any]]:
    """
    Safely and idempotently recalculates CVSS provenance and evidence-based confidence scores
    for all existing findings in a project.

    - Clears un-provenanced/unsupported historical CVSS fallbacks (e.g., detect-secrets 8.1).
    - Preserves authoritative CVSS scores with valid provenance.
    - Recalculates confidence scores via ConfidenceService.
    - Operates within a single transaction; rolls back on failure or in dry-run mode.
    """
    findings = db.query(Finding).filter(Finding.project_id == project_id).all()
    if not findings:
        return []

    changes_summary = []

    try:
        for f in findings:
            old_cvss = float(f.cvss) if f.cvss is not None else None
            old_cvss_source = f.cvss_source
            old_cvss_vector = f.cvss_vector
            old_cvss_version = f.cvss_version
            old_conf_score = f.confidence_score
            old_conf_level = f.confidence_level

            source_str = (f.source.value if hasattr(f.source, "value") else str(f.source)).lower()
            scanner_name = (f.scanner_name or source_str).lower()

            # 1. Determine new CVSS Provenance
            if source_str == "secrets" or scanner_name == "detect-secrets":
                new_cvss = None
                new_cvss_vector = None
                new_cvss_source = None
                new_cvss_version = None
            else:
                # If finding already has an explicit cvss_source or cvss_vector, preserve
                if f.cvss_source or f.cvss_vector:
                    new_cvss = old_cvss
                    new_cvss_vector = f.cvss_vector
                    new_cvss_source = f.cvss_source
                    new_cvss_version = f.cvss_version
                elif old_cvss is not None and f.rule_id and (f.rule_id.startswith("CVE-") or f.rule_id.startswith("GHSA-")):
                    # Authoritative CVE/GHSA advisory from SCA
                    new_cvss = old_cvss
                    new_cvss_vector = None
                    new_cvss_source = "OSV / NVD Advisory"
                    new_cvss_version = "3.1"
                else:
                    # Unprovenanced historical score -> clear to None
                    new_cvss = None
                    new_cvss_vector = None
                    new_cvss_source = None
                    new_cvss_version = None

            # 2. Recalculate Evidence-Based Confidence
            correlated_sources_list = []
            if f.evidence_sources:
                correlated_sources_list = [s.strip() for s in f.evidence_sources.split(",") if s.strip()]

            new_conf_score, new_conf_level = ConfidenceService.calculate_confidence(
                source=source_str,
                scanner_name=f.scanner_name,
                code_snippet=f.code_snippet,
                file_path=f.file_path,
                line_number=f.line_number,
                cwe=f.cwe,
                owasp=f.owasp,
                rule_id=f.rule_id,
                fingerprint=f.fingerprint,
                verification_status=f.verification_status,
                correlation_count=f.correlation_count or 0,
                correlated_sources=correlated_sources_list,
                dast_attempted_and_failed=False,
            )

            changed = (
                old_cvss != new_cvss
                or old_cvss_source != new_cvss_source
                or old_cvss_vector != new_cvss_vector
                or old_cvss_version != new_cvss_version
                or old_conf_score != new_conf_score
                or old_conf_level != new_conf_level
            )

            changes_summary.append({
                "finding_id": f.id,
                "title": f.title,
                "source": source_str,
                "verification_status": f.verification_status,
                "old_cvss": old_cvss,
                "new_cvss": new_cvss,
                "old_cvss_source": old_cvss_source,
                "new_cvss_source": new_cvss_source,
                "old_confidence": old_conf_score,
                "new_confidence": new_conf_score,
                "old_confidence_level": old_conf_level,
                "new_confidence_level": new_conf_level,
                "changed": changed,
            })

            if not dry_run and changed:
                f.cvss = new_cvss
                f.cvss_vector = new_cvss_vector
                f.cvss_source = new_cvss_source
                f.cvss_version = new_cvss_version
                f.confidence_score = new_conf_score
                f.confidence_level = new_conf_level

        if dry_run:
            db.rollback()
        else:
            db.commit()

        return changes_summary

    except Exception:
        db.rollback()
        raise
