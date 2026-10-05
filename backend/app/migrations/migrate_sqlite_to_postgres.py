import json
import os
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(backend_dir))

from app.config import settings
from app.database import Base, get_secret_safe_url
from app.models.api_endpoint import ApiEndpoint
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.models.project import Project
from app.models.scan import Scan, ScanStatus


def parse_datetime(val) -> datetime | None:
    if not val:
        return None
    if isinstance(val, datetime):
        return val
    try:
        return datetime.fromisoformat(str(val))
    except Exception:
        return None


def run_sqlite_to_postgres_migration(
    sqlite_db_path: Path,
    target_engine,
    verbose: bool = True
) -> dict:
    """
    Migrates SQLite project, scan, finding, and endpoint data into target database (PostgreSQL)
    with strict data integrity validation.
    """
    if not sqlite_db_path.exists():
        raise FileNotFoundError(f"Source SQLite database not found at {sqlite_db_path}")

    # 1. Connect to SQLite source
    conn = sqlite3.connect(sqlite_db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    raw_projects = [dict(r) for r in c.execute("SELECT * FROM projects").fetchall()]
    raw_scans = [dict(r) for r in c.execute("SELECT * FROM scans").fetchall()]
    raw_findings = [dict(r) for r in c.execute("SELECT * FROM findings").fetchall()]

    tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    raw_endpoints = []
    if "api_endpoints" in tables:
        raw_endpoints = [dict(r) for r in c.execute("SELECT * FROM api_endpoints").fetchall()]

    if verbose:
        print("--- Migration Source Baseline (SQLite) ---")
        print(f"Projects: {len(raw_projects)}")
        print(f"Scans: {len(raw_scans)}")
        print(f"Findings: {len(raw_findings)}")
        print(f"Endpoints: {len(raw_endpoints)}")

    # 2. Initialize schema in target DB
    Base.metadata.create_all(bind=target_engine)

    # 3. Perform data insertion inside transaction
    with Session(target_engine) as session:
        # Clear target tables if needed or check existing
        existing_projects = session.scalars(select(Project)).all()
        if existing_projects:
            if verbose:
                print(f"Target DB already contains {len(existing_projects)} project(s). Skipping insert.")
        else:
            # Insert Projects
            for p in raw_projects:
                project = Project(
                    id=p["id"],
                    organization_id=p.get("organization_id"),
                    name=p["name"],
                    description=p.get("description"),
                    repository_url=p.get("repository_url"),
                    technology=p.get("technology"),
                    status=p.get("status", "active"),
                    created_at=parse_datetime(p.get("created_at")) or datetime.utcnow(),
                    source_type=p.get("source_type"),
                    source_status=p.get("source_status", "NOT_INGESTED"),
                    local_source_reference=p.get("local_source_reference"),
                    target_url=p.get("target_url"),
                    last_ingested_at=parse_datetime(p.get("last_ingested_at")),
                    ingestion_error=p.get("ingestion_error"),
                    api_target_url=p.get("api_target_url"),
                    api_dast_enabled=bool(p.get("api_dast_enabled", False)),
                    api_auth_type=p.get("api_auth_type", "NONE"),
                    api_auth_header_name=p.get("api_auth_header_name", "Authorization"),
                    api_auth_token_hash=p.get("api_auth_token_hash"),
                )
                session.add(project)

            # Insert Scans
            for s in raw_scans:
                scan = Scan(
                    id=s["id"],
                    project_id=s["project_id"],
                    status=ScanStatus(s.get("status", "completed")),
                    progress=s.get("progress", 100),
                    current_phase=s.get("current_phase", "Completed"),
                    started_at=parse_datetime(s.get("started_at")),
                    completed_at=parse_datetime(s.get("completed_at")),
                    created_at=parse_datetime(s.get("created_at")) or datetime.utcnow(),
                    error_message=s.get("error_message"),
                    scanner=s.get("scanner"),
                    scanner_version=s.get("scanner_version"),
                    sca_status=s.get("sca_status"),
                    dast_status=s.get("dast_status"),
                    duration=s.get("duration"),
                    result_count=s.get("result_count"),
                )
                session.add(scan)

            # Insert Findings
            for f in raw_findings:
                finding = Finding(
                    id=f["id"],
                    project_id=f["project_id"],
                    scan_id=f["scan_id"],
                    title=f["title"],
                    description=f["description"],
                    severity=FindingSeverity(str(f["severity"]).lower()),
                    cvss=f.get("cvss"),
                    category=f["category"],
                    file_path=f["file_path"],
                    line_number=f.get("line_number"),
                    status=FindingStatus(str(f.get("status", "open")).lower()),
                    source=FindingSource(str(f["source"]).lower()),
                    created_at=parse_datetime(f.get("created_at")) or datetime.utcnow(),
                    rule_id=f.get("rule_id"),
                    cwe=f.get("cwe"),
                    owasp=f.get("owasp"),
                    end_line_number=f.get("end_line_number"),
                    code_snippet=f.get("code_snippet"),
                    scanner_name=f.get("scanner_name", "semgrep"),
                    scanner_version=f.get("scanner_version"),
                    fingerprint=f.get("fingerprint"),
                    resolution_comment=f.get("resolution_comment"),
                    resolved_at=parse_datetime(f.get("resolved_at")),
                    confidence_score=f.get("confidence_score", 50),
                    confidence_level=f.get("confidence_level", "MEDIUM"),
                    verification_status=f.get("verification_status", "UNVERIFIED"),
                    verification_explanation=f.get("verification_explanation"),
                    evidence_sources=f.get("evidence_sources"),
                    correlation_count=f.get("correlation_count", 0),
                    correlated_finding_ids=f.get("correlated_finding_ids"),
                )
                session.add(finding)

            # Insert API Endpoints
            for ep in raw_endpoints:
                endpoint = ApiEndpoint(
                    id=ep["id"],
                    project_id=ep["project_id"],
                    path=ep["path"],
                    method=ep["method"],
                    summary=ep.get("summary"),
                    operation_id=ep.get("operation_id"),
                    auth_status=ep.get("auth_status", "UNAUTHENTICATED"),
                    auth_type=ep.get("auth_type", "NONE"),
                    rate_limit_status=ep.get("rate_limit_status", "MISSING"),
                    request_validation_status=ep.get("request_validation_status", "UNCONSTRAINED"),
                    sensitive_data_fields=ep.get("sensitive_data_fields"),
                    risk_score=ep.get("risk_score", 0),
                    risk_level=ep.get("risk_level", "INFO"),
                    bola_status=ep.get("bola_status", "NONE"),
                    mass_assignment_status=ep.get("mass_assignment_status", "NONE"),
                    dast_status=ep.get("dast_status", "UNTESTED"),
                    discovered_via=ep.get("discovered_via", "OPENAPI_SPEC"),
                    created_at=parse_datetime(ep.get("created_at")) or datetime.utcnow(),
                    updated_at=parse_datetime(ep.get("updated_at")) or datetime.utcnow(),
                )
                session.add(endpoint)

            session.commit()

    # 4. Perform Data Integrity Verification
    with Session(target_engine) as session:
        migrated_projects = session.scalars(select(Project)).all()
        migrated_scans = session.scalars(select(Scan)).all()
        migrated_findings = session.scalars(select(Finding)).all()
        migrated_endpoints = session.scalars(select(ApiEndpoint)).all()

        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in migrated_findings:
            sev = str(f.severity.value if hasattr(f.severity, "value") else f.severity).lower()
            if sev in severities:
                severities[sev] += 1

        verification_result = {
            "verified": (
                len(migrated_projects) == len(raw_projects) and
                len(migrated_scans) == len(raw_scans) and
                len(migrated_findings) == len(raw_findings) and
                len(migrated_endpoints) == len(raw_endpoints)
            ),
            "counts": {
                "projects": len(migrated_projects),
                "scans": len(migrated_scans),
                "findings": len(migrated_findings),
                "endpoints": len(migrated_endpoints),
                "severities": severities,
            },
            "expected_counts": {
                "projects": len(raw_projects),
                "scans": len(raw_scans),
                "findings": len(raw_findings),
                "endpoints": len(raw_endpoints),
            }
        }

        if verbose:
            print("\n--- Migration Integrity Verification ---")
            print(f"Verification Status: {'SUCCESS' if verification_result['verified'] else 'FAILED'}")
            print(f"Projects Migrated: {len(migrated_projects)} / {len(raw_projects)}")
            print(f"Scans Migrated: {len(migrated_scans)} / {len(raw_scans)}")
            print(f"Findings Migrated: {len(migrated_findings)} / {len(raw_findings)}")
            print(f"Severity Breakdown: {severities}")

        return verification_result


if __name__ == "__main__":
    sqlite_path = backend_dir / "kyptic.db"
    if not sqlite_path.exists():
        sqlite_path = backend_dir / "kyptic.db.bak"

    target_url = settings.DATABASE_URL
    print(f"Starting SQLite to Target Migration to: {get_secret_safe_url(target_url)}")
    target_engine = create_engine(target_url)
    res = run_sqlite_to_postgres_migration(sqlite_path, target_engine)
    print("Migration result:", json.dumps(res, indent=2))
