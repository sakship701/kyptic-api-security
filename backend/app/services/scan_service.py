import asyncio
import time
import shutil
from datetime import datetime

from sqlalchemy import delete, select

from app.database import SessionLocal
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.models.scan import Scan, ScanStatus
from app.models.project import Project
from app.services.semgrep_scanner import SemgrepSASTScanner
from app.services.detect_secrets_scanner import DetectSecretsScanner
from app.services.sca_scanner import SCADependencyScanner
from app.services.dast_scanner import DASTWebScanner, DASTStatus
from app.services.finding_normalizer import (
    normalize_semgrep_results,
    normalize_detect_secrets_results,
    normalize_sca_results,
    normalize_dast_results,
)
from app.services.storage_service import get_source_dir

PHASES = (
    (20, "Running SAST"),
    (40, "Running Secret Detection"),
    (60, "Running Dependency Analysis"),
    (80, "Parsing findings"),
    (95, "Saving findings"),
    (100, "Completed"),
)
_scan_tasks: dict[int, asyncio.Task[None]] = {}


def _phase_for_progress(progress: int) -> str:
    for threshold, phase in PHASES:
        if progress < threshold:
            return phase
    return "Finalizing"


async def _run_scan(scan_id: int) -> None:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.status in {ScanStatus.PAUSED, ScanStatus.STOPPED, ScanStatus.FAILED}:
            return
        
        project = db.get(Project, scan.project_id)
        if project is None:
            scan.status = ScanStatus.FAILED
            scan.error_message = "Project not found"
            db.commit()
            return
            
        if not project.source_type or project.source_status != "READY":
            scan.status = ScanStatus.FAILED
            scan.error_message = "Project source code is missing or not ready. Please complete onboarding first."
            db.commit()
            return

        # Start execution
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        scan.current_phase = "Preparing scan"
        scan.progress = 10
        db.commit()

        start_time = time.time()
        combined_findings = []

        # =====================================================================
        # ROUTE 1: WEBSITE Projects -> Run DAST Scanner ONLY
        # =====================================================================
        if project.source_type == "WEBSITE":
            target_url = project.target_url
            if not target_url:
                scan.status = ScanStatus.FAILED
                scan.error_message = "Website projects are DAST targets; target URL is missing."
                db.commit()
                return

            scan.current_phase = "Running DAST Web Scan"
            scan.progress = 40
            db.commit()

            dast_scanner = DASTWebScanner()
            try:
                dast_results = await dast_scanner.scan(target_url)
            except Exception as dast_err:
                dast_results = {
                    "status": DASTStatus.SCANNER_ERROR,
                    "results": [],
                    "error_message": str(dast_err)
                }

            dast_status = dast_results.get("status")
            scan.dast_status = dast_status
            dast_version = dast_results.get("version", "dast-web 1.0.0")

            # Parse findings
            scan.current_phase = "Parsing DAST findings"
            scan.progress = 80
            db.commit()

            dast_findings = normalize_dast_results(
                dast_results,
                project_id=project.id,
                scan_id=scan_id,
                scanner_version=dast_version,
            )
            combined_findings = dast_findings
            scanner_name_str = "dast-web"
            scanner_ver_str = f"dast-web {dast_version}"

        # =====================================================================
        # ROUTE 2: Source Code Projects (ZIP/GIT) -> SAST + Secrets + SCA
        # =====================================================================
        else:
            # Check if semgrep is installed
            semgrep_path = SemgrepSASTScanner()._resolve_semgrep_path()
            if not semgrep_path:
                scan.status = ScanStatus.FAILED
                scan.error_message = (
                    "Semgrep executable not found. Please install Semgrep locally "
                    "(e.g., using 'pip install semgrep') to run SAST scans."
                )
                db.commit()
                return

            source_dir = get_source_dir(project.id)
            if not source_dir.exists():
                scan.status = ScanStatus.FAILED
                scan.error_message = f"Source directory not found: {source_dir}"
                db.commit()
                return

            # 1. Run SAST (Semgrep)
            scan.current_phase = "Running SAST"
            scan.progress = 20
            db.commit()

            sast_scanner = SemgrepSASTScanner()
            sast_results = await sast_scanner.scan(source_dir)
            sast_version = sast_results.get("version")

            # 2. Run Secret Detection (detect-secrets)
            scan.current_phase = "Running Secret Detection"
            scan.progress = 40
            db.commit()

            secrets_scanner = DetectSecretsScanner()
            secrets_results = await secrets_scanner.scan(source_dir)
            secrets_version = secrets_results.get("version")

            # 3. Run SCA / Dependency Analysis
            scan.current_phase = "Running Dependency Analysis"
            scan.progress = 60
            db.commit()

            sca_scanner = SCADependencyScanner()
            try:
                sca_results = await sca_scanner.scan(source_dir)
            except Exception as sca_err:
                sca_results = {
                    "status": "SCANNER_ERROR",
                    "results": [],
                    "error_message": str(sca_err)
                }

            sca_status = sca_results.get("status")
            scan.sca_status = sca_status
            sca_version = sca_results.get("version", "sca-dependency 1.0.0")

            # 4. Parse and normalize findings
            scan.current_phase = "Parsing findings"
            scan.progress = 80
            db.commit()

            sast_findings = normalize_semgrep_results(
                sast_results.get("results", {}),
                project_id=project.id,
                scan_id=scan_id,
                scanner_version=sast_version,
                target_dir=source_dir
            )

            secrets_findings = normalize_detect_secrets_results(
                secrets_results.get("results", {}),
                project_id=project.id,
                scan_id=scan_id,
                scanner_version=secrets_version,
                target_dir=source_dir
            )

            sca_findings = normalize_sca_results(
                sca_results,
                project_id=project.id,
                scan_id=scan_id,
                scanner_version=sca_version,
                target_dir=source_dir
            )

            combined_findings = sast_findings + secrets_findings + sca_findings
            scanner_name_str = "semgrep, detect-secrets, sca-dependency"
            scanner_ver_str = f"semgrep {sast_version or 'unknown'}, detect-secrets {secrets_version or 'unknown'}, sca-dependency 1.0.0"

        duration = time.time() - start_time

        # Remove duplicate findings within this scan
        unique_findings = []
        seen_fingerprints = set()
        for f in combined_findings:
            if f.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(f.fingerprint)
                unique_findings.append(f)

        # Query prior findings for the same project to inherit triaged status
        prior_findings = db.scalars(
            select(Finding).where(Finding.project_id == project.id, Finding.scan_id != scan_id)
        ).all()
        prev_triage_map = {}
        for pf in prior_findings:
            if pf.fingerprint and pf.status in (FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE):
                prev_triage_map[pf.fingerprint] = pf

        for f in unique_findings:
            if f.fingerprint in prev_triage_map:
                prev_f = prev_triage_map[f.fingerprint]
                f.status = prev_f.status
                f.resolution_comment = prev_f.resolution_comment
                f.resolved_at = prev_f.resolved_at

        # Set phase to Saving findings
        scan.current_phase = "Saving findings"
        scan.progress = 95
        db.commit()

        # Persist findings to database
        db.execute(delete(Finding).where(Finding.scan_id == scan_id))
        db.add_all(unique_findings)

        # Completed
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.progress = 100
        scan.current_phase = "Completed"
        scan.scanner = scanner_name_str
        scan.scanner_version = scanner_ver_str
        scan.duration = duration
        scan.result_count = len(unique_findings)
        
        db.commit()

    except asyncio.CancelledError:
        # Task was cancelled (stopped)
        db = SessionLocal()
        try:
            scan = db.get(Scan, scan_id)
            if scan:
                scan.status = ScanStatus.STOPPED
                db.commit()
        except Exception:
            pass
        raise
    except Exception as e:
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            db.commit()
    finally:
        db.close()
        _scan_tasks.pop(scan_id, None)


def start_scan_task(scan_id: int) -> None:
    existing_task = _scan_tasks.get(scan_id)
    if existing_task is None or existing_task.done():
        _scan_tasks[scan_id] = asyncio.create_task(_run_scan(scan_id))


def stop_scan_task(scan_id: int) -> None:
    task = _scan_tasks.pop(scan_id, None)
    if task is not None and not task.done():
        task.cancel()


def resume_pending_scans() -> None:
    db = SessionLocal()
    try:
        pending_scan_ids = db.scalars(
            select(Scan.id).where(Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]))
        ).all()
    finally:
        db.close()
    for scan_id in pending_scan_ids:
        start_scan_task(scan_id)