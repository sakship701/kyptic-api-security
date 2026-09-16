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
from app.services.storage_service import get_source_dir, get_project_dir
from app.services.api_security_scanner import run_static_api_analysis
from app.services.dast_probes import run_active_dast_probes
from app.services.ssrf_protection import is_ssrf_safe_url
from app.services.scan_orchestrator import ScanOrchestrator

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
        orchestrator = ScanOrchestrator(db, scan_id)
        await orchestrator.execute()
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
