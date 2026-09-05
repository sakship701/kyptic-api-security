from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.schemas.scan import ScanCreate, ScanResponse
from app.services.scan_service import start_scan_task, stop_scan_task


router = APIRouter(prefix="/api/scans", tags=["scans"])


def get_scan_or_404(scan_id: int, db: Session) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(scan_data: ScanCreate, db: Session = Depends(get_db)) -> Scan:
    project = db.get(Project, scan_data.project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    if not project.source_type or project.source_status != "READY":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Project target or source code is not ready for scanning. Please complete onboarding first."
        )

    scan = Scan(
        project_id=scan_data.project_id,
        status=ScanStatus.RUNNING,
        progress=0,
        current_phase="Preparing source",
        started_at=datetime.utcnow(),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    start_scan_task(scan.id)
    return scan


@router.get("", response_model=list[ScanResponse])
def list_scans(db: Session = Depends(get_db)) -> list[Scan]:
    return list(db.scalars(select(Scan).order_by(Scan.created_at.desc())).all())


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> Scan:
    return get_scan_or_404(scan_id, db)


@router.post("/{scan_id}/pause", response_model=ScanResponse)
def pause_scan(scan_id: int, db: Session = Depends(get_db)) -> Scan:
    scan = get_scan_or_404(scan_id, db)
    if scan.status != ScanStatus.RUNNING:
        raise HTTPException(status_code=409, detail="Only a running scan can be paused")
    scan.status = ScanStatus.PAUSED
    db.commit()
    db.refresh(scan)
    return scan


@router.post("/{scan_id}/resume", response_model=ScanResponse)
async def resume_scan(scan_id: int, db: Session = Depends(get_db)) -> Scan:
    scan = get_scan_or_404(scan_id, db)
    if scan.status != ScanStatus.PAUSED:
        raise HTTPException(status_code=409, detail="Only a paused scan can be resumed")
    scan.status = ScanStatus.RUNNING
    db.commit()
    db.refresh(scan)
    start_scan_task(scan.id)
    return scan


@router.post("/{scan_id}/stop", response_model=ScanResponse)
def stop_scan(scan_id: int, db: Session = Depends(get_db)) -> Scan:
    scan = get_scan_or_404(scan_id, db)
    if scan.status not in {ScanStatus.RUNNING, ScanStatus.PAUSED}:
        raise HTTPException(status_code=409, detail="Only a running or paused scan can be stopped")
    scan.status = ScanStatus.STOPPED
    scan.completed_at = None
    db.commit()
    db.refresh(scan)
    stop_scan_task(scan.id)
    return scan