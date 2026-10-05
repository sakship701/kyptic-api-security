from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies.auth import get_current_user, get_scan_with_ownership_check, verify_project_access
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanResponse
from app.services.scan_service import start_scan_task, stop_scan_task

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_data: ScanCreate,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    project = verify_project_access(project_id=scan_data.project_id, request=request, user=user, db=db)

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
def list_scans(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Scan]:
    # Strictly scope to user's owned projects
    user_project_ids = list(
        db.scalars(
            select(Project.id).where(Project.user_id == user.id)
        ).all()
    )
    if not user_project_ids:
        return []

    return list(
        db.scalars(
            select(Scan)
            .where(Scan.project_id.in_(user_project_ids))
            .order_by(Scan.created_at.desc())
        ).all()
    )


@router.get("/activity")
def get_scan_activity(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    user_project_ids = list(
        db.scalars(
            select(Project.id).where(Project.user_id == user.id)
        ).all()
    )

    if not user_project_ids:
        scans = []
    else:
        scans = db.scalars(select(Scan).where(Scan.project_id.in_(user_project_ids))).all()

    # Map 30-day dates
    now = datetime.utcnow()
    date_map = {}
    for i in range(29, -1, -1):
        day_str = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        date_map[day_str] = 0

    for scan in scans:
        if scan.created_at:
            day_str = scan.created_at.strftime("%Y-%m-%d")
            if day_str in date_map:
                date_map[day_str] += 1

    return [{"date": k, "count": v} for k, v in date_map.items()]


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    return get_scan_with_ownership_check(scan_id, request, user, db)


@router.post("/{scan_id}/pause", response_model=ScanResponse)
def pause_scan(
    scan_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    scan = get_scan_with_ownership_check(scan_id, request, user, db)
    if scan.status != ScanStatus.RUNNING:
        raise HTTPException(status_code=409, detail="Only a running scan can be paused")
    scan.status = ScanStatus.PAUSED
    db.commit()
    db.refresh(scan)
    return scan


@router.post("/{scan_id}/resume", response_model=ScanResponse)
async def resume_scan(
    scan_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    scan = get_scan_with_ownership_check(scan_id, request, user, db)
    if scan.status != ScanStatus.PAUSED:
        raise HTTPException(status_code=409, detail="Only a paused scan can be resumed")
    scan.status = ScanStatus.RUNNING
    db.commit()
    db.refresh(scan)
    start_scan_task(scan.id)
    return scan


@router.post("/{scan_id}/stop", response_model=ScanResponse)
def stop_scan(
    scan_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    scan = get_scan_with_ownership_check(scan_id, request, user, db)
    if scan.status not in {ScanStatus.RUNNING, ScanStatus.PAUSED}:
        raise HTTPException(status_code=409, detail="Only a running or paused scan can be stopped")
    scan.status = ScanStatus.STOPPED
    scan.completed_at = None
    db.commit()
    db.refresh(scan)
    stop_scan_task(scan.id)
    return scan
