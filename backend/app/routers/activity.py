from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies.auth import get_current_user, verify_project_access
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding, FindingStatus
from app.models.user import User

router = APIRouter(prefix="/api", tags=["activity"])


@router.get("/activity")
@router.get("/v1/activity")
def get_activity_feed(
    request: Request,
    project_id: Optional[int] = Query(None, description="Optional project filter"),
    limit: int = Query(10, ge=1, le=50),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[dict]:
    # Determine allowed project IDs
    if project_id is not None:
        verify_project_access(project_id=project_id, request=request, user=user, db=db)
        allowed_project_ids = [project_id]
    else:
        allowed_project_ids = list(
            db.scalars(
                select(Project.id).where(Project.user_id == user.id)
            ).all()
        )

    if not allowed_project_ids:
        return []

    events = []

    # 1. Projects Created
    projects = (
        db.query(Project)
        .filter(Project.id.in_(allowed_project_ids))
        .order_by(Project.created_at.desc())
        .limit(limit)
        .all()
    )

    for p in projects:
        if p.created_at:
            events.append({
                "id": f"proj-{p.id}",
                "type": "PROJECT_CREATED",
                "title": f"Project Created: {p.name}",
                "description": f"Target: {p.target_url or p.repository_url or 'Local Project'}",
                "timestamp": p.created_at.isoformat(),
                "icon": "inventory_2",
                "status": "info",
                "dt": p.created_at,
            })

    # 2. Scans
    scans = (
        db.query(Scan)
        .filter(Scan.project_id.in_(allowed_project_ids))
        .order_by(Scan.started_at.desc())
        .limit(limit)
        .all()
    )

    for s in scans:
        if s.completed_at:
            events.append({
                "id": f"scan-comp-{s.id}",
                "type": "SCAN_COMPLETED",
                "title": f"Scan #{s.id} Completed",
                "description": f"Scanner: {s.scanner or 'Engine'}, Findings: {s.result_count or 0}",
                "timestamp": s.completed_at.isoformat(),
                "icon": "verified_user",
                "status": "success",
                "dt": s.completed_at,
            })
        elif s.started_at:
            events.append({
                "id": f"scan-start-{s.id}",
                "type": "SCAN_STARTED",
                "title": f"Scan #{s.id} Started",
                "description": f"Status: {s.status.value if hasattr(s.status, 'value') else str(s.status)}",
                "timestamp": s.started_at.isoformat(),
                "icon": "radar",
                "status": "primary",
                "dt": s.started_at,
            })

    # 3. Critical / High Findings
    findings = (
        db.query(Finding)
        .filter(Finding.project_id.in_(allowed_project_ids))
        .order_by(Finding.created_at.desc())
        .limit(limit)
        .all()
    )

    for f in findings:
        if f.created_at:
            sev_str = str(f.severity.value if hasattr(f.severity, "value") else f.severity).upper()
            events.append({
                "id": f"finding-{f.id}",
                "type": "FINDING_DETECTED",
                "title": f"{sev_str} Finding: {f.title}",
                "description": f"Location: {f.file_path} ({f.source.value if hasattr(f.source, 'value') else f.source})",
                "timestamp": f.created_at.isoformat(),
                "icon": "warning" if sev_str in ["CRITICAL", "HIGH"] else "info",
                "status": "error" if sev_str == "CRITICAL" else "warning",
                "dt": f.created_at,
            })

    # Sort all events deterministically by timestamp DESC
    events.sort(key=lambda x: x["dt"], reverse=True)
    clean_events = events[:limit]
    for ev in clean_events:
        del ev["dt"]

    return clean_events
