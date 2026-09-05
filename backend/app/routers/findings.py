from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.schemas.finding import FindingResponse, FindingUpdate


router = APIRouter(prefix="/api", tags=["findings"])


def get_finding_or_404(finding_id: int, db: Session) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.get("/findings", response_model=list[FindingResponse])
def list_findings(
    severity: FindingSeverity | None = None,
    finding_status: FindingStatus | None = None,
    db: Session = Depends(get_db)
) -> list[Finding]:
    query = select(Finding).order_by(Finding.created_at.desc())
    if severity is not None:
        query = query.where(Finding.severity == severity)
    if finding_status is not None:
        query = query.where(Finding.status == finding_status)
    return list(db.scalars(query).all())


@router.get("/findings/summary")
@router.get("/v1/findings/summary")
def get_global_findings_summary(db: Session = Depends(get_db)) -> dict:
    findings = db.scalars(select(Finding)).all()
    open_count = sum(1 for f in findings if f.status == FindingStatus.OPEN)
    resolved_count = sum(1 for f in findings if f.status == FindingStatus.RESOLVED)
    fp_count = sum(1 for f in findings if f.status == FindingStatus.FALSE_POSITIVE)

    critical_count = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    high_count = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
    medium_count = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
    low_count = sum(1 for f in findings if f.severity == FindingSeverity.LOW)
    info_count = sum(1 for f in findings if f.severity == FindingSeverity.INFO)

    return {
        "total": len(findings),
        "open": open_count,
        "resolved": resolved_count,
        "false_positive": fp_count,
        "critical": critical_count,
        "high": high_count,
        "medium": medium_count,
        "low": low_count,
        "info": info_count,
    }


@router.get("/findings/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: int, db: Session = Depends(get_db)) -> Finding:
    return get_finding_or_404(finding_id, db)


@router.patch("/findings/{finding_id}", response_model=FindingResponse)
def update_finding(
    finding_id: int,
    payload: FindingUpdate,
    db: Session = Depends(get_db)
) -> Finding:
    finding = get_finding_or_404(finding_id, db)
    old_status = finding.status
    new_status = payload.status

    if new_status == FindingStatus.OPEN:
        finding.status = FindingStatus.OPEN
        finding.resolved_at = None
        finding.resolution_comment = None
    else:
        finding.status = new_status
        if old_status == FindingStatus.OPEN or finding.resolved_at is None:
            finding.resolved_at = datetime.utcnow()
        if payload.resolution_comment is not None:
            finding.resolution_comment = payload.resolution_comment.strip()

    db.commit()
    db.refresh(finding)
    return finding


@router.get("/projects/{project_id}/findings", response_model=list[FindingResponse])
def list_project_findings(project_id: int, db: Session = Depends(get_db)) -> list[Finding]:
    if db.get(Project, project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return list(db.scalars(select(Finding).where(Finding.project_id == project_id).order_by(Finding.created_at.desc())).all())


@router.get("/projects/{project_id}/findings/summary")
def get_project_findings_summary(project_id: int, db: Session = Depends(get_db)) -> dict:
    if db.get(Project, project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    findings = db.scalars(select(Finding).where(Finding.project_id == project_id)).all()
    open_count = sum(1 for f in findings if f.status == FindingStatus.OPEN)
    resolved_count = sum(1 for f in findings if f.status == FindingStatus.RESOLVED)
    fp_count = sum(1 for f in findings if f.status == FindingStatus.FALSE_POSITIVE)

    # Compute delta baseline against previous completed scan
    scans = db.scalars(
        select(Scan)
        .where(Scan.project_id == project_id, Scan.status == ScanStatus.COMPLETED)
        .order_by(Scan.completed_at.desc(), Scan.id.desc())
    ).all()

    new_count = 0
    recurring_count = 0
    fixed_count = 0

    if len(scans) >= 1:
        latest_scan = scans[0]
        latest_findings = [f for f in findings if f.scan_id == latest_scan.id]
        latest_fps = {f.fingerprint for f in latest_findings if f.fingerprint}

        if len(scans) >= 2:
            prev_scan = scans[1]
            prev_findings = [f for f in findings if f.scan_id == prev_scan.id]
            prev_fps = {f.fingerprint for f in prev_findings if f.fingerprint}

            for f in latest_findings:
                if f.fingerprint in prev_fps:
                    recurring_count += 1
                else:
                    new_count += 1

            fixed_count = len(prev_fps - latest_fps)
        else:
            new_count = len(latest_findings)

    return {
        "open": open_count,
        "resolved": resolved_count,
        "false_positive": fp_count,
        "total": len(findings),
        "new": new_count,
        "recurring": recurring_count,
        "fixed": fixed_count,
    }


@router.get("/scans/{scan_id}/findings", response_model=list[FindingResponse])
def list_scan_findings(scan_id: int, db: Session = Depends(get_db)) -> list[Finding]:
    if db.get(Scan, scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return list(db.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.created_at.desc())).all())