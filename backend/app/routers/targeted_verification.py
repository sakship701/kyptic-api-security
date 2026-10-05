from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies.auth import get_current_user, get_finding_with_ownership_check, verify_project_access
from app.models.finding import Finding
from app.models.project import Project
from app.models.user import User
from app.schemas.targeted_verification import (
    TargetedVerificationRequest,
    TargetedVerificationResult,
)
from app.security.vulnerability_registry import VulnerabilityDefinition, VulnerabilityRegistry
from app.services.targeted_verification_engine import TargetedVerificationEngine

router = APIRouter(prefix="/api", tags=["targeted-verification"])


@router.get("/vulnerabilities", response_model=List[dict])
def list_vulnerabilities(
    user: User = Depends(get_current_user),
) -> List[dict]:
    """Returns canonical list of all registered vulnerabilities in Kyptic Vulnerability Registry."""
    return [v.to_dict() for v in VulnerabilityRegistry.list_vulnerabilities()]


@router.post(
    "/targeted-verification",
    response_model=TargetedVerificationResult,
)
def run_standalone_targeted_verification(
    req: TargetedVerificationRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TargetedVerificationResult:
    """Executes a standalone targeted verification request for an authenticated user."""
    engine = TargetedVerificationEngine(db=db)
    return engine.verify_standalone(req)


@router.post(
    "/projects/{project_id}/findings/{finding_id}/verify",
    response_model=TargetedVerificationResult,
)
def verify_existing_finding(
    project_id: int,
    finding_id: int,
    project: Project = Depends(verify_project_access),
    db: Session = Depends(get_db),
) -> TargetedVerificationResult:
    """Executes targeted verification for an existing finding bound to the authenticated user's project."""
    finding = db.get(Finding, finding_id)
    if finding is None or finding.project_id != project.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding {finding_id} not found in project {project.id}."
        )

    engine = TargetedVerificationEngine(db=db)
    return engine.verify_finding(project_id=project.id, finding_id=finding_id)
