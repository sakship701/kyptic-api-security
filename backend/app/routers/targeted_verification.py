from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.targeted_verification import (
    TargetedVerificationRequest,
    TargetedVerificationResult,
)
from app.security.vulnerability_registry import VulnerabilityDefinition, VulnerabilityRegistry
from app.services.targeted_verification_engine import TargetedVerificationEngine

router = APIRouter(prefix="/api", tags=["targeted-verification"])


@router.get("/vulnerabilities", response_model=List[dict])
def list_vulnerabilities() -> List[dict]:
    """Returns canonical list of all registered vulnerabilities in Kyptic Vulnerability Registry."""
    return [v.to_dict() for v in VulnerabilityRegistry.list_vulnerabilities()]


@router.post(
    "/targeted-verification",
    response_model=TargetedVerificationResult,
)
def run_standalone_targeted_verification(
    req: TargetedVerificationRequest,
    db: Session = Depends(get_db),
) -> TargetedVerificationResult:
    """Executes a standalone targeted verification request against an independent target."""
    engine = TargetedVerificationEngine(db=db)
    return engine.verify_standalone(req)


@router.post(
    "/projects/{project_id}/findings/{finding_id}/verify",
    response_model=TargetedVerificationResult,
)
def verify_existing_finding(
    project_id: int,
    finding_id: int,
    db: Session = Depends(get_db),
) -> TargetedVerificationResult:
    """Executes targeted verification for an existing finding bound to a project and endpoint."""
    engine = TargetedVerificationEngine(db=db)
    return engine.verify_finding(project_id=project_id, finding_id=finding_id)
