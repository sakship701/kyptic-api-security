from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.project import Project
from app.schemas.compliance import ComplianceResponse
from app.services.compliance_service import ComplianceService

router = APIRouter(tags=["compliance"])


@router.get("/api/v1/projects/{project_id}/compliance", response_model=ComplianceResponse)
@router.get("/api/projects/{project_id}/compliance", response_model=ComplianceResponse)
def get_project_compliance(
    project_id: int,
    framework: Optional[str] = Query("PCI_DSS", description="Framework key (PCI_DSS, SOC_2, ISO_27001, OWASP_API_TOP_10, OWASP_TOP_10, CWE)"),
    db: Session = Depends(get_db),
) -> ComplianceResponse:
    if db.get(Project, project_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Project {project_id} not found")

    try:
        return ComplianceService.evaluate_compliance(
            db=db,
            project_id=project_id,
            framework=framework or "PCI_DSS",
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
