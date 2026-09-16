from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.project import Project
from app.schemas.risk_map import RiskMapGraphResponse
from app.services.risk_map_service import RiskMapService

router = APIRouter(tags=["risk_map"])


@router.get("/api/v1/projects/{project_id}/risk-map", response_model=RiskMapGraphResponse)
@router.get("/api/projects/{project_id}/risk-map", response_model=RiskMapGraphResponse)
def get_project_risk_map(
    project_id: int,
    severity: Optional[str] = Query(None, description="Filter by finding severity (critical, high, medium, low)"),
    verification_status: Optional[str] = Query(None, description="Filter by verification status (CONFIRMED, UNVERIFIED, etc.)"),
    vulnerability_type: Optional[str] = Query(None, description="Filter by vulnerability category or CWE"),
    min_risk_score: Optional[int] = Query(None, ge=0, le=100, description="Minimum risk score threshold"),
    db: Session = Depends(get_db),
) -> RiskMapGraphResponse:
    if db.get(Project, project_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Project {project_id} not found")

    try:
        return RiskMapService.generate_graph(
            db=db,
            project_id=project_id,
            severity_filter=severity,
            verification_status_filter=verification_status,
            vuln_type_filter=vulnerability_type,
            min_risk_score=min_risk_score,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
