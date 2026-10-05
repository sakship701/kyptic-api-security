from datetime import datetime
from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Request, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies.auth import get_current_user, verify_project_access
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.schemas.project import (
    GitIngestRequest,
    ProjectCreate,
    ProjectResponse,
    ProjectSourceResponse,
    WebsiteIngestRequest,
)
from app.schemas.scan import ScanResponse
from app.services.auth_service import log_audit_event
from app.services.ingestion_service import (
    MAX_UPLOAD_SIZE,
    handle_git_ingestion,
    handle_website_ingestion,
    handle_zip_ingestion,
    validate_git_url,
    validate_website_url,
)
from app.services.scan_service import start_scan_task
from app.services.storage_service import get_project_dir

router = APIRouter(prefix="/api/projects", tags=["projects"])


def enrich_project_response(project: Project, db: Session) -> Project:
    from app.services.posture_service import get_project_posture
    posture = get_project_posture(db, project.id)
    counts = posture.get("counts", {})
    setattr(project, "has_data", posture.get("has_data", False))
    setattr(project, "score", posture.get("score"))
    setattr(project, "critical", counts.get("critical", 0))
    setattr(project, "high", counts.get("high", 0))
    setattr(project, "medium", counts.get("medium", 0))
    setattr(project, "low", counts.get("low", 0))
    setattr(project, "total_findings", posture.get("total_findings", 0))
    return project


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(
    project_data: ProjectCreate,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Project:
    project_values = project_data.model_dump()
    if project_values.get("repository_url") is not None:
        project_values["repository_url"] = str(project_values["repository_url"])
    project_values["user_id"] = user.id

    project = Project(**project_values)
    db.add(project)
    db.commit()
    db.refresh(project)

    ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        user_id=user.id,
        action="PROJECT_CREATED",
        resource_type="project",
        resource_id=str(project.id),
        details=f"User {user.email} created project {project.name}",
        ip_address=ip,
    )

    return enrich_project_response(project, db)


@router.get("", response_model=list[ProjectResponse])
def list_projects(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Project]:
    # Strictly return projects owned by the authenticated user
    projects = list(
        db.scalars(
            select(Project)
            .where(Project.user_id == user.id)
            .order_by(Project.id)
        ).all()
    )
    return [enrich_project_response(p, db) for p in projects]


@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(
    project: Project = Depends(verify_project_access),
    db: Session = Depends(get_db),
) -> Project:
    return enrich_project_response(project, db)


@router.post("/{project_id}/ingest/zip", response_model=ProjectResponse)
async def ingest_zip(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    project: Project = Depends(verify_project_access),
    db: Session = Depends(get_db),
) -> Project:
    project_id = project.id

    # Enforce file size limit
    temp_zip_dir = get_project_dir(project_id)
    temp_zip_dir.mkdir(parents=True, exist_ok=True)
    temp_zip_path = temp_zip_dir / f"upload_{project_id}.zip"

    size = 0
    try:
        with open(temp_zip_path, "wb") as f:
            while True:
                chunk = await file.read(1024 * 1024)  # 1MB chunks
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_UPLOAD_SIZE:
                    f.close()
                    temp_zip_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="File size exceeds maximum limit of 50MB"
                    )
                f.write(chunk)
    except HTTPException:
        raise
    except Exception as e:
        temp_zip_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload zip: {str(e)}"
        )

    # Set state to INGESTING
    project.source_status = "INGESTING"
    project.source_type = "ZIP"
    project.ingestion_error = None
    db.commit()
    db.refresh(project)

    # Add background task for extraction
    background_tasks.add_task(handle_zip_ingestion, project_id, str(temp_zip_path))

    return enrich_project_response(project, db)


@router.post("/{project_id}/ingest/git", response_model=ProjectResponse)
def ingest_git(
    payload: GitIngestRequest,
    background_tasks: BackgroundTasks,
    project: Project = Depends(verify_project_access),
    db: Session = Depends(get_db),
) -> Project:
    project_id = project.id

    # Validate Git URL first
    if not validate_git_url(payload.repository_url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Git Repository URL. Only HTTP/HTTPS URLs are allowed."
        )

    # Set state to INGESTING
    project.source_status = "INGESTING"
    project.source_type = "GIT"
    project.ingestion_error = None
    db.commit()
    db.refresh(project)

    # Add background task for cloning
    background_tasks.add_task(handle_git_ingestion, project_id, payload.repository_url)

    return enrich_project_response(project, db)


@router.post("/{project_id}/ingest/website", response_model=ProjectResponse)
def ingest_website(
    payload: WebsiteIngestRequest,
    project: Project = Depends(verify_project_access),
    db: Session = Depends(get_db),
) -> Project:
    project_id = project.id
    try:
        project = handle_website_ingestion(project_id, payload.target_url, db)
        return enrich_project_response(project, db)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/{project_id}/ingest/openapi")
async def ingest_openapi(
    file: UploadFile = File(...),
    project: Project = Depends(verify_project_access),
    db: Session = Depends(get_db),
) -> dict:
    from app.routers.api_security import ingest_openapi_spec
    return await ingest_openapi_spec(project.id, file, project=project, db=db)


@router.get("/{project_id}/source", response_model=ProjectSourceResponse)
def get_project_source(
    project: Project = Depends(verify_project_access),
) -> dict:
    return {
        "project_id": project.id,
        "source_type": project.source_type,
        "status": project.source_status,
        "target_url": project.target_url,
        "last_ingested_at": project.last_ingested_at,
        "error_message": project.ingestion_error,
    }


@router.post("/{project_id}/scans", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_project_scan(
    project: Project = Depends(verify_project_access),
    db: Session = Depends(get_db),
) -> Scan:
    project_id = project.id
    if not project.source_type or project.source_status != "READY":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Project target or source code is not ready for scanning. Please complete onboarding first."
        )

    scan = Scan(
        project_id=project_id,
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


@router.get("/global/posture")
@router.get("/v1/posture")
def get_global_posture_endpoint(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    from app.services.posture_service import get_global_posture
    return get_global_posture(db, user_id=user.id)


@router.get("/{project_id}/posture")
def get_project_posture_endpoint(
    project: Project = Depends(verify_project_access),
    db: Session = Depends(get_db),
) -> dict:
    from app.services.posture_service import get_project_posture
    return get_project_posture(db, project.id)
