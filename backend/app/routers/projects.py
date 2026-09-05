from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, UploadFile, File
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.project import Project
from datetime import datetime
from app.models.scan import Scan, ScanStatus
from app.schemas.scan import ScanResponse
from app.services.scan_service import start_scan_task
from app.schemas.project import (
    ProjectCreate,
    ProjectResponse,
    ProjectSourceResponse,
    GitIngestRequest,
    WebsiteIngestRequest,
)
from app.services.ingestion_service import (
    handle_zip_ingestion,
    handle_git_ingestion,
    handle_website_ingestion,
    MAX_UPLOAD_SIZE,
    validate_git_url,
    validate_website_url,
)
from app.services.storage_service import get_project_dir

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(project_data: ProjectCreate, db: Session = Depends(get_db)) -> Project:
    project_values = project_data.model_dump()
    if project_values["repository_url"] is not None:
        project_values["repository_url"] = str(project_values["repository_url"])
    project = Project(**project_values)
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@router.get("", response_model=list[ProjectResponse])
def list_projects(db: Session = Depends(get_db)) -> list[Project]:
    return list(db.scalars(select(Project).order_by(Project.id)).all())


@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(project_id: int, db: Session = Depends(get_db)) -> Project:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.post("/{project_id}/ingest/zip", response_model=ProjectResponse)
async def ingest_zip(
    project_id: int,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> Project:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

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

    return project


@router.post("/{project_id}/ingest/git", response_model=ProjectResponse)
def ingest_git(
    project_id: int,
    payload: GitIngestRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> Project:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

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

    return project


@router.post("/{project_id}/ingest/website", response_model=ProjectResponse)
def ingest_website(
    project_id: int,
    payload: WebsiteIngestRequest,
    db: Session = Depends(get_db),
) -> Project:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        project = handle_website_ingestion(project_id, payload.target_url, db)
        return project
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/{project_id}/ingest/openapi")
async def ingest_openapi(
    project_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> dict:
    from app.routers.api_security import ingest_openapi_spec
    return await ingest_openapi_spec(project_id, file, db)


@router.get("/{project_id}/source", response_model=ProjectSourceResponse)
def get_project_source(project_id: int, db: Session = Depends(get_db)) -> dict:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    return {
        "project_id": project.id,
        "source_type": project.source_type,
        "status": project.source_status,
        "target_url": project.target_url,
        "last_ingested_at": project.last_ingested_at,
        "error_message": project.ingestion_error,
    }


@router.post("/{project_id}/scans", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_project_scan(project_id: int, db: Session = Depends(get_db)) -> Scan:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

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
