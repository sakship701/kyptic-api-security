import time
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding, FindingStatus, FindingSource
from app.models.api_endpoint import ApiEndpoint
from app.schemas.scan import ScanResponse
from app.schemas.api_security import (
    ApiEndpointResponse,
    ApiSecuritySummaryResponse,
    OpenApiIngestResponse,
)
from app.services.api_spec_parser import OpenApiSpecParser, MAX_SPEC_SIZE
from app.services.api_security_scanner import ApiSecurityScanner
from app.services.storage_service import get_project_dir

router = APIRouter(prefix="/api", tags=["api-security"])


@router.post(
    "/projects/{project_id}/ingest/openapi",
    response_model=OpenApiIngestResponse,
    status_code=status.HTTP_200_OK,
)
async def ingest_openapi_spec(
    project_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> dict:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    # Enforce Upload File Size
    content_bytes = await file.read()
    if len(content_bytes) > MAX_SPEC_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Specification file size exceeds maximum limit of 50MB"
        )

    # Parse and Validate Specification
    try:
        parser = OpenApiSpecParser(content_bytes)
        endpoints_data = parser.extract_endpoints()
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed or unsupported OpenAPI specification: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to process specification file: {str(e)}"
        )

    if not endpoints_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Specification contains no valid paths or operations."
        )

    # Store spec file safely in project directory
    project_dir = get_project_dir(project_id)
    project_dir.mkdir(parents=True, exist_ok=True)
    filename = file.filename or "openapi_spec.json"
    spec_save_path = project_dir / "openapi_spec.raw"
    spec_save_path.write_bytes(content_bytes)

    # Delete previous endpoint inventory for this project
    db.execute(delete(ApiEndpoint).where(ApiEndpoint.project_id == project_id))

    # Initialize new endpoints in DB
    scanner = ApiSecurityScanner(project_id=project_id, scan_id=0)
    created_endpoints = []
    for ep_info in endpoints_data:
        ep_dict, _ = scanner.analyze_endpoint(ep_info)
        endpoint_obj = ApiEndpoint(**ep_dict)
        created_endpoints.append(endpoint_obj)

    db.add_all(created_endpoints)

    # Update project state
    project.source_type = "OPENAPI"
    project.source_status = "READY"
    project.local_source_reference = str(spec_save_path)
    project.last_ingested_at = datetime.utcnow()
    project.ingestion_error = None
    db.commit()

    return {
        "project_id": project_id,
        "source_type": "OPENAPI",
        "status": "READY",
        "endpoints_count": len(created_endpoints),
        "message": f"Successfully ingested {len(created_endpoints)} API endpoints from {parser.get_version()} specification."
    }


@router.post(
    "/projects/{project_id}/api-security/analyze",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
)
def run_api_security_analysis(
    project_id: int,
    db: Session = Depends(get_db),
) -> Scan:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    if not project.source_type or project.source_status != "READY":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Project source is missing or not ready. Please ingest an OpenAPI specification first."
        )

    # Load stored specification file if available
    spec_file = get_project_dir(project_id) / "openapi_spec.raw"
    if not spec_file.exists():
        raise HTTPException(
            status_code=404,
            detail="OpenAPI specification source file not found for this project."
        )

    start_time = time.time()

    # Create Scan Record
    scan = Scan(
        project_id=project_id,
        status=ScanStatus.RUNNING,
        progress=10,
        current_phase="Parsing OpenAPI Specification",
        started_at=datetime.utcnow(),
        scanner="api-security",
        scanner_version="api-security 1.0.0"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        parser = OpenApiSpecParser(spec_file.read_bytes())
        endpoints_data = parser.extract_endpoints()

        scan.progress = 50
        scan.current_phase = "Auditing API Endpoints & Risk Rules"
        db.commit()

        scanner = ApiSecurityScanner(project_id=project_id, scan_id=scan.id)
        all_findings: List[Finding] = []
        
        # Clear existing endpoints and update with fresh scan analysis
        db.execute(delete(ApiEndpoint).where(ApiEndpoint.project_id == project_id))

        for ep_info in endpoints_data:
            ep_dict, ep_findings = scanner.analyze_endpoint(ep_info)
            endpoint_obj = ApiEndpoint(**ep_dict)
            db.add(endpoint_obj)
            all_findings.extend(ep_findings)

        # Deduplicate findings by fingerprint
        unique_findings: List[Finding] = []
        seen_fps = set()
        for f in all_findings:
            if f.fingerprint not in seen_fps:
                seen_fps.add(f.fingerprint)
                unique_findings.append(f)

        # Preserve prior triage status (RESOLVED/FALSE_POSITIVE) for matching fingerprints
        prior_findings = db.scalars(
            select(Finding).where(Finding.project_id == project_id, Finding.scan_id != scan.id)
        ).all()
        prev_triage_map = {
            pf.fingerprint: pf for pf in prior_findings 
            if pf.fingerprint and pf.status in (FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE)
        }

        for f in unique_findings:
            if f.fingerprint in prev_triage_map:
                prev_f = prev_triage_map[f.fingerprint]
                f.status = prev_f.status
                f.resolution_comment = prev_f.resolution_comment
                f.resolved_at = prev_f.resolved_at

        # Save findings to database
        db.execute(delete(Finding).where(Finding.scan_id == scan.id))
        db.add_all(unique_findings)

        duration = time.time() - start_time
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.progress = 100
        scan.current_phase = "Completed"
        scan.duration = duration
        scan.result_count = len(unique_findings)
        db.commit()
        db.refresh(scan)

        return scan
    except Exception as e:
        db.rollback()
        scan.status = ScanStatus.FAILED
        scan.error_message = str(e)
        db.commit()
        db.refresh(scan)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"API security analysis failed: {str(e)}"
        )


@router.get(
    "/projects/{project_id}/api-security/endpoints",
    response_model=list[ApiEndpointResponse],
)
def list_api_endpoints(
    project_id: int,
    db: Session = Depends(get_db),
) -> list[ApiEndpoint]:
    if db.get(Project, project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    endpoints = list(
        db.scalars(
            select(ApiEndpoint)
            .where(ApiEndpoint.project_id == project_id)
            .order_by(ApiEndpoint.risk_score.desc(), ApiEndpoint.path)
        ).all()
    )
    return endpoints


@router.get(
    "/projects/{project_id}/api-security/endpoints/{endpoint_id}",
    response_model=ApiEndpointResponse,
)
def get_api_endpoint(
    project_id: int,
    endpoint_id: int,
    db: Session = Depends(get_db),
) -> ApiEndpoint:
    if db.get(Project, project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    endpoint = db.get(ApiEndpoint, endpoint_id)
    if endpoint is None or endpoint.project_id != project_id:
        raise HTTPException(status_code=404, detail="API Endpoint not found")

    return endpoint


@router.get(
    "/projects/{project_id}/api-security/summary",
    response_model=ApiSecuritySummaryResponse,
)
def get_api_security_summary(
    project_id: int,
    db: Session = Depends(get_db),
) -> dict:
    if db.get(Project, project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    endpoints = list(db.scalars(select(ApiEndpoint).where(ApiEndpoint.project_id == project_id)).all())
    findings = list(
        db.scalars(
            select(Finding).where(
                Finding.project_id == project_id,
                Finding.source == FindingSource.API_SECURITY
            )
        ).all()
    )

    total_endpoints = len(endpoints)
    critical_ep = sum(1 for e in endpoints if e.risk_level == "CRITICAL")
    high_ep = sum(1 for e in endpoints if e.risk_level == "HIGH")
    medium_ep = sum(1 for e in endpoints if e.risk_level == "MEDIUM")
    low_ep = sum(1 for e in endpoints if e.risk_level == "LOW")
    info_ep = sum(1 for e in endpoints if e.risk_level == "INFO")

    unauthenticated_ep = sum(1 for e in endpoints if e.auth_status == "UNAUTHENTICATED")
    sensitive_data_ep = sum(1 for e in endpoints if e.sensitive_data_fields is not None and len(e.sensitive_data_fields) > 0)
    unconstrained_val_ep = sum(1 for e in endpoints if e.request_validation_status == "UNCONSTRAINED")

    total_api_findings = len(findings)
    open_api_findings = sum(1 for f in findings if f.status == FindingStatus.OPEN)

    return {
        "total_endpoints": total_endpoints,
        "critical_endpoints": critical_ep,
        "high_endpoints": high_ep,
        "medium_endpoints": medium_ep,
        "low_endpoints": low_ep,
        "info_endpoints": info_ep,
        "unauthenticated_endpoints": unauthenticated_ep,
        "sensitive_data_endpoints": sensitive_data_ep,
        "unconstrained_validation_endpoints": unconstrained_val_ep,
        "total_api_findings": total_api_findings,
        "open_api_findings": open_api_findings,
    }
