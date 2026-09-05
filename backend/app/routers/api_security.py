import time
from datetime import datetime
from pathlib import Path
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
    DastTargetConfigRequest,
    DastTargetConfigResponse,
    DastTestConnectionResponse,
)
from app.services.api_spec_parser import OpenApiSpecParser, MAX_SPEC_SIZE
from app.services.api_security_scanner import ApiSecurityScanner, run_static_api_analysis
from app.services.storage_service import get_project_dir
from app.services.ssrf_protection import is_ssrf_safe_url
from app.services.dast_http_client import DastHttpClient, DastAuthContext, redact_secrets, DastError
from app.services.dast_probes import DastProbeEngine, DastVerificationStatus, map_probe_result_to_finding, run_active_dast_probes

router = APIRouter(prefix="/api", tags=["api-security"])


@router.get(
    "/projects/{project_id}/api-security/dast-config",
    response_model=DastTargetConfigResponse,
)
def get_dast_config(
    project_id: int,
    db: Session = Depends(get_db),
) -> dict:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    target_url = project.api_target_url
    is_safe = False
    msg = "No live DAST target URL configured."
    if target_url:
        is_safe, msg = is_ssrf_safe_url(target_url, allow_localhost=False)

    return {
        "project_id": project_id,
        "api_target_url": target_url,
        "api_dast_enabled": project.api_dast_enabled,
        "api_auth_type": project.api_auth_type or "NONE",
        "api_auth_header_name": project.api_auth_header_name or "Authorization",
        "is_ssrf_safe": is_safe,
        "message": msg,
    }


@router.put(
    "/projects/{project_id}/api-security/dast-config",
    response_model=DastTargetConfigResponse,
)
def update_dast_config(
    project_id: int,
    config_in: DastTargetConfigRequest,
    db: Session = Depends(get_db),
) -> dict:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    target_url = config_in.api_target_url.strip()
    is_safe, msg = is_ssrf_safe_url(target_url, allow_localhost=False)
    if not is_safe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target URL SSRF validation failed: {msg}"
        )

    project.api_target_url = target_url
    project.api_dast_enabled = config_in.api_dast_enabled
    project.api_auth_type = (config_in.api_auth_type or "NONE").upper()
    project.api_auth_header_name = config_in.api_auth_header_name or "Authorization"
    db.commit()

    return {
        "project_id": project_id,
        "api_target_url": target_url,
        "api_dast_enabled": project.api_dast_enabled,
        "api_auth_type": project.api_auth_type,
        "api_auth_header_name": project.api_auth_header_name,
        "is_ssrf_safe": True,
        "message": "DAST target configuration updated successfully."
    }


@router.post(
    "/projects/{project_id}/api-security/dast/test-connection",
    response_model=DastTestConnectionResponse,
)
def test_dast_connection(
    project_id: int,
    db: Session = Depends(get_db),
) -> dict:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    target_url = project.api_target_url
    if not target_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No DAST target URL configured for this project. Update DAST configuration first."
        )

    is_safe, ssrf_msg = is_ssrf_safe_url(target_url, allow_localhost=False)
    if not is_safe:
        return {
            "status": "BLOCKED",
            "target_url": target_url,
            "status_code": None,
            "elapsed_ms": 0.0,
            "message": redact_secrets(f"SSRF validation blocked request: {ssrf_msg}")
        }

    client = DastHttpClient(allow_localhost=False)
    auth_ctx = DastAuthContext(
        auth_type=project.api_auth_type or "NONE",
        header_name=project.api_auth_header_name or "Authorization"
    )

    try:
        response = client.execute_request(
            url=target_url,
            method="HEAD",
            auth_context=auth_ctx,
            timeout=5.0
        )
        return {
            "status": "SUCCESS" if response.status_code and response.status_code < 500 else "FAILED",
            "target_url": target_url,
            "status_code": response.status_code,
            "elapsed_ms": response.elapsed_ms,
            "message": f"Successfully connected to live target (HTTP {response.status_code})."
        }
    except DastError as e:
        return {
            "status": "FAILED",
            "target_url": target_url,
            "status_code": None,
            "elapsed_ms": 0.0,
            "message": redact_secrets(str(e))
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "target_url": target_url,
            "status_code": None,
            "elapsed_ms": 0.0,
            "message": redact_secrets(f"Connection test failed: {str(e)}")
        }

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

    # Enforce Upload File Extension & Path Traversal Guard
    raw_filename = file.filename or "openapi_spec.json"
    safe_filename = Path(raw_filename).name
    ext = Path(safe_filename).suffix.lower()
    if ext not in (".json", ".yaml", ".yml"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported specification file format. Only .json, .yaml, and .yml extensions are accepted."
        )

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
            detail="Failed to process specification file."
        )

    if not endpoints_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Specification contains no valid paths or operations."
        )

    # Store spec file safely in project directory
    project_dir = get_project_dir(project_id)
    project_dir.mkdir(parents=True, exist_ok=True)
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
        created_endpoints, static_findings = run_static_api_analysis(
            db=db, project_id=project_id, scan_id=scan.id
        )

        scan.progress = 50
        scan.current_phase = "Auditing API Endpoints & Risk Rules"
        db.commit()

        # Deduplicate findings by fingerprint
        unique_findings: List[Finding] = []
        seen_fps = set()
        for f in static_findings:
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


@router.post(
    "/projects/{project_id}/api-security/dast/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
)
def run_dast_active_scan(
    project_id: int,
    db: Session = Depends(get_db),
) -> Scan:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    if not project.api_dast_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="DAST dynamic testing is disabled for this project. Enable DAST in project settings first."
        )

    target_url = project.api_target_url
    if not target_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No DAST target URL configured for this project."
        )

    is_safe, ssrf_msg = is_ssrf_safe_url(target_url, allow_localhost=False)
    if not is_safe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target URL SSRF validation failed: {ssrf_msg}"
        )

    endpoints = list(db.scalars(select(ApiEndpoint).where(ApiEndpoint.project_id == project_id)).all())
    if not endpoints:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No endpoints found in inventory to scan. Ingest an OpenAPI spec first."
        )

    # Phase 3A: Check if a DAST scan is already running
    existing_running_scan = db.scalar(
        select(Scan).where(
            Scan.project_id == project_id,
            Scan.status == ScanStatus.RUNNING,
            Scan.scanner == "dast-active-probe"
        )
    )
    if existing_running_scan:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A DAST active verification scan is currently running for this project."
        )

    # 1. QUEUED lifecycle state
    scan = Scan(
        project_id=project_id,
        status=ScanStatus.QUEUED,
        progress=0,
        current_phase="Queued",
        scanner="dast-active-probe",
        scanner_version="1.0.0",
        dast_status="QUEUED",
        started_at=datetime.utcnow(),
        target_path=target_url,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # 2. RUNNING lifecycle state
    scan.status = ScanStatus.RUNNING
    scan.current_phase = "Running Dynamic Probes"
    scan.dast_status = "RUNNING"
    db.commit()

    start_time = time.time()

    try:
        def update_progress(idx, total):
            scan.progress = int((idx / total) * 100)
            db.commit()

        new_findings = run_active_dast_probes(
            db=db,
            project=project,
            scan_id=scan.id,
            endpoints=endpoints,
            existing_findings_map=existing_findings_map,
            progress_callback=update_progress,
        )

        if new_findings:
            db.add_all(new_findings)

        duration = round(time.time() - start_time, 2)
        scan.status = ScanStatus.COMPLETED
        scan.current_phase = "Completed"
        scan.dast_status = "COMPLETED"
        scan.completed_at = datetime.utcnow()
        scan.duration = duration
        scan.result_count = len(new_findings)
        scan.progress = 100
        db.commit()
        db.refresh(scan)

        return scan
    except Exception as e:
        db.rollback()
        scan.status = ScanStatus.FAILED
        scan.dast_status = "FAILED"
        scan.current_phase = "Failed"
        scan.completed_at = datetime.utcnow()
        scan.error_message = redact_secrets(str(e))
        db.commit()
        db.refresh(scan)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"DAST scan failed: {redact_secrets(str(e))}"
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
                Finding.source.in_([FindingSource.API_SECURITY, FindingSource.DAST])
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

    bola_risk_ep = sum(1 for e in endpoints if getattr(e, "bola_status", "NONE") != "NONE")
    mass_assign_ep = sum(1 for e in endpoints if getattr(e, "mass_assignment_status", "NONE") != "NONE")
    missing_rate_limit_ep = sum(1 for e in endpoints if e.rate_limit_status == "MISSING")

    total_api_findings = len(findings)
    open_api_findings = sum(1 for f in findings if f.status == FindingStatus.OPEN)

    verified_vulnerable_ep = sum(1 for e in endpoints if getattr(e, "dast_status", "UNTESTED") == "VERIFIED_VULNERABLE")
    verified_secure_ep = sum(1 for e in endpoints if getattr(e, "dast_status", "UNTESTED") == "VERIFIED_SECURE")
    inconclusive_ep = sum(1 for e in endpoints if getattr(e, "dast_status", "UNTESTED") == "INCONCLUSIVE")
    untested_ep = sum(1 for e in endpoints if getattr(e, "dast_status", "UNTESTED") == "UNTESTED")

    static_findings_count = sum(1 for f in findings if f.source == FindingSource.API_SECURITY)
    dast_findings_count = sum(1 for f in findings if f.source == FindingSource.DAST)

    last_dast_scan = db.scalar(
        select(Scan)
        .where(Scan.project_id == project_id, Scan.scanner == "dast-active-probe")
        .order_by(Scan.id.desc())
    )

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
        "bola_risk_endpoints": bola_risk_ep,
        "mass_assignment_endpoints": mass_assign_ep,
        "missing_rate_limit_endpoints": missing_rate_limit_ep,
        "total_api_findings": total_api_findings,
        "open_api_findings": open_api_findings,
        "verified_vulnerable_endpoints": verified_vulnerable_ep,
        "verified_secure_endpoints": verified_secure_ep,
        "inconclusive_endpoints": inconclusive_ep,
        "untested_endpoints": untested_ep,
        "static_findings_count": static_findings_count,
        "dast_findings_count": dast_findings_count,
        "last_dast_scan_status": last_dast_scan.status.value if (last_dast_scan and last_dast_scan.status) else None,
        "last_dast_scan_at": (last_dast_scan.completed_at or last_dast_scan.started_at) if last_dast_scan else None,
    }
