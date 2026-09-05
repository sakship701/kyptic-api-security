from datetime import datetime
from pydantic import BaseModel, ConfigDict


class ApiEndpointResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    path: str
    method: str
    summary: str | None = None
    operation_id: str | None = None
    auth_status: str
    auth_type: str | None = None
    rate_limit_status: str
    request_validation_status: str
    sensitive_data_fields: str | None = None
    bola_status: str = "NONE"
    mass_assignment_status: str = "NONE"
    dast_status: str = "UNTESTED"
    risk_score: int
    risk_level: str
    discovered_via: str
    created_at: datetime
    updated_at: datetime


class ApiSecuritySummaryResponse(BaseModel):
    total_endpoints: int
    critical_endpoints: int
    high_endpoints: int
    medium_endpoints: int
    low_endpoints: int
    info_endpoints: int
    unauthenticated_endpoints: int
    sensitive_data_endpoints: int
    unconstrained_validation_endpoints: int
    bola_risk_endpoints: int = 0
    mass_assignment_endpoints: int = 0
    missing_rate_limit_endpoints: int = 0
    total_api_findings: int
    open_api_findings: int

    # Phase 3 DAST Verification Summary Metrics
    verified_vulnerable_endpoints: int = 0
    verified_secure_endpoints: int = 0
    inconclusive_endpoints: int = 0
    untested_endpoints: int = 0
    static_findings_count: int = 0
    dast_findings_count: int = 0
    last_dast_scan_status: str | None = None
    last_dast_scan_at: datetime | None = None


class OpenApiIngestResponse(BaseModel):
    project_id: int
    source_type: str
    status: str
    endpoints_count: int
    message: str


class DastTargetConfigRequest(BaseModel):
    api_target_url: str
    api_dast_enabled: bool = True
    api_auth_type: str = "NONE"  # NONE, BEARER, API_KEY, BASIC
    api_auth_header_name: str | None = "Authorization"
    api_auth_token: str | None = None


class DastTargetConfigResponse(BaseModel):
    project_id: int
    api_target_url: str | None = None
    api_dast_enabled: bool = False
    api_auth_type: str | None = "NONE"
    api_auth_header_name: str | None = "Authorization"
    is_ssrf_safe: bool = False
    message: str


class DastTestConnectionResponse(BaseModel):
    status: str  # SUCCESS, FAILED, BLOCKED
    target_url: str
    status_code: int | None = None
    elapsed_ms: float = 0.0
    message: str
