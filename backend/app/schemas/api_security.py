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
    total_api_findings: int
    open_api_findings: int


class OpenApiIngestResponse(BaseModel):
    project_id: int
    source_type: str
    status: str
    endpoints_count: int
    message: str
