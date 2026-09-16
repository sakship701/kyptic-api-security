from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TargetedVerificationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    NOT_CONFIRMED = "NOT_CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_SUPPORTED = "NOT_SUPPORTED"


class TargetedVerificationRequest(BaseModel):
    target_url: str = Field(..., description="Target base URL or full endpoint URL")
    http_method: str = Field(default="GET", description="HTTP method (GET, POST, PUT, DELETE, PATCH)")
    path: str = Field(default="/", description="Endpoint path e.g. /api/v1/users/{id}")
    vulnerability_id: str = Field(..., description="Vulnerability ID or alias e.g. BOLA, BROKEN_AUTH, MASS_ASSIGNMENT, RATE_LIMIT")
    auth_type: Optional[str] = Field(default="NONE", description="Auth type: NONE, BEARER, API_KEY, BASIC")
    auth_header_name: Optional[str] = Field(default="Authorization", description="Header name for auth context")
    auth_token: Optional[str] = Field(default=None, description="Secret token or credential")


class TargetedVerificationResult(BaseModel):
    finding_id: Optional[int] = None
    project_id: Optional[int] = None
    endpoint_id: Optional[int] = None
    target_url: str
    http_method: str
    path: str
    vulnerability_id: str
    vulnerability_family: str
    probe_type: Optional[str] = None
    status: TargetedVerificationStatus
    explanation: str
    evidence: Optional[str] = None
    requests_attempted: int = 0
    responses_observed: List[Dict[str, Any]] = Field(default_factory=list)
    safe_to_execute: bool = True
    execution_metadata: Dict[str, Any] = Field(default_factory=dict)
