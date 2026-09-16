from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.finding import FindingSeverity, FindingSource, FindingStatus


class FindingUpdate(BaseModel):
    status: FindingStatus
    resolution_comment: str | None = Field(default=None, max_length=1000)

    @field_validator("resolution_comment")
    @classmethod
    def validate_comment_length(cls, v: str | None) -> str | None:
        if v is not None and len(v) > 1000:
            raise ValueError("Resolution comment must not exceed 1000 characters.")
        return v


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    scan_id: int
    title: str
    description: str
    severity: FindingSeverity
    cvss: float | None = None
    category: str
    file_path: str
    line_number: int | None
    status: FindingStatus
    source: FindingSource
    created_at: datetime

    # SAST Specific Evidence & Metadata
    rule_id: str | None = None
    cwe: str | None = None
    owasp: str | None = None
    end_line_number: int | None = None
    code_snippet: str | None = None
    scanner_name: str | None = None
    scanner_version: str | None = None
    fingerprint: str | None = None

    # Triage & Lifecycle Metadata
    resolution_comment: str | None = None
    resolved_at: datetime | None = None

    # Phase 2: Cross-Validation & Confidence Metadata
    confidence_score: int = 50
    confidence_level: str = "MEDIUM"
    verification_status: str = "UNVERIFIED"
    verification_explanation: str | None = None
    evidence_sources: str | None = None
    correlation_count: int = 0
    correlated_finding_ids: str | None = None

    @field_validator("confidence_score", mode="before")
    @classmethod
    def default_confidence_score(cls, v: Any) -> int:
        return 50 if v is None else v

    @field_validator("confidence_level", mode="before")
    @classmethod
    def default_confidence_level(cls, v: Any) -> str:
        return "MEDIUM" if v is None else v

    @field_validator("verification_status", mode="before")
    @classmethod
    def default_verification_status(cls, v: Any) -> str:
        return "UNVERIFIED" if v is None else v

    @field_validator("correlation_count", mode="before")
    @classmethod
    def default_correlation_count(cls, v: Any) -> int:
        return 0 if v is None else v

    @field_validator("verification_explanation", mode="before")
    @classmethod
    def default_verification_explanation(cls, v: Any) -> str | None:
        if v is None:
            return "Legacy record (no cross-validation metadata calculated)."
        return v
