from datetime import datetime

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