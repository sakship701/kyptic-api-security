from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.scan import ScanStatus


class ScanCreate(BaseModel):
    project_id: int


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    status: ScanStatus
    progress: int
    current_phase: str
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    error_message: str | None

    # Scanner details
    scanner: str | None = None
    scanner_version: str | None = None
    sca_status: str | None = None
    dast_status: str | None = None
    duration: float | None = None
    result_count: int | None = None