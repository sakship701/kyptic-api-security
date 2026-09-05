from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    repository_url: str | None = None
    technology: str | None = Field(default=None, max_length=255)
    status: str = Field(default="active", max_length=50)
    source_type: str | None = None
    target_url: str | None = None


class ProjectResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    repository_url: str | None
    technology: str | None
    status: str
    created_at: datetime
    
    # Ingestion details
    source_type: str | None = None
    source_status: str = "NOT_INGESTED"
    local_source_reference: str | None = None
    target_url: str | None = None
    last_ingested_at: datetime | None = None
    ingestion_error: str | None = None


class ProjectSourceResponse(BaseModel):
    project_id: int
    source_type: str | None
    status: str
    target_url: str | None
    last_ingested_at: datetime | None
    error_message: str | None


class GitIngestRequest(BaseModel):
    repository_url: str


class WebsiteIngestRequest(BaseModel):
    target_url: str