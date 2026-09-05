from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    repository_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    technology: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )

    # Ingestion columns
    source_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    source_status: Mapped[str] = mapped_column(String(50), nullable=False, default="NOT_INGESTED")
    local_source_reference: Mapped[str | None] = mapped_column(String(500), nullable=True)
    target_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    last_ingested_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ingestion_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # DAST Target Config columns
    api_target_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    api_dast_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    api_auth_type: Mapped[str | None] = mapped_column(String(50), nullable=True, default="NONE")
    api_auth_header_name: Mapped[str | None] = mapped_column(String(100), nullable=True, default="Authorization")
    api_auth_token_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)