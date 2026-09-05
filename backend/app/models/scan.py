from datetime import datetime
from enum import Enum as PythonEnum

from sqlalchemy import DateTime, Enum as SqlAlchemyEnum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ScanStatus(str, PythonEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    STOPPED = "stopped"
    FAILED = "failed"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    status: Mapped[ScanStatus] = mapped_column(
        SqlAlchemyEnum(ScanStatus, values_callable=lambda values: [status.value for status in values]),
        nullable=False,
        default=ScanStatus.QUEUED,
    )
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    current_phase: Mapped[str] = mapped_column(String(100), nullable=False, default="Queued")
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Scanner details
    scanner: Mapped[str | None] = mapped_column(String(50), nullable=True)
    scanner_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    sca_status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    dast_status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    duration: Mapped[float | None] = mapped_column(nullable=True)
    result_count: Mapped[int | None] = mapped_column(Integer, nullable=True)