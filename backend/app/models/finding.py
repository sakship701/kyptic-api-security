from datetime import datetime
from enum import Enum as PythonEnum

from sqlalchemy import DateTime, Enum as SqlAlchemyEnum, ForeignKey, Integer, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class FindingSeverity(str, PythonEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, PythonEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class FindingSource(str, PythonEnum):
    SAST = "sast"
    DAST = "dast"
    GREYBOX = "greybox"
    CORRELATION = "correlation"
    MANUAL = "manual"
    SECRETS = "secrets"
    SCA = "sca"
    API_SECURITY = "api_security"


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(
        SqlAlchemyEnum(FindingSeverity, values_callable=lambda values: [severity.value for severity in values]),
        nullable=False,
    )
    cvss: Mapped[float | None] = mapped_column(Numeric(3, 1), nullable=True)
    category: Mapped[str] = mapped_column(String(255), nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[FindingStatus] = mapped_column(
        SqlAlchemyEnum(FindingStatus, values_callable=lambda values: [finding_status.value for finding_status in values]),
        nullable=False,
        default=FindingStatus.OPEN,
    )
    source: Mapped[FindingSource] = mapped_column(
        SqlAlchemyEnum(FindingSource, values_callable=lambda values: [finding_source.value for finding_source in values]),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    # SAST Specific Evidence & Metadata
    rule_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owasp: Mapped[str | None] = mapped_column(String(255), nullable=True)
    end_line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    code_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    scanner_name: Mapped[str | None] = mapped_column(String(50), nullable=True, default="semgrep")
    scanner_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(500), nullable=True, index=True)

    # Triage & Lifecycle Metadata
    resolution_comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)