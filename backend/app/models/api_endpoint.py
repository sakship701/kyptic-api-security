from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ApiEndpoint(Base):
    __tablename__ = "api_endpoints"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    path: Mapped[str] = mapped_column(String(500), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    summary: Mapped[str | None] = mapped_column(String(500), nullable=True)
    operation_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    
    # Security & Auth Details
    auth_status: Mapped[str] = mapped_column(String(50), nullable=False, default="UNAUTHENTICATED")
    auth_type: Mapped[str | None] = mapped_column(String(50), nullable=True, default="NONE")
    
    # Rate Limit & Validation Details
    rate_limit_status: Mapped[str] = mapped_column(String(50), nullable=False, default="MISSING")
    request_validation_status: Mapped[str] = mapped_column(String(50), nullable=False, default="UNCONSTRAINED")
    
    # Data Exposure Metadata
    sensitive_data_fields: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # Risk Assessment
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False, default="INFO")
    
    # Milestone 2 & 3 Security Attributes
    bola_status: Mapped[str] = mapped_column(String(50), nullable=False, default="NONE")
    mass_assignment_status: Mapped[str] = mapped_column(String(50), nullable=False, default="NONE")
    dast_status: Mapped[str] = mapped_column(String(50), nullable=False, default="UNTESTED")

    # Discovery & Lifecycle Metadata
    discovered_via: Mapped[str] = mapped_column(String(50), nullable=False, default="OPENAPI_SPEC")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
