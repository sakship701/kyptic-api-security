from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ControlMappedFinding(BaseModel):
    finding_id: int
    title: str
    severity: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    verification_status: str
    confidence_score: int
    file_path: str


class ComplianceControl(BaseModel):
    control_id: str
    control_name: str
    framework: str
    description: str
    status: str  # 'AFFECTED', 'NOT_AFFECTED', 'INSUFFICIENT_EVIDENCE', 'NO_DIRECT_MAPPING'
    affected_findings_count: int
    mapped_findings: List[ControlMappedFinding]
    evidence_summary: str
    remediation_reference: str


class ComplianceFrameworkSummary(BaseModel):
    framework: str
    framework_name: str
    total_controls: int
    affected_controls: int
    unaffected_controls: int
    insufficient_evidence_controls: int
    total_mapped_findings: int
    coverage_percentage: float
    disclaimer: str


class ComplianceResponse(BaseModel):
    project_id: int
    project_name: str
    framework: str
    summary: ComplianceFrameworkSummary
    controls: List[ComplianceControl]
