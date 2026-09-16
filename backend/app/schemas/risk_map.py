from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RiskMapNodeDetails(BaseModel):
    vulnName: Optional[str] = None
    owasp: Optional[str] = None
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    description: Optional[str] = None
    sastDesc: Optional[str] = None
    sastCode: Optional[str] = None
    dastDesc: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    source_file: Optional[str] = None
    line_number: Optional[int] = None


class RiskMapNode(BaseModel):
    id: str
    label: str
    type: str  # 'PROJECT', 'API', 'ENDPOINT', 'FINDING', 'VULNERABILITY', 'FILE'
    status: str  # 'safe', 'warning', 'critical', 'info'
    icon: str
    x: float
    y: float
    score: float
    severity: Optional[str] = None
    confidence_score: Optional[int] = None
    confidence_level: Optional[str] = None
    verification_status: Optional[str] = None
    source: Optional[str] = None
    project_id: int
    details: Optional[RiskMapNodeDetails] = None


class RiskMapEdge(BaseModel):
    id: str
    source: str
    target: str
    type: str  # 'PROJECT_API', 'API_ENDPOINT', 'ENDPOINT_FINDING', 'FINDING_VULN', 'FINDING_FILE'
    status: str  # 'safe', 'warning', 'critical'
    label: Optional[str] = None


class RiskMapSummary(BaseModel):
    total_nodes: int
    total_edges: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    overall_risk_score: int
    overall_risk_grade: str


class RiskMapGraphResponse(BaseModel):
    project_id: int
    project_name: str
    nodes: List[RiskMapNode]
    edges: List[RiskMapEdge]
    summary: RiskMapSummary
