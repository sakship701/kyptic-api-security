from typing import List, Optional
from pydantic import BaseModel, ConfigDict


class GreyBoxContextResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: Optional[int] = None
    project_id: int
    endpoint_id: Optional[int] = None
    target_url: Optional[str] = None
    http_method: str
    path: str
    vulnerability_family: str
    recommended_probe_types: List[str]
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    priority_score: int
    priority_level: str
    mapping_confidence: str
    context_reason: str
