from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class CopilotChatRequest(BaseModel):
    finding_id: Optional[int] = None
    project_id: Optional[int] = None
    message: str = Field(..., min_length=1, max_length=4000)
    stream: bool = False


class CopilotCodeBlock(BaseModel):
    file: str
    code: str
    lang: str = "text"


class CopilotChatResponse(BaseModel):
    message: str
    code_block: Optional[CopilotCodeBlock] = None
    is_fallback: bool = False
    provider: str
    model: str
    finding_id: Optional[int] = None


class CopilotStatusResponse(BaseModel):
    configured_provider: str
    configured_model: str
    provider_available: bool
    fallback_available: bool = True
    latency_ms: Optional[float] = None
    details: Optional[Dict[str, Any]] = None
