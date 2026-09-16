import json
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.copilot import CopilotChatRequest, CopilotChatResponse, CopilotStatusResponse
from app.services.copilot.copilot_service import CopilotService

router = APIRouter(tags=["copilot"])


@router.post("/api/copilot/chat", response_model=CopilotChatResponse)
@router.post("/api/v1/copilot/chat", response_model=CopilotChatResponse)
async def copilot_chat(
    request: CopilotChatRequest,
    db: Session = Depends(get_db)
) -> CopilotChatResponse | StreamingResponse:
    service = CopilotService()

    if request.stream:
        async def event_generator():
            try:
                async for token in service.chat_stream(request, db):
                    data = json.dumps({"delta": token})
                    yield f"event: token\ndata: {data}\n\n"
                done_data = json.dumps({"status": "completed"})
                yield f"event: done\ndata: {done_data}\n\n"
            except Exception as err:
                err_data = json.dumps({"error": str(err)})
                yield f"event: error\ndata: {err_data}\n\n"

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    return await service.chat(request, db)


@router.get("/api/copilot/status", response_model=CopilotStatusResponse)
@router.get("/api/v1/copilot/status", response_model=CopilotStatusResponse)
async def copilot_status() -> CopilotStatusResponse:
    service = CopilotService()
    return await service.get_status()
