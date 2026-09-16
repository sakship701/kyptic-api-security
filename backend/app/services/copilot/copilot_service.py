import logging
import re
from typing import AsyncGenerator, Optional
from sqlalchemy.orm import Session

from app.config import settings
from app.models.finding import Finding
from app.schemas.copilot import CopilotChatRequest, CopilotChatResponse, CopilotCodeBlock, CopilotStatusResponse
from app.services.copilot.context_builder import ContextBuilder
from app.services.copilot.fallback_engine import FallbackEngine
from app.services.copilot.ollama_provider import OllamaProvider
from app.services.copilot.openai_provider import OpenAICompatibleProvider
from app.services.copilot.provider_base import BaseLLMProvider

logger = logging.getLogger(__name__)


class CopilotService:
    def __init__(self, provider_override: Optional[BaseLLMProvider] = None) -> None:
        self.context_builder = ContextBuilder(max_context_chars=settings.COPILOT_MAX_CONTEXT_CHARS)
        if provider_override:
            self.provider = provider_override
        elif settings.COPILOT_PROVIDER == "openai":
            self.provider = OpenAICompatibleProvider(
                base_url=settings.COPILOT_OPENAI_URL,
                api_key=settings.COPILOT_OPENAI_API_KEY,
                model=settings.COPILOT_OPENAI_MODEL,
                timeout_seconds=settings.COPILOT_TIMEOUT_SECONDS,
            )
        else:
            self.provider = OllamaProvider(
                base_url=settings.COPILOT_OLLAMA_URL,
                model=settings.COPILOT_OLLAMA_MODEL,
                timeout_seconds=settings.COPILOT_TIMEOUT_SECONDS,
            )

    async def get_status(self) -> CopilotStatusResponse:
        import time
        start = time.time()
        is_available = await self.provider.health_check()
        latency = (time.time() - start) * 1000.0 if is_available else None

        return CopilotStatusResponse(
            configured_provider=self.provider.provider_name,
            configured_model=self.provider.model_name,
            provider_available=is_available,
            fallback_available=True,
            latency_ms=round(latency, 2) if latency is not None else None,
        )

    def _extract_code_block(self, response_text: str, default_file: str = "patch") -> tuple[str, Optional[CopilotCodeBlock]]:
        """Extract markdown code block if present in response text."""
        pattern = re.compile(r"```(\w+)?\n([\s\S]+?)```")
        match = pattern.search(response_text)
        if match:
            lang = match.group(1) or "text"
            code = match.group(2).strip()
            code_block = CopilotCodeBlock(file=default_file, code=code, lang=lang)
            return response_text, code_block
        return response_text, None

    async def chat(self, request: CopilotChatRequest, db: Session) -> CopilotChatResponse:
        finding: Optional[Finding] = None
        if request.finding_id is not None:
            finding = db.get(Finding, request.finding_id)

        system_prompt = self.context_builder.build_system_prompt()
        prompt = self.context_builder.build_finding_context(finding, request.message)

        try:
            logger.info("Sending request to Copilot LLM provider %s (%s)...", self.provider.provider_name, self.provider.model_name)
            raw_response = await self.provider.generate_response(prompt, system_prompt)
            if not raw_response:
                raise RuntimeError("Empty response received from LLM provider")

            clean_text, code_block = self._extract_code_block(
                raw_response,
                default_file=finding.file_path if finding else "remediation_patch"
            )

            return CopilotChatResponse(
                message=clean_text,
                code_block=code_block,
                is_fallback=False,
                provider=self.provider.provider_name,
                model=self.provider.model_name,
                finding_id=finding.id if finding else None,
            )
        except Exception as e:
            logger.warning("Copilot provider error/timeout (%s). Activating deterministic fallback engine: %s", type(e).__name__, e)
            fallback_msg, fallback_code = FallbackEngine.generate_advisory(finding, request.message)
            return CopilotChatResponse(
                message=fallback_msg,
                code_block=fallback_code,
                is_fallback=True,
                provider="fallback",
                model="deterministic",
                finding_id=finding.id if finding else None,
            )

    async def chat_stream(self, request: CopilotChatRequest, db: Session) -> AsyncGenerator[str, None]:
        finding: Optional[Finding] = None
        if request.finding_id is not None:
            finding = db.get(Finding, request.finding_id)

        system_prompt = self.context_builder.build_system_prompt()
        prompt = self.context_builder.build_finding_context(finding, request.message)

        try:
            async for token in self.provider.stream_response(prompt, system_prompt):
                yield token
        except Exception as e:
            logger.warning("Copilot streaming error/timeout (%s). Yielding fallback advisory: %s", type(e).__name__, e)
            fallback_msg, _ = FallbackEngine.generate_advisory(finding, request.message)
            yield fallback_msg
