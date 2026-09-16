from abc import ABC, abstractmethod
from typing import AsyncGenerator


class BaseLLMProvider(ABC):
    @abstractmethod
    async def generate_response(self, prompt: str, system_prompt: str) -> str:
        """Generate a complete non-streaming response."""
        pass

    @abstractmethod
    async def stream_response(self, prompt: str, system_prompt: str) -> AsyncGenerator[str, None]:
        """Stream tokens as an async generator."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check provider reachability and model status."""
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        pass
