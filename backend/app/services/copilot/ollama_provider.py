import json
from typing import AsyncGenerator
import httpx

from app.services.copilot.provider_base import BaseLLMProvider


class OllamaProvider(BaseLLMProvider):
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "qwen2.5-coder:1.5b", timeout_seconds: float = 8.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds

    @property
    def provider_name(self) -> str:
        return "ollama"

    @property
    def model_name(self) -> str:
        return self.model

    async def generate_response(self, prompt: str, system_prompt: str) -> str:
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system_prompt,
            "stream": False,
        }
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get("response", "").strip()

    async def stream_response(self, prompt: str, system_prompt: str) -> AsyncGenerator[str, None]:
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system_prompt,
            "stream": True,
        }
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            async with client.stream("POST", url, json=payload) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        token = data.get("response", "")
                        if token:
                            yield token
                    except Exception:
                        continue

    async def health_check(self) -> bool:
        try:
            url = f"{self.base_url}/api/tags"
            async with httpx.AsyncClient(timeout=2.0) as client:
                res = await client.get(url)
                return res.status_code == 200
        except Exception:
            return False
