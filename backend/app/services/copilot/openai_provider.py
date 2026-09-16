import json
from typing import AsyncGenerator
import httpx

from app.services.copilot.provider_base import BaseLLMProvider


class OpenAICompatibleProvider(BaseLLMProvider):
    def __init__(
        self,
        base_url: str = "https://api.openai.com/v1",
        api_key: str = "",
        model: str = "gpt-3.5-turbo",
        timeout_seconds: float = 8.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds

    @property
    def provider_name(self) -> str:
        return "openai"

    @property
    def model_name(self) -> str:
        return self.model

    def _get_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def generate_response(self, prompt: str, system_prompt: str) -> str:
        url = f"{self.base_url}/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
        }
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(url, json=payload, headers=self._get_headers())
            response.raise_for_status()
            data = response.json()
            choices = data.get("choices", [])
            if choices and len(choices) > 0:
                message = choices[0].get("message", {})
                return message.get("content", "").strip()
            return ""

    async def stream_response(self, prompt: str, system_prompt: str) -> AsyncGenerator[str, None]:
        url = f"{self.base_url}/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "stream": True,
        }
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            async with client.stream("POST", url, json=payload, headers=self._get_headers()) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line:
                        continue
                    if line.startswith("data: "):
                        line_data = line[6:].strip()
                        if line_data == "[DONE]":
                            break
                        try:
                            parsed = json.loads(line_data)
                            choices = parsed.get("choices", [])
                            if choices:
                                delta = choices[0].get("delta", {})
                                token = delta.get("content", "")
                                if token:
                                    yield token
                        except Exception:
                            continue

    async def health_check(self) -> bool:
        try:
            url = f"{self.base_url}/models"
            async with httpx.AsyncClient(timeout=2.0) as client:
                res = await client.get(url, headers=self._get_headers())
                return res.status_code == 200
        except Exception:
            return False
