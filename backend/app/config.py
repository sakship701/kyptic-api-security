import os
from pathlib import Path


class CopilotSettings:
    def __init__(self) -> None:
        self.COPILOT_PROVIDER: str = os.getenv("COPILOT_PROVIDER", "ollama").lower()
        self.COPILOT_OLLAMA_URL: str = os.getenv("COPILOT_OLLAMA_URL", "http://localhost:11434").rstrip("/")
        self.COPILOT_OLLAMA_MODEL: str = os.getenv("COPILOT_OLLAMA_MODEL", "qwen2.5-coder:1.5b")
        
        self.COPILOT_OPENAI_URL: str = os.getenv("COPILOT_OPENAI_URL", "https://api.openai.com/v1").rstrip("/")
        self.COPILOT_OPENAI_API_KEY: str = os.getenv("COPILOT_OPENAI_API_KEY", "")
        self.COPILOT_OPENAI_MODEL: str = os.getenv("COPILOT_OPENAI_MODEL", "gpt-3.5-turbo")
        
        try:
            self.COPILOT_TIMEOUT_SECONDS: float = float(os.getenv("COPILOT_TIMEOUT_SECONDS", "8.0"))
        except ValueError:
            self.COPILOT_TIMEOUT_SECONDS = 8.0
            
        try:
            self.COPILOT_MAX_CONTEXT_CHARS: int = int(os.getenv("COPILOT_MAX_CONTEXT_CHARS", "4000"))
        except ValueError:
            self.COPILOT_MAX_CONTEXT_CHARS = 4000
            
        try:
            self.COPILOT_MAX_RESPONSE_TOKENS: int = int(os.getenv("COPILOT_MAX_RESPONSE_TOKENS", "512"))
        except ValueError:
            self.COPILOT_MAX_RESPONSE_TOKENS = 512
            
        self.COPILOT_ENABLE_STREAMING: bool = os.getenv("COPILOT_ENABLE_STREAMING", "true").lower() in ("true", "1", "yes")


settings = CopilotSettings()
