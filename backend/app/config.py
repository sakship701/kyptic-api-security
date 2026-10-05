import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]


class Settings:
    def __init__(self) -> None:
        self.ENVIRONMENT: str = os.getenv("APP_ENV", os.getenv("ENVIRONMENT", "development")).lower()
        self.SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")

        # Session & Authentication Settings
        self.BOOTSTRAP_OWNER_EMAIL: str = os.getenv("KYPTIC_BOOTSTRAP_OWNER_EMAIL", "demo@kyptic.security").lower().strip()
        self.COOKIE_SECURE: bool = self.ENVIRONMENT in ("production", "prod") or os.getenv("COOKIE_SECURE", "false").lower() in ("true", "1", "yes")
        self.COOKIE_SAMESITE: str = os.getenv("COOKIE_SAMESITE", "lax").lower()
        self.ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))  # 24 hours

        # Primary Database URL: Defaults to SQLite in backend/kyptic.db for local dev fallback
        default_db = f"sqlite:///{BASE_DIR / 'kyptic.db'}"
        self.DATABASE_URL: str = os.getenv("DATABASE_URL", default_db)
        self.TEST_DATABASE_URL: str = os.getenv("TEST_DATABASE_URL", "")

        # Storage Abstraction Settings
        self.STORAGE_PROVIDER: str = os.getenv("STORAGE_PROVIDER", "local").lower()
        self.STORAGE_LOCAL_DIR: Path = BASE_DIR / "data"
        self.S3_BUCKET_NAME: str = os.getenv("S3_BUCKET_NAME", "kyptic-artifacts")
        self.S3_REGION: str = os.getenv("S3_REGION", "us-east-1")
        self.S3_ENDPOINT_URL: str | None = os.getenv("S3_ENDPOINT_URL")

        # Network & SSRF Exceptions
        self.KYPTIC_LOCAL_DEMO_URL: str = os.getenv("KYPTIC_LOCAL_DEMO_URL", "http://localhost:8001")
        self.ALLOW_LOCALHOST: bool = os.getenv("ALLOW_LOCALHOST", "true").lower() in ("true", "1", "yes")

        # Copilot Settings
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


settings = Settings()
