from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.risk_policy import RiskTolerance


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SQLITE_URL_PREFIX = "sqlite:///"


def _resolve_project_path(value: str) -> Path:
    candidate = Path(value).expanduser()
    if candidate.is_absolute():
        return candidate
    return PROJECT_ROOT / candidate


class Settings(BaseSettings):
    app_name: str = "VulnTrace Agent"
    api_prefix: str = "/api"
    debug: bool = Field(default=False, validation_alias=AliasChoices("APP_DEBUG"))

    # ── LLM provider configuration ──────────────────────────────────
    llm_provider: str = "deepseek"
    llm_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("LLM_API_KEY", "DEEPSEEK_API_KEY"),
    )
    llm_temperature: float = 0.2
    llm_timeout: int = 120
    llm_max_tokens: int = 8192

    # ── DeepSeek-specific (legacy, kept as fallback) ────────────────
    deepseek_api_key: str | None = None
    deepseek_model: str = "deepseek-v4-flash"
    deepseek_base_url: str = "https://api.deepseek.com/v1"

    database_url: str = Field(
        default=f"sqlite:///{PROJECT_ROOT / 'backend' / 'vulntrace_agent.db'}"
    )
    artifact_dir: str = str(PROJECT_ROOT / "artifacts")

    # ── Security / risk controls ────────────────────────────────────
    allow_public_targets: bool = False
    risk_tolerance: RiskTolerance = RiskTolerance.MODERATE

    default_timeout: int = 60
    max_output_chars: int = 12000
    max_task_steps: int = 8
    websocket_poll_interval: float = 1.0
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ]
    )
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    @property
    def database_path(self) -> str:
        """Return database URL, supporting sqlite and postgresql."""
        url = self.database_url
        if url.startswith("sqlite:///"):
            # Resolve relative paths to absolute
            rel = url.removeprefix("sqlite:///")
            if not rel.startswith("/"):
                return f"sqlite:///{(PROJECT_ROOT / rel).as_posix()}"
            return url
        return url  # postgresql:// or other

    @property
    def artifact_path(self) -> Path:
        return _resolve_project_path(self.artifact_dir)

    @property
    def resolved_llm_api_key(self) -> str | None:
        """Return the effective LLM API key, falling back from llm_api_key to deepseek_api_key."""
        return self.llm_api_key or self.deepseek_api_key


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
