from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    deepseek_api_key: str | None = None
    deepseek_model: str = "deepseek-v4-flash"
    deepseek_base_url: str = "https://api.deepseek.com/v1"
    database_url: str = Field(
        default=f"sqlite:///{PROJECT_ROOT / 'backend' / 'vulntrace_agent.db'}"
    )
    artifact_dir: str = str(PROJECT_ROOT / "artifacts")
    allow_public_targets: bool = False
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
    def database_path(self) -> Path:
        if not self.database_url.startswith(SQLITE_URL_PREFIX):
            raise ValueError("Only sqlite:/// DATABASE_URL is supported in this project.")
        return _resolve_project_path(self.database_url.replace(SQLITE_URL_PREFIX, "", 1))

    @property
    def artifact_path(self) -> Path:
        return _resolve_project_path(self.artifact_dir)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
