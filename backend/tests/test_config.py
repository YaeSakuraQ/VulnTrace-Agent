from __future__ import annotations

from app.core.config import PROJECT_ROOT, Settings


def test_settings_resolve_relative_paths_from_project_root(monkeypatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "sqlite:///backend/vulntrace_agent.db")
    monkeypatch.setenv("ARTIFACT_DIR", "artifacts")

    settings = Settings()

    assert settings.database_path == PROJECT_ROOT / "backend" / "vulntrace_agent.db"
    assert settings.artifact_path == PROJECT_ROOT / "artifacts"


def test_settings_preserve_absolute_paths(monkeypatch, tmp_path) -> None:
    db_path = tmp_path / "agent.db"
    artifact_dir = tmp_path / "artifacts"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("ARTIFACT_DIR", str(artifact_dir))

    settings = Settings()

    assert settings.database_path == db_path
    assert settings.artifact_path == artifact_dir
