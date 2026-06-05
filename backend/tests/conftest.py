from __future__ import annotations

import tempfile
from pathlib import Path
import sys

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest


@pytest.fixture
def temp_db():
    """Create a temporary SQLite database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield f"sqlite:///{db_path}"
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def settings_override(monkeypatch):
    """Override settings for testing."""
    monkeypatch.setenv("APP_DEBUG", "true")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("ARTIFACT_DIR", "/tmp/test_artifacts")


@pytest.fixture
def dummy_llm_client():
    """A dummy LLM client that always returns a valid plan decision."""
    from app.agents.planner import PlanDecision

    class DummyClient:
        enabled = False

        def invoke_structured(self, schema, system_prompt, user_prompt):
            return PlanDecision(
                tool_name="asset_discovery",
                stage="asset_discovery",
                params={"targets": ["127.0.0.1"], "port_spec": "80", "timeout": 30},
                reason="Test plan",
                risk_level="low",
                requires_approval=False,
                confidence="medium",
                source="heuristic",
            )

    return DummyClient()
