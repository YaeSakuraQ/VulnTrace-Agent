from __future__ import annotations

import asyncio
from types import SimpleNamespace

from app.core.config import get_settings
from app.services.demo_template_service import DemoTemplateService
from app.api.tasks import create_task, list_task_templates
from app.schemas.task import TaskCreate


def test_demo_template_service_exposes_expected_templates() -> None:
    service = DemoTemplateService()

    templates = service.list_templates()

    assert [template.id for template in templates] == ["dvwa", "vulhub"]
    assert templates[0].defaults.scope == ["127.0.0.1"]
    assert "PoC" in templates[0].defaults.objective
    assert templates[0].recommended_port_presets[0] == "80"
    assert len(templates[1].demo_flow) >= 3
    assert templates[1].defaults.max_steps >= templates[0].defaults.max_steps


def test_demo_template_endpoint_returns_templates(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'templates.db'}")
    monkeypatch.setenv("ARTIFACT_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("APP_DEBUG", "false")
    get_settings.cache_clear()
    from app.main import create_app

    app = create_app()
    request = SimpleNamespace(app=app)

    payload = asyncio.run(list_task_templates(request))

    assert [item.id for item in payload] == ["dvwa", "vulhub"]
    assert payload[1].defaults.scope == ["127.0.0.1"]
    assert "PoC" in payload[0].defaults.objective
    assert payload[0].recommended_port_presets[1] == "8080"
    get_settings.cache_clear()


def test_create_task_with_auto_run_schedules_runtime(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'autorun.db'}")
    monkeypatch.setenv("ARTIFACT_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("APP_DEBUG", "false")
    get_settings.cache_clear()
    from app.main import create_app

    app = create_app()
    scheduled: dict[str, str] = {}

    async def fake_schedule(task_id: str) -> bool:
        scheduled["task_id"] = task_id
        return True

    app.state.container.task_runtime.schedule = fake_schedule
    request = SimpleNamespace(app=app)

    payload = asyncio.run(
        create_task(
            request,
            TaskCreate(
                name="DVWA Autorun",
                scope=["127.0.0.1"],
                authorization="authorized local lab",
                lab_description="dvwa local target",
                objective="autorun smoke flow",
                ports="80,8080",
                max_steps=6,
                auto_run=True,
            ),
        )
    )

    assert payload.id == scheduled["task_id"]
    get_settings.cache_clear()
