from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Query, Request

from app.core.scope_guard import ScopeValidationError
from app.schemas.task import (
    ArtifactRecord,
    TaskCreate,
    TaskDetail,
    TaskEvent,
    TaskSummary,
    TaskTemplate,
    TaskUpdate,
)
from app.services.task_service import TaskNotFoundError


router = APIRouter(prefix="/tasks", tags=["tasks"])


@router.post("", response_model=TaskDetail)
async def create_task(request: Request, payload: TaskCreate) -> TaskDetail:
    container = request.app.state.container
    try:
        normalized_scope = container.scope_guard.validate_scope(payload.scope)
    except ScopeValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    task = container.task_service.create_task(payload, normalized_scope)
    if payload.auto_run:
        await container.task_runtime.schedule(task.id)
        return container.task_service.get_task(task.id)
    return task


@router.get("", response_model=list[TaskSummary])
async def list_tasks(request: Request) -> list[TaskSummary]:
    return request.app.state.container.task_service.list_tasks()


@router.get("/templates", response_model=list[TaskTemplate])
async def list_task_templates(request: Request) -> list[TaskTemplate]:
    return request.app.state.container.demo_template_service.list_templates()


@router.get("/{task_id}", response_model=TaskDetail)
async def get_task(task_id: str, request: Request) -> TaskDetail:
    try:
        return request.app.state.container.task_service.get_task(task_id)
    except TaskNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Task not found.") from exc


@router.post("/{task_id}/run")
async def run_task(task_id: str, request: Request) -> dict[str, str | bool]:
    container = request.app.state.container
    try:
        container.task_service.get_task(task_id)
    except TaskNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Task not found.") from exc

    scheduled = await container.task_runtime.schedule(task_id)
    return {"task_id": task_id, "scheduled": scheduled}


@router.post("/{task_id}/pause", response_model=TaskDetail)
async def pause_task(task_id: str, request: Request) -> TaskDetail:
    container = request.app.state.container
    try:
        task = container.task_service.get_task(task_id)
    except TaskNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Task not found.") from exc

    updated = container.task_service.update_task(
        task_id,
        TaskUpdate(status="paused", state=task.state, stop_reason="Paused by user."),
    )
    container.task_service.add_event(
        task_id,
        event_type="task_paused",
        stage=task.current_stage,
        message="Task paused by user.",
        payload={},
    )
    return updated


@router.post("/{task_id}/stop", response_model=TaskDetail)
async def stop_task(task_id: str, request: Request) -> TaskDetail:
    container = request.app.state.container
    try:
        task = container.task_service.get_task(task_id)
    except TaskNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Task not found.") from exc

    updated = container.task_service.update_task(
        task_id,
        TaskUpdate(
            status="stopped",
            state=task.state,
            stop_reason="Stopped by user.",
            finished_at=datetime.now(UTC),
        ),
    )
    container.task_service.add_event(
        task_id,
        event_type="task_stopped",
        stage=task.current_stage,
        message="Task stopped by user.",
        payload={},
    )
    return updated


@router.get("/{task_id}/events", response_model=list[TaskEvent])
async def get_events(
    task_id: str,
    request: Request,
    after_id: int | None = Query(default=None),
) -> list[TaskEvent]:
    container = request.app.state.container
    try:
        container.task_service.get_task(task_id)
    except TaskNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Task not found.") from exc
    return container.task_service.list_events(task_id, after_id=after_id)


@router.get("/{task_id}/artifacts", response_model=list[ArtifactRecord])
async def get_artifacts(task_id: str, request: Request) -> list[ArtifactRecord]:
    container = request.app.state.container
    try:
        container.task_service.get_task(task_id)
    except TaskNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Task not found.") from exc
    return container.task_service.list_artifacts(task_id)
