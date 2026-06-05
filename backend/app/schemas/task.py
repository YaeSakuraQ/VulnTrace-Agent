from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


TaskStatus = Literal[
    "draft",
    "running",
    "paused",
    "waiting_approval",
    "completed",
    "failed",
    "stopped",
]


class TaskCreate(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    scope: list[str] = Field(min_length=1)
    authorization: str = Field(min_length=3)
    lab_description: str = ""
    objective: str = "Identify reachable services and validate low-risk findings."
    ports: str = "1-1024"
    max_steps: int = Field(default=8, ge=1, le=20)
    auto_run: bool = False


class TaskTemplateDefaults(BaseModel):
    name: str
    scope: list[str] = Field(min_length=1)
    authorization: str
    lab_description: str
    objective: str
    ports: str
    max_steps: int = Field(ge=1, le=20)


class TaskTemplate(BaseModel):
    id: str
    title: str
    lab_type: str
    summary: str
    defaults: TaskTemplateDefaults
    recommended_scope_examples: list[str] = Field(default_factory=list)
    recommended_port_presets: list[str] = Field(default_factory=list)
    setup_notes: list[str] = Field(default_factory=list)
    checklist: list[str] = Field(default_factory=list)
    demo_flow: list[str] = Field(default_factory=list)
    risk_focus: str


class TaskUpdate(BaseModel):
    status: TaskStatus | None = None
    current_stage: str | None = None
    state: dict[str, Any] | None = None
    report_path: str | None = None
    stop_reason: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class TaskSummary(BaseModel):
    id: str
    name: str
    scope: list[str]
    authorization: str
    lab_description: str
    objective: str
    ports: str
    current_stage: str
    status: TaskStatus
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    report_path: str | None = None
    stop_reason: str | None = None


class TaskDetail(TaskSummary):
    state: dict[str, Any]


class TaskEvent(BaseModel):
    id: int
    task_id: str
    event_type: str
    stage: str | None = None
    message: str
    payload: dict[str, Any]
    created_at: datetime


class ArtifactRecord(BaseModel):
    id: str
    task_id: str
    artifact_type: str
    title: str
    path: str
    summary: str
    created_at: datetime
