from __future__ import annotations

from typing import Any

from typing_extensions import TypedDict


class AgentState(TypedDict, total=False):
    task_id: str
    task_name: str
    scope: list[str]
    authorization: str
    lab_description: str
    objective: str
    ports: str
    current_stage: str
    status: str
    hosts: list[dict[str, Any]]
    services: list[dict[str, Any]]
    hypotheses: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    pocs: list[dict[str, Any]]
    actions: list[dict[str, Any]]
    reflections: list[dict[str, Any]]
    pending_approval: dict[str, Any] | None
    approved_action: dict[str, Any] | None
    last_decision: dict[str, Any] | None
    last_result: dict[str, Any] | None
    last_reflection: dict[str, Any] | None
    last_summary: str | None
    path_graph: dict[str, list[dict[str, Any]]]
    report_path: str | None
    error_count: int
    stop_reason: str | None
    max_steps: int
    step_count: int
