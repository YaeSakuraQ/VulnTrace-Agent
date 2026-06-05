#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

import requests
import websockets


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import get_settings
from app.main import create_container
from app.schemas.task import TaskUpdate


BASE_URL = "http://127.0.0.1:8000/api"
WS_BASE_URL = "ws://127.0.0.1:8000/ws/tasks"


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str


class ApiCheckError(RuntimeError):
    pass


session = requests.Session()
results: list[CheckResult] = []
container = None


def record(name: str, ok: bool, detail: str) -> None:
    results.append(CheckResult(name=name, ok=ok, detail=detail))
    status = "OK" if ok else "FAIL"
    print(f"[{status}] {name}: {detail}")


def request_json(method: str, path: str, *, expected: int = 200, **kwargs):
    response = session.request(method, f"{BASE_URL}{path}", timeout=30, **kwargs)
    if response.status_code != expected:
        raise ApiCheckError(
            f"{method} {path} expected {expected}, got {response.status_code}: {response.text[:400]}"
        )
    if response.content:
        return response.json()
    return None


def create_task(name: str) -> dict:
    payload = {
        "name": name,
        "scope": ["127.0.0.1"],
        "authorization": "Authorized local integration test target.",
        "lab_description": "Backend API server on localhost:8000 for integration checks.",
        "objective": "Exercise frontend-facing API workflows end to end.",
        "ports": "8000",
        "max_steps": 8,
        "auto_run": False,
    }
    return request_json("POST", "/tasks", json=payload)


def ensure_container():
    global container
    if container is None:
        os.environ.setdefault("APP_DEBUG", "false")
        get_settings.cache_clear()
        container = create_container()
    return container


def seed_pending_approval(task_id: str, *, timeout: int = 30) -> str:
    local_container = ensure_container()
    task = local_container.task_service.get_task(task_id)
    state = dict(task.state)
    state["current_stage"] = "vuln_verify"
    state["status"] = "waiting_approval"
    state["hosts"] = [{"address": "127.0.0.1", "status": "up"}]
    state["services"] = [
        {
            "target": "127.0.0.1",
            "port": 8000,
            "protocol": "tcp",
            "service": "http",
            "product": "Uvicorn",
            "version": "",
            "source": "seed",
        }
    ]
    state["evidence"] = [
        {
            "kind": "web_probe",
            "target": "127.0.0.1",
            "port": 8000,
            "summary": "/ -> 404 backend root",
            "data": {
                "url": "http://127.0.0.1:8000/",
                "path": "/",
                "status_code": 404,
                "title": "",
                "headers": {"server": "uvicorn"},
            },
        }
    ]
    local_container.task_service.update_task(
        task_id,
        TaskUpdate(status="waiting_approval", current_stage="vuln_verify", state=state),
    )
    approval = local_container.approval_service.create_approval(
        task_id,
        tool_name="vuln_verify",
        target="127.0.0.1:8000",
        risk_level="high",
        reason="Seeded integration-test approval for frontend API coverage.",
        params={
            "target": "127.0.0.1",
            "port": 8000,
            "scheme": "http",
            "profile": "generic_web",
            "preferred_poc": "none",
            "service_name": "http",
            "service_product": "Uvicorn",
            "service_version": "",
            "lab_description": "Seeded local backend approval target.",
            "page_title": "",
            "headers": {"server": "uvicorn"},
            "interesting_paths": ["/"],
            "timeout": timeout,
        },
    )
    return approval.id


def wait_for_status(task_id: str, statuses: set[str], *, timeout: float = 120.0) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = request_json("GET", f"/tasks/{task_id}")
        if last["status"] in statuses:
            return last
        time.sleep(1.0)
    raise ApiCheckError(
        f"Task {task_id} did not reach {sorted(statuses)} in time; last status={last['status'] if last else 'unknown'}"
    )


async def check_websocket(task_id: str) -> None:
    async with websockets.connect(f"{WS_BASE_URL}/{task_id}") as websocket:
        snapshot = json.loads(await asyncio.wait_for(websocket.recv(), timeout=5))
        heartbeat = json.loads(await asyncio.wait_for(websocket.recv(), timeout=5))
        if snapshot.get("type") != "task_snapshot":
            raise ApiCheckError(f"Unexpected websocket snapshot payload: {snapshot}")
        if heartbeat.get("type") not in {"heartbeat", "event"}:
            raise ApiCheckError(f"Unexpected websocket follow-up payload: {heartbeat}")


def test_read_endpoints() -> None:
    tasks = request_json("GET", "/tasks")
    templates = request_json("GET", "/tasks/templates")
    assert isinstance(tasks, list) and len(tasks) >= 0
    assert {item["id"] for item in templates} == {"dvwa", "metasploitable", "vulhub"}
    record("list_tasks", True, f"loaded {len(tasks)} task(s)")
    record("list_templates", True, f"loaded {[item['id'] for item in templates]}")


def test_control_endpoints() -> None:
    task = create_task(f"api-control-{uuid4().hex[:8]}")
    task_id = task["id"]

    fetched = request_json("GET", f"/tasks/{task_id}")
    events = request_json("GET", f"/tasks/{task_id}/events")
    artifacts = request_json("GET", f"/tasks/{task_id}/artifacts")
    report_resp = session.get(f"{BASE_URL}/reports/{task_id}", timeout=15)

    if fetched["id"] != task_id:
        raise ApiCheckError("Fetched task id mismatch.")
    if report_resp.status_code != 404:
        raise ApiCheckError(f"Expected 404 report before execution, got {report_resp.status_code}")

    record("create_task", True, task_id)
    record("fetch_task", True, fetched["status"])
    record("fetch_events", True, f"{len(events)} event(s)")
    record("fetch_artifacts", True, f"{len(artifacts)} artifact(s)")
    record("fetch_report_before_ready", True, "returns 404 as expected")

    paused = request_json("POST", f"/tasks/{task_id}/pause")
    if paused["status"] != "paused":
        raise ApiCheckError("Pause endpoint did not set paused status.")
    record("pause_task", True, paused["status"])

    stopped = request_json("POST", f"/tasks/{task_id}/stop")
    if stopped["status"] != "stopped":
        raise ApiCheckError("Stop endpoint did not set stopped status.")
    record("stop_task", True, stopped["status"])


def launch_seeded_approval_task(prefix: str) -> tuple[str, dict]:
    task = create_task(f"{prefix}-{uuid4().hex[:8]}")
    task_id = task["id"]
    approval_id = seed_pending_approval(task_id)
    task = wait_for_status(task_id, {"waiting_approval"}, timeout=10)
    approvals = request_json("GET", f"/approvals?task_id={task_id}")
    pending = [item for item in approvals if item["status"] == "pending" and item["id"] == approval_id]
    if not pending:
        raise ApiCheckError(f"Task {task_id} reached waiting_approval but no pending approval found.")
    return task_id, pending[0]


def test_websocket_and_reject_flow() -> None:
    task_id, approval = launch_seeded_approval_task("api-reject")
    asyncio.run(check_websocket(task_id))
    record("websocket_task_stream", True, f"connected for {task_id}")

    rejected = request_json(
        "POST",
        f"/approvals/{approval['id']}/reject",
        json={"note": "Integration test reject."},
    )
    if rejected["status"] != "rejected":
        raise ApiCheckError("Reject endpoint did not mark approval rejected.")

    task = wait_for_status(task_id, {"paused"}, timeout=10)
    record("list_approvals", True, f"pending approval {approval['id']} created")
    record("reject_action", True, f"task status -> {task['status']}")


def test_edit_approve_flow() -> None:
    task_id, approval = launch_seeded_approval_task("api-edit-approve")
    edited_params = dict(approval["params"])
    edited_params["timeout"] = 35
    approved = request_json(
        "POST",
        f"/approvals/{approval['id']}/edit",
        json={"note": "Integration test edited approval.", "edited_params": edited_params},
    )
    if approved["status"] != "approved" or approved["params"]["timeout"] != 35:
        raise ApiCheckError("Edit approval endpoint did not persist edited params.")

    task = wait_for_status(task_id, {"completed", "failed", "stopped"}, timeout=120)
    if task["status"] != "completed":
        raise ApiCheckError(f"Edited approval flow ended in {task['status']}, expected completed.")

    report = request_json("GET", f"/reports/{task_id}")
    artifacts = request_json("GET", f"/tasks/{task_id}/artifacts")
    if "markdown" not in report or not report["markdown"]:
        raise ApiCheckError("Completed task report is empty.")
    if not artifacts:
        raise ApiCheckError("Completed task should have artifacts.")

    record("edit_and_approve_action", True, f"task {task_id} completed with edited params")
    record("fetch_report_after_complete", True, report["path"] or "report generated")
    record("fetch_artifacts_after_complete", True, f"{len(artifacts)} artifact(s)")


def test_approve_flow() -> None:
    task_id, approval = launch_seeded_approval_task("api-approve")
    approved = request_json(
        "POST",
        f"/approvals/{approval['id']}/approve",
        json={"note": "Integration test approve."},
    )
    if approved["status"] != "approved":
        raise ApiCheckError("Approve endpoint did not mark approval approved.")
    task = wait_for_status(task_id, {"completed", "failed", "stopped"}, timeout=120)
    if task["status"] != "completed":
        raise ApiCheckError(f"Approve flow ended in {task['status']}, expected completed.")
    record("approve_action", True, f"task {task_id} completed")


def main() -> int:
    try:
        test_read_endpoints()
        test_control_endpoints()
        test_websocket_and_reject_flow()
        test_edit_approve_flow()
        test_approve_flow()
    except Exception as exc:
        record("integration_summary", False, str(exc))
        return 1

    record("integration_summary", True, f"{len(results)} checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
