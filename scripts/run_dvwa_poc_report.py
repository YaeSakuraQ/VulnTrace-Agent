#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import get_settings
from app.main import create_container
from app.schemas.approval import ApprovalDecision
from app.schemas.task import TaskCreate, TaskUpdate


def utc_now() -> datetime:
    return datetime.now(UTC)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a real DVWA file-inclusion PoC flow and generate a report.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4281)
    parser.add_argument("--scheme", default="http", choices=["http", "https"])
    parser.add_argument(
        "--task-name",
        default="DVWA FI PoC Report Chain",
    )
    parser.add_argument(
        "--lab-description",
        default="Local DVWA lab with controlled file inclusion verification.",
    )
    return parser


def add_action(
    container,
    state: dict,
    task_id: str,
    *,
    stage: str,
    tool_name: str,
    params: dict,
    result,
) -> None:
    state.setdefault("actions", []).append(
        {
            "tool_name": tool_name,
            "stage": stage,
            "params": params,
            "success": result.success,
            "summary": result.summary,
        }
    )
    state["last_result"] = result.model_dump()
    container.result_parser.apply(state, result)
    for artifact_path in result.artifact_paths:
        container.task_service.add_artifact(
            task_id,
            artifact_type=tool_name,
            title=f"{tool_name} output",
            path=artifact_path,
            summary=result.summary,
        )
    container.task_service.add_event(
        task_id,
        event_type="tool_completed" if result.success else "tool_failed",
        stage=stage,
        message=f"Tool {tool_name} {'completed successfully' if result.success else 'failed'}.",
        payload={"tool_name": tool_name, "summary": result.summary},
    )


def collect_probe_context(state: dict, host: str, port: int) -> tuple[str, dict[str, str], list[str]]:
    page_title = ""
    headers: dict[str, str] = {}
    interesting_paths: list[str] = []
    for item in state.get("evidence", []):
        if item.get("target") != host or item.get("port") != port:
            continue
        data = item.get("data", {})
        if item.get("kind") == "web_probe" and not page_title:
            page_title = str(data.get("title", "")).strip()
            raw_headers = data.get("headers", {})
            if isinstance(raw_headers, dict):
                headers = {str(key): str(value) for key, value in raw_headers.items()}
        path = data.get("path")
        if isinstance(path, str) and path not in interesting_paths:
            interesting_paths.append(path)
    return page_title, headers, interesting_paths[:12]


def main() -> int:
    args = build_parser().parse_args()
    os.environ.setdefault("APP_DEBUG", "false")
    get_settings.cache_clear()
    container = create_container()

    normalized_scope = container.scope_guard.validate_scope([args.host])
    task = container.task_service.create_task(
        TaskCreate(
            name=args.task_name,
            scope=[args.host],
            authorization="Authorized local DVWA training target only.",
            lab_description=args.lab_description,
            objective=(
                "Collect HTTP evidence and, after approval, run a single controlled file inclusion PoC "
                "with request/parameter/success evidence preserved in the report."
            ),
            ports=str(args.port),
            max_steps=6,
            auto_run=False,
        ),
        normalized_scope,
    )
    state = task.state
    state["status"] = "running"
    state["current_stage"] = "web_probe"
    state["hosts"] = [{"address": args.host, "status": "up"}]
    state["services"] = [
        {
            "target": args.host,
            "port": args.port,
            "protocol": "tcp",
            "service": "http",
            "product": "PHP built-in server",
            "version": "",
        }
    ]
    container.task_service.update_task(
        task.id,
        TaskUpdate(
            status="running",
            current_stage="web_probe",
            state=state,
            started_at=utc_now(),
        ),
    )

    web_probe_params = {
        "target": args.host,
        "port": args.port,
        "scheme": args.scheme,
        "paths": ["/", "/setup.php", "/vulnerabilities/fi/"],
        "timeout": 10,
    }
    web_probe_result = container.tool_executor.execute(
        task_id=task.id,
        scope=normalized_scope,
        stage="web_probe",
        tool_name="web_probe",
        params=web_probe_params,
    )
    add_action(
        container,
        state,
        task.id,
        stage="web_probe",
        tool_name="web_probe",
        params=web_probe_params,
        result=web_probe_result,
    )

    dir_enum_params = {
        "target": args.host,
        "port": args.port,
        "scheme": args.scheme,
        "max_paths": 12,
        "timeout": 10,
    }
    dir_enum_result = container.tool_executor.execute(
        task_id=task.id,
        scope=normalized_scope,
        stage="dir_enum",
        tool_name="dir_enum",
        params=dir_enum_params,
    )
    add_action(
        container,
        state,
        task.id,
        stage="dir_enum",
        tool_name="dir_enum",
        params=dir_enum_params,
        result=dir_enum_result,
    )

    snapshot_params = {
        "target": args.host,
        "port": args.port,
        "scheme": args.scheme,
        "paths": ["/setup.php", "/vulnerabilities/fi/", "/login.php"],
        "timeout": 10,
        "max_body_chars": 300,
    }
    snapshot_result = container.tool_executor.execute(
        task_id=task.id,
        scope=normalized_scope,
        stage="http_snapshot",
        tool_name="http_snapshot",
        params=snapshot_params,
    )
    add_action(
        container,
        state,
        task.id,
        stage="http_snapshot",
        tool_name="http_snapshot",
        params=snapshot_params,
        result=snapshot_result,
    )

    page_title, headers, interesting_paths = collect_probe_context(state, args.host, args.port)
    verify_params = {
        "target": args.host,
        "port": args.port,
        "scheme": args.scheme,
        "profile": "php_apache",
        "preferred_poc": "dvwa_fi",
        "service_name": "http",
        "service_product": "PHP built-in server",
        "lab_description": args.lab_description,
        "page_title": page_title,
        "headers": headers,
        "interesting_paths": interesting_paths or ["/", "/setup.php", "/vulnerabilities/fi/"],
        "timeout": 45,
    }
    approval = container.approval_service.create_approval(
        task.id,
        tool_name="vuln_verify",
        target=f"{args.host}:{args.port}",
        risk_level="high",
        reason="Run one approved DVWA file inclusion PoC against the local training target.",
        params=verify_params,
    )
    container.task_service.add_event(
        task.id,
        event_type="approval_requested",
        stage="vuln_verify",
        message="High-risk DVWA FI PoC requested for approval.",
        payload={"approval_id": approval.id, "params": verify_params},
    )
    container.approval_service.approve(
        approval.id,
        ApprovalDecision(note="Approved for the local DVWA report demonstration."),
    )

    verify_result = container.tool_executor.execute(
        task_id=task.id,
        scope=normalized_scope,
        stage="vuln_verify",
        tool_name="vuln_verify",
        params=verify_params,
    )
    add_action(
        container,
        state,
        task.id,
        stage="vuln_verify",
        tool_name="vuln_verify",
        params=verify_params,
        result=verify_result,
    )

    state["status"] = "completed"
    state["current_stage"] = "generate_report"
    state["stop_reason"] = "No further safe actions are pending."
    updated_task = container.task_service.update_task(
        task.id,
        TaskUpdate(
            status="completed",
            current_stage="generate_report",
            state=state,
            finished_at=utc_now(),
            stop_reason=state["stop_reason"],
        ),
    )

    approvals = container.approval_service.list_approvals(task.id)
    events = container.task_service.list_events(task.id)
    artifacts = container.task_service.list_artifacts(task.id)
    markdown_content, _, report_path = container.report_agent.generate(
        updated_task,
        events,
        approvals,
        artifacts,
    )
    container.task_service.update_task(
        task.id,
        TaskUpdate(
            status="completed",
            current_stage="completed",
            state=state,
            report_path=report_path,
            finished_at=updated_task.finished_at or utc_now(),
            stop_reason=state["stop_reason"],
        ),
    )

    result = {
        "task_id": task.id,
        "report_path": report_path,
        "summary": verify_result.summary,
        "confirmed_pocs": [item for item in state.get("pocs", []) if item.get("status") == "confirmed"],
        "findings": state.get("findings", []),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if "DVWA File Inclusion low-level PoC" not in markdown_content:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
