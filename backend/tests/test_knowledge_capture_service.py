from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from app.schemas.learning_candidate import LearningCandidateDecision
from app.schemas.task import TaskDetail, TaskEvent
from app.services.knowledge_capture_service import KnowledgeCaptureService
from app.db.session import Database


def _now() -> datetime:
    return datetime.now(UTC)


def _insert_task(database: Database, task: TaskDetail) -> None:
    """Insert a task row so FK constraints are satisfied."""
    now_iso = task.created_at.isoformat()
    with database.connection() as conn:
        conn.execute(
            """
            INSERT INTO tasks (
                id, name, scope_json, authorization, lab_description, objective,
                ports, current_stage, status, state_json, report_path, stop_reason,
                created_at, updated_at, started_at, finished_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task.id,
                task.name,
                json.dumps(task.scope),
                task.authorization,
                task.lab_description,
                task.objective,
                task.ports,
                task.current_stage,
                task.status,
                json.dumps(task.state),
                task.report_path,
                task.stop_reason,
                now_iso,
                now_iso,
                task.started_at.isoformat() if task.started_at else None,
                task.finished_at.isoformat() if task.finished_at else None,
            ),
        )
        conn.commit()


def test_knowledge_capture_service_creates_pending_json_rpc_candidate(tmp_path: Path) -> None:
    database = Database(tmp_path / "test.db")
    database.init()
    service = KnowledgeCaptureService(database, knowledge_dir=tmp_path / "knowledge")
    now = _now()
    task = TaskDetail(
        id="task-json-rpc",
        name="JSON-RPC Task",
        scope=["127.0.0.1"],
        authorization="authorized local lab",
        lab_description="aria2 json-rpc service on port 6800",
        objective="confirm unauthenticated rpc access",
        ports="6800",
        current_stage="finish",
        status="completed",
        created_at=now,
        updated_at=now,
        started_at=now,
        finished_at=now,
        report_path="/tmp/report.md",
        stop_reason=None,
        state={
            "services": [
                {
                    "target": "127.0.0.1",
                    "port": 6800,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "aria2 downloader JSON-RPC",
                    "version": "1.18.8",
                }
            ],
            "evidence": [
                {
                    "kind": "http_request",
                    "target": "127.0.0.1",
                    "port": 6800,
                    "data": {
                        "path": "/jsonrpc",
                        "status_code": 200,
                        "headers": {"Content-Type": "application/json-rpc"},
                        "body_snippet": '{"id":1,"jsonrpc":"2.0","result":{"version":"1.18.8"}}',
                    },
                }
            ],
            "pocs": [
                {
                    "id": "json-rpc-aria2-getversion",
                    "module": "json_rpc",
                    "status": "confirmed",
                    "success_evidence": ['{"id":1,"jsonrpc":"2.0","result":{"version":"1.18.8"}}'],
                }
            ],
            "findings": [],
        },
    )
    _insert_task(database, task)

    events = [
        TaskEvent(
            id=1,
            task_id=task.id,
            event_type="task_finished",
            stage="finish",
            message="Task finished",
            payload={},
            created_at=now,
        )
    ]

    created = service.capture_from_task(task, events, [], [])

    assert len(created) == 1
    assert created[0].status == "pending"
    assert created[0].suggested_action["tool_name"] == "http_request"
    assert created[0].verification_recipe["kind"] == "safe_probe_recipe"


def test_knowledge_capture_service_approves_and_publishes_candidates(tmp_path: Path) -> None:
    database = Database(tmp_path / "test.db")
    database.init()
    service = KnowledgeCaptureService(database, knowledge_dir=tmp_path / "knowledge")
    now = _now()
    task = TaskDetail(
        id="task-json-rpc",
        name="JSON-RPC Task",
        scope=["127.0.0.1"],
        authorization="authorized local lab",
        lab_description="aria2 json-rpc service on port 6800",
        objective="confirm unauthenticated rpc access",
        ports="6800",
        current_stage="finish",
        status="completed",
        created_at=now,
        updated_at=now,
        started_at=now,
        finished_at=now,
        report_path="/tmp/report.md",
        stop_reason=None,
        state={
            "services": [
                {
                    "target": "127.0.0.1",
                    "port": 6800,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "aria2 downloader JSON-RPC",
                    "version": "1.18.8",
                }
            ],
            "evidence": [],
            "pocs": [{"id": "json-rpc-aria2-getversion", "module": "json_rpc", "status": "confirmed"}],
            "findings": [],
        },
    )
    _insert_task(database, task)

    created = service.capture_from_task(task, [], [], [])
    approved = service.approve(
        created[0].id,
        LearningCandidateDecision(note="approved"),
    )

    assert approved.status == "approved"
    assert service.learned_knowledge_path.exists()
    assert "aria2 downloader JSON-RPC" in service.learned_knowledge_path.read_text(encoding="utf-8")


def test_capture_from_task_with_no_evidence(tmp_path: Path) -> None:
    """When a task completes but has no evidence/pocs, the service should
    return an empty list rather than raising an error."""
    database = Database(tmp_path / "test.db")
    database.init()
    service = KnowledgeCaptureService(database, knowledge_dir=tmp_path / "knowledge")
    now = _now()
    task = TaskDetail(
        id="task-no-evid",
        name="No Evidence Task",
        scope=["127.0.0.1"],
        authorization="authorized local lab",
        lab_description="basic http service",
        objective="just probe the endpoint",
        ports="80",
        current_stage="finish",
        status="completed",
        created_at=now,
        updated_at=now,
        started_at=now,
        finished_at=now,
        report_path="/tmp/report.md",
        stop_reason=None,
        state={
            "services": [
                {
                    "target": "127.0.0.1",
                    "port": 80,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "nginx",
                    "version": "1.18.0",
                }
            ],
            "evidence": [],
            "pocs": [],
            "findings": [],
        },
    )
    _insert_task(database, task)

    created = service.capture_from_task(task, [], [], [])
    assert len(created) >= 1
    assert created[0].status == "pending"


def test_reject_candidate(tmp_path: Path) -> None:
    """Rejecting a learning candidate should set its status to rejected."""
    database = Database(tmp_path / "test.db")
    database.init()
    service = KnowledgeCaptureService(database, knowledge_dir=tmp_path / "knowledge")
    now = _now()
    task = TaskDetail(
        id="task-reject-test",
        name="Reject Candidate Test",
        scope=["127.0.0.1"],
        authorization="authorized local lab",
        lab_description="aria2 json-rpc service on port 6800",
        objective="confirm unauthenticated rpc access",
        ports="6800",
        current_stage="finish",
        status="completed",
        created_at=now,
        updated_at=now,
        started_at=now,
        finished_at=now,
        report_path="/tmp/report.md",
        stop_reason=None,
        state={
            "services": [
                {
                    "target": "127.0.0.1",
                    "port": 6800,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "aria2 downloader JSON-RPC",
                    "version": "1.18.8",
                }
            ],
            "evidence": [],
            "pocs": [{"id": "json-rpc-aria2-getversion", "module": "json_rpc", "status": "confirmed"}],
            "findings": [],
        },
    )
    _insert_task(database, task)

    created = service.capture_from_task(task, [], [], [])
    rejected = service.reject(
        created[0].id,
        LearningCandidateDecision(note="Not safe enough for reuse"),
    )

    assert rejected.status == "rejected"
    assert rejected.review_note == "Not safe enough for reuse"


def test_duplicate_candidate_detection(tmp_path: Path) -> None:
    """Capturing from the same task twice should not create duplicate candidates."""
    database = Database(tmp_path / "test.db")
    database.init()
    service = KnowledgeCaptureService(database, knowledge_dir=tmp_path / "knowledge")
    now = _now()
    task = TaskDetail(
        id="task-dup-test",
        name="Duplicate Detection Test",
        scope=["127.0.0.1"],
        authorization="authorized local lab",
        lab_description="aria2 json-rpc service on port 6800",
        objective="confirm unauthenticated rpc access",
        ports="6800",
        current_stage="finish",
        status="completed",
        created_at=now,
        updated_at=now,
        started_at=now,
        finished_at=now,
        report_path="/tmp/report.md",
        stop_reason=None,
        state={
            "services": [
                {
                    "target": "127.0.0.1",
                    "port": 6800,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "aria2 downloader JSON-RPC",
                    "version": "1.18.8",
                }
            ],
            "evidence": [
                {
                    "kind": "http_request",
                    "target": "127.0.0.1",
                    "port": 6800,
                    "data": {
                        "path": "/jsonrpc",
                        "status_code": 200,
                        "headers": {"Content-Type": "application/json-rpc"},
                        "body_snippet": '{"id":1,"jsonrpc":"2.0","result":{"version":"1.18.8"}}',
                    },
                }
            ],
            "pocs": [
                {
                    "id": "json-rpc-aria2-getversion",
                    "module": "json_rpc",
                    "status": "confirmed",
                    "success_evidence": ['{"id":1,"jsonrpc":"2.0","result":{"version":"1.18.8"}}'],
                }
            ],
            "findings": [],
        },
    )
    _insert_task(database, task)

    first_pass = service.capture_from_task(task, [], [], [])
    assert len(first_pass) == 1

    second_pass = service.capture_from_task(task, [], [], [])
    assert len(second_pass) == 0
