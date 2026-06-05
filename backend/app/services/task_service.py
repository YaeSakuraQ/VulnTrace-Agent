from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from app.db.session import Database
from app.schemas.task import ArtifactRecord, TaskCreate, TaskDetail, TaskEvent, TaskSummary, TaskUpdate


def utc_now() -> datetime:
    return datetime.now(UTC)


class TaskNotFoundError(KeyError):
    """Raised when a task id cannot be found."""


class TaskService:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create_task(self, payload: TaskCreate, normalized_scope: list[str]) -> TaskDetail:
        now = utc_now()
        task_id = str(uuid4())
        state = {
            "task_id": task_id,
            "task_name": payload.name,
            "scope": normalized_scope,
            "authorization": payload.authorization,
            "lab_description": payload.lab_description,
            "objective": payload.objective,
            "ports": payload.ports,
            "current_stage": "validate_scope",
            "status": "draft",
            "hosts": [],
            "services": [],
            "hypotheses": [],
            "findings": [],
            "evidence": [],
            "pocs": [],
            "actions": [],
            "reflections": [],
            "pending_approval": None,
            "approved_action": None,
            "last_decision": None,
            "last_result": None,
            "last_reflection": None,
            "last_summary": None,
            "path_graph": {"nodes": [], "edges": []},
            "report_path": None,
            "error_count": 0,
            "stop_reason": None,
            "max_steps": payload.max_steps,
            "step_count": 0,
        }

        with self.database.connection() as conn:
            conn.execute(
                """
                INSERT INTO tasks (
                    id, name, scope_json, authorization, lab_description, objective,
                    ports, current_stage, status, state_json, report_path, stop_reason,
                    created_at, updated_at, started_at, finished_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    payload.name,
                    json.dumps(normalized_scope),
                    payload.authorization,
                    payload.lab_description,
                    payload.objective,
                    payload.ports,
                    "validate_scope",
                    "draft",
                    json.dumps(state),
                    None,
                    None,
                    now.isoformat(),
                    now.isoformat(),
                    None,
                    None,
                ),
            )
            conn.commit()

        self.add_event(
            task_id,
            event_type="task_created",
            stage="validate_scope",
            message=f"Task {payload.name} created.",
            payload={"scope": normalized_scope, "objective": payload.objective},
        )
        return self.get_task(task_id)

    def list_tasks(self) -> list[TaskSummary]:
        with self.database.connection() as conn:
            rows = conn.execute("SELECT * FROM tasks ORDER BY created_at DESC").fetchall()
        return [self._row_to_summary(row) for row in rows]

    def get_task(self, task_id: str) -> TaskDetail:
        with self.database.connection() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise TaskNotFoundError(task_id)
        return self._row_to_detail(row)

    def update_task(self, task_id: str, payload: TaskUpdate) -> TaskDetail:
        current = self.get_task(task_id)
        now = utc_now()
        state = payload.state if payload.state is not None else current.state
        current_stage = payload.current_stage or current.current_stage
        status = payload.status or current.status
        report_path = payload.report_path if payload.report_path is not None else current.report_path
        stop_reason = payload.stop_reason if payload.stop_reason is not None else current.stop_reason
        started_at = payload.started_at or current.started_at
        finished_at = payload.finished_at if payload.finished_at is not None else current.finished_at

        with self.database.connection() as conn:
            conn.execute(
                """
                UPDATE tasks
                SET current_stage = ?, status = ?, state_json = ?, report_path = ?,
                    stop_reason = ?, updated_at = ?, started_at = ?, finished_at = ?
                WHERE id = ?
                """,
                (
                    current_stage,
                    status,
                    json.dumps(state),
                    report_path,
                    stop_reason,
                    now.isoformat(),
                    started_at.isoformat() if started_at else None,
                    finished_at.isoformat() if finished_at else None,
                    task_id,
                ),
            )
            conn.commit()
        return self.get_task(task_id)

    def add_event(
        self,
        task_id: str,
        *,
        event_type: str,
        message: str,
        stage: str | None = None,
        payload: dict | None = None,
    ) -> TaskEvent:
        created_at = utc_now()
        with self.database.connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO events (task_id, event_type, stage, message, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    event_type,
                    stage,
                    message,
                    json.dumps(payload or {}),
                    created_at.isoformat(),
                ),
            )
            conn.commit()
            event_id = cursor.lastrowid

        return TaskEvent(
            id=event_id,
            task_id=task_id,
            event_type=event_type,
            stage=stage,
            message=message,
            payload=payload or {},
            created_at=created_at,
        )

    def list_events(self, task_id: str, after_id: int | None = None) -> list[TaskEvent]:
        query = "SELECT * FROM events WHERE task_id = ?"
        params: list[object] = [task_id]
        if after_id is not None:
            query += " AND id > ?"
            params.append(after_id)
        query += " ORDER BY id ASC"
        with self.database.connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [
            TaskEvent(
                id=row["id"],
                task_id=row["task_id"],
                event_type=row["event_type"],
                stage=row["stage"],
                message=row["message"],
                payload=json.loads(row["payload_json"]),
                created_at=datetime.fromisoformat(row["created_at"]),
            )
            for row in rows
        ]

    def add_artifact(
        self,
        task_id: str,
        *,
        artifact_type: str,
        title: str,
        path: str,
        summary: str,
    ) -> ArtifactRecord:
        artifact_id = str(uuid4())
        created_at = utc_now()
        with self.database.connection() as conn:
            conn.execute(
                """
                INSERT INTO artifacts (id, task_id, artifact_type, title, path, summary, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact_id,
                    task_id,
                    artifact_type,
                    title,
                    path,
                    summary,
                    created_at.isoformat(),
                ),
            )
            conn.commit()
        return ArtifactRecord(
            id=artifact_id,
            task_id=task_id,
            artifact_type=artifact_type,
            title=title,
            path=path,
            summary=summary,
            created_at=created_at,
        )

    def list_artifacts(self, task_id: str) -> list[ArtifactRecord]:
        with self.database.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM artifacts WHERE task_id = ? ORDER BY created_at ASC",
                (task_id,),
            ).fetchall()
        return [
            ArtifactRecord(
                id=row["id"],
                task_id=row["task_id"],
                artifact_type=row["artifact_type"],
                title=row["title"],
                path=row["path"],
                summary=row["summary"],
                created_at=datetime.fromisoformat(row["created_at"]),
            )
            for row in rows
        ]

    def _row_to_summary(self, row: object) -> TaskSummary:
        return TaskSummary(
            id=row["id"],
            name=row["name"],
            scope=json.loads(row["scope_json"]),
            authorization=row["authorization"],
            lab_description=row["lab_description"],
            objective=row["objective"],
            ports=row["ports"],
            current_stage=row["current_stage"],
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
            finished_at=datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None,
            report_path=row["report_path"],
            stop_reason=row["stop_reason"],
        )

    def _row_to_detail(self, row: object) -> TaskDetail:
        summary = self._row_to_summary(row)
        return TaskDetail(**summary.model_dump(), state=json.loads(row["state_json"]))
