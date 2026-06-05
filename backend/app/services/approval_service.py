from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from app.schemas.approval import ApprovalDecision, ApprovalRecord
from app.schemas.task import TaskUpdate
from app.services.task_service import TaskService


def utc_now() -> datetime:
    return datetime.now(UTC)


class ApprovalNotFoundError(KeyError):
    """Raised when an approval id cannot be found."""


class ApprovalService:
    def __init__(self, task_service: TaskService) -> None:
        self.task_service = task_service
        self.database = task_service.database

    def create_approval(
        self,
        task_id: str,
        *,
        tool_name: str,
        target: str,
        risk_level: str,
        reason: str,
        params: dict,
    ) -> ApprovalRecord:
        approval_id = str(uuid4())
        created_at = utc_now()
        with self.database.connection() as conn:
            conn.execute(
                """
                INSERT INTO approvals (id, task_id, tool_name, target, risk_level, reason, params_json, status, created_at, decided_at, decision_note)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    approval_id,
                    task_id,
                    tool_name,
                    target,
                    risk_level,
                    reason,
                    json.dumps(params),
                    "pending",
                    created_at.isoformat(),
                    None,
                    None,
                ),
            )
            conn.commit()

        return ApprovalRecord(
            id=approval_id,
            task_id=task_id,
            tool_name=tool_name,
            target=target,
            risk_level=risk_level,
            reason=reason,
            params=params,
            status="pending",
            created_at=created_at,
        )

    def get_approval(self, approval_id: str) -> ApprovalRecord:
        with self.database.connection() as conn:
            row = conn.execute(
                "SELECT * FROM approvals WHERE id = ?",
                (approval_id,),
            ).fetchone()
        if row is None:
            raise ApprovalNotFoundError(approval_id)
        return ApprovalRecord(
            id=row["id"],
            task_id=row["task_id"],
            tool_name=row["tool_name"],
            target=row["target"],
            risk_level=row["risk_level"],
            reason=row["reason"],
            params=json.loads(row["params_json"]),
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            decided_at=datetime.fromisoformat(row["decided_at"]) if row["decided_at"] else None,
            decision_note=row["decision_note"],
        )

    def list_approvals(self, task_id: str | None = None) -> list[ApprovalRecord]:
        query = "SELECT * FROM approvals"
        params: tuple[str, ...] = ()
        if task_id:
            query += " WHERE task_id = ?"
            params = (task_id,)
        query += " ORDER BY created_at DESC"
        with self.database.connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            ApprovalRecord(
                id=row["id"],
                task_id=row["task_id"],
                tool_name=row["tool_name"],
                target=row["target"],
                risk_level=row["risk_level"],
                reason=row["reason"],
                params=json.loads(row["params_json"]),
                status=row["status"],
                created_at=datetime.fromisoformat(row["created_at"]),
                decided_at=datetime.fromisoformat(row["decided_at"]) if row["decided_at"] else None,
                decision_note=row["decision_note"],
            )
            for row in rows
        ]

    def approve(self, approval_id: str, decision: ApprovalDecision) -> ApprovalRecord:
        return self._apply_decision(approval_id, decision, status="approved")

    def reject(self, approval_id: str, decision: ApprovalDecision) -> ApprovalRecord:
        return self._apply_decision(approval_id, decision, status="rejected")

    def _apply_decision(
        self,
        approval_id: str,
        decision: ApprovalDecision,
        *,
        status: str,
    ) -> ApprovalRecord:
        approval = self.get_approval(approval_id)
        decided_at = utc_now()
        params = decision.edited_params or approval.params
        with self.database.connection() as conn:
            conn.execute(
                """
                UPDATE approvals
                SET params_json = ?, status = ?, decided_at = ?, decision_note = ?
                WHERE id = ?
                """,
                (
                    json.dumps(params),
                    status,
                    decided_at.isoformat(),
                    decision.note,
                    approval_id,
                ),
            )
            conn.commit()

        task = self.task_service.get_task(approval.task_id)
        state = task.state
        state["pending_approval"] = None
        state["approved_action"] = (
            {
                "tool_name": approval.tool_name,
                "params": params,
                "risk_level": approval.risk_level,
                "reason": approval.reason,
            }
            if status == "approved"
            else None
        )
        updated_status = "paused"
        stop_reason = "High-risk action rejected by user." if status == "rejected" else task.stop_reason
        self.task_service.update_task(
            approval.task_id,
            TaskUpdate(
                status=updated_status,
                state=state,
                stop_reason=stop_reason,
            ),
        )
        self.task_service.add_event(
            approval.task_id,
            event_type=f"approval_{status}",
            stage=task.current_stage,
            message=f"Approval {approval_id} marked as {status}.",
            payload={"tool_name": approval.tool_name, "params": params, "note": decision.note},
        )
        return self.get_approval(approval_id)
