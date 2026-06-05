from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


ApprovalStatus = Literal["pending", "approved", "rejected"]


class ApprovalRecord(BaseModel):
    id: str
    task_id: str
    tool_name: str
    target: str
    risk_level: str
    reason: str
    params: dict[str, Any]
    status: ApprovalStatus
    created_at: datetime
    decided_at: datetime | None = None
    decision_note: str | None = None


class ApprovalDecision(BaseModel):
    note: str = ""
    edited_params: dict[str, Any] | None = None


class ApprovalActionPayload(BaseModel):
    tool_name: str
    params: dict[str, Any] = Field(default_factory=dict)
    risk_level: str
    reason: str
