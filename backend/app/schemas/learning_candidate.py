from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


LearningCandidateStatus = Literal["pending", "approved", "rejected"]


class LearningCandidateRecord(BaseModel):
    id: str
    task_id: str
    title: str
    summary: str
    fingerprint_key: str
    signature: dict[str, Any] = Field(default_factory=dict)
    suggested_action: dict[str, Any] = Field(default_factory=dict)
    verification_recipe: dict[str, Any] = Field(default_factory=dict)
    evidence_markers: list[str] = Field(default_factory=list)
    status: LearningCandidateStatus
    created_at: datetime
    reviewed_at: datetime | None = None
    review_note: str | None = None


class LearningCandidateDecision(BaseModel):
    note: str = ""
    edited_suggested_action: dict[str, Any] | None = None
    edited_verification_recipe: dict[str, Any] | None = None
