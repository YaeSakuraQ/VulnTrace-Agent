from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import JSON, ForeignKey, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    scope_json: Mapped[Any] = mapped_column(JSON, nullable=False)
    authorization: Mapped[str] = mapped_column(String, nullable=False)
    lab_description: Mapped[str] = mapped_column(String, nullable=False)
    objective: Mapped[str] = mapped_column(String, nullable=False)
    ports: Mapped[str] = mapped_column(String, nullable=False)
    current_stage: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    state_json: Mapped[Any] = mapped_column(JSON, nullable=False)
    report_path: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    stop_reason: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    started_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    finished_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    events: Mapped[list["TaskEvent"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )
    approvals: Mapped[list["Approval"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )
    artifacts: Mapped[list["Artifact"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )
    learning_candidates: Mapped[list["LearningCandidate"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )


class TaskEvent(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    stage: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    message: Mapped[str] = mapped_column(String, nullable=False)
    payload_json: Mapped[Any] = mapped_column(JSON, nullable=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)

    task: Mapped["Task"] = relationship(back_populates="events")


class Approval(Base):
    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    task_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tool_name: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[str] = mapped_column(String, nullable=False)
    risk_level: Mapped[str] = mapped_column(String, nullable=False)
    reason: Mapped[str] = mapped_column(String, nullable=False)
    params_json: Mapped[Any] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    decided_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    decision_note: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    task: Mapped["Task"] = relationship(back_populates="approvals")


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    task_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    artifact_type: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    path: Mapped[str] = mapped_column(String, nullable=False)
    summary: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)

    task: Mapped["Task"] = relationship(back_populates="artifacts")


class LearningCandidate(Base):
    __tablename__ = "learning_candidates"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    task_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String, nullable=False)
    summary: Mapped[str] = mapped_column(String, nullable=False)
    fingerprint_key: Mapped[str] = mapped_column(String, nullable=False)
    signature_json: Mapped[Any] = mapped_column(JSON, nullable=False)
    suggested_action_json: Mapped[Any] = mapped_column(JSON, nullable=False)
    verification_recipe_json: Mapped[Any] = mapped_column(JSON, nullable=False)
    evidence_markers_json: Mapped[Any] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    reviewed_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    review_note: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    task: Mapped["Task"] = relationship(back_populates="learning_candidates")


# ── Backward-compatible raw SQL schema strings ──────────────────────────

TASKS_TABLE = """
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    authorization TEXT NOT NULL,
    lab_description TEXT NOT NULL,
    objective TEXT NOT NULL,
    ports TEXT NOT NULL,
    current_stage TEXT NOT NULL,
    status TEXT NOT NULL,
    state_json TEXT NOT NULL,
    report_path TEXT,
    stop_reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);
"""

EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    stage TEXT,
    message TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
);
"""

APPROVALS_TABLE = """
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    target TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    reason TEXT NOT NULL,
    params_json TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    decided_at TEXT,
    decision_note TEXT,
    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
);
"""

ARTIFACTS_TABLE = """
CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    title TEXT NOT NULL,
    path TEXT NOT NULL,
    summary TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
);
"""

LEARNING_CANDIDATES_TABLE = """
CREATE TABLE IF NOT EXISTS learning_candidates (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    fingerprint_key TEXT NOT NULL,
    signature_json TEXT NOT NULL,
    suggested_action_json TEXT NOT NULL,
    verification_recipe_json TEXT NOT NULL,
    evidence_markers_json TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    reviewed_at TEXT,
    review_note TEXT,
    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
);
"""

SCHEMA = [
    TASKS_TABLE,
    EVENTS_TABLE,
    APPROVALS_TABLE,
    ARTIFACTS_TABLE,
    LEARNING_CANDIDATES_TABLE,
]
