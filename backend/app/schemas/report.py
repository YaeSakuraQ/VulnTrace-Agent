from __future__ import annotations

from pydantic import BaseModel


class ReportResponse(BaseModel):
    task_id: str
    markdown: str
    html: str
    path: str | None = None
