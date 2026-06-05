from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

from app.schemas.report import ReportResponse
from app.services.task_service import TaskNotFoundError


router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{task_id}", response_model=ReportResponse)
async def get_report(task_id: str, request: Request) -> ReportResponse:
    container = request.app.state.container
    try:
        task = container.task_service.get_task(task_id)
    except TaskNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Task not found.") from exc
    if not task.report_path:
        raise HTTPException(status_code=404, detail="Report not generated yet.")

    report_path = Path(task.report_path)
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report file is missing.")

    markdown_content = report_path.read_text(encoding="utf-8")
    html_path = report_path.with_suffix(".html")
    html_content = html_path.read_text(encoding="utf-8") if html_path.exists() else ""
    return ReportResponse(
        task_id=task_id,
        markdown=markdown_content,
        html=html_content,
        path=str(report_path),
    )
