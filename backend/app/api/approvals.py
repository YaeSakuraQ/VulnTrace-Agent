from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from app.schemas.approval import ApprovalDecision, ApprovalRecord
from app.services.approval_service import ApprovalNotFoundError


router = APIRouter(prefix="/approvals", tags=["approvals"])


@router.get("", response_model=list[ApprovalRecord])
async def list_approvals(
    request: Request,
    task_id: str | None = Query(default=None),
) -> list[ApprovalRecord]:
    return request.app.state.container.approval_service.list_approvals(task_id)


@router.post("/{approval_id}/approve", response_model=ApprovalRecord)
async def approve_action(
    approval_id: str,
    request: Request,
    payload: ApprovalDecision,
) -> ApprovalRecord:
    container = request.app.state.container
    try:
        approval = container.approval_service.approve(approval_id, payload)
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Approval not found.") from exc
    await container.task_runtime.schedule(approval.task_id)
    return approval


@router.post("/{approval_id}/reject", response_model=ApprovalRecord)
async def reject_action(
    approval_id: str,
    request: Request,
    payload: ApprovalDecision,
) -> ApprovalRecord:
    try:
        return request.app.state.container.approval_service.reject(approval_id, payload)
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Approval not found.") from exc


@router.post("/{approval_id}/edit", response_model=ApprovalRecord)
async def edit_and_approve_action(
    approval_id: str,
    request: Request,
    payload: ApprovalDecision,
) -> ApprovalRecord:
    container = request.app.state.container
    try:
        approval = container.approval_service.approve(approval_id, payload)
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Approval not found.") from exc
    await container.task_runtime.schedule(approval.task_id)
    return approval
