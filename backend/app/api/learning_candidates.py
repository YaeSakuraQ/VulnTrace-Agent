from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from app.schemas.learning_candidate import LearningCandidateDecision, LearningCandidateRecord
from app.services.knowledge_capture_service import LearningCandidateNotFoundError


router = APIRouter(prefix="/learning-candidates", tags=["learning-candidates"])


@router.get("", response_model=list[LearningCandidateRecord])
async def list_learning_candidates(
    request: Request,
    task_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
) -> list[LearningCandidateRecord]:
    return request.app.state.container.knowledge_capture_service.list_candidates(task_id=task_id, status=status)


@router.post("/{candidate_id}/approve", response_model=LearningCandidateRecord)
async def approve_learning_candidate(
    candidate_id: str,
    request: Request,
    payload: LearningCandidateDecision,
) -> LearningCandidateRecord:
    try:
        return request.app.state.container.knowledge_capture_service.approve(candidate_id, payload)
    except LearningCandidateNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Learning candidate not found.") from exc


@router.post("/{candidate_id}/reject", response_model=LearningCandidateRecord)
async def reject_learning_candidate(
    candidate_id: str,
    request: Request,
    payload: LearningCandidateDecision,
) -> LearningCandidateRecord:
    try:
        return request.app.state.container.knowledge_capture_service.reject(candidate_id, payload)
    except LearningCandidateNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Learning candidate not found.") from exc
