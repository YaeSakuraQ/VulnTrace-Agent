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


@router.post("/publish-knowledge", response_model=dict)
async def publish_approved_knowledge(request: Request) -> dict:
    """Publish all approved learning candidates to the knowledge base files."""
    service = request.app.state.container.knowledge_capture_service
    service.publish_approved_candidates()

    # Also reload the exploit mapper so new signatures are immediately available
    exploit_mapper = request.app.state.container.planner.exploit_mapper
    exploit_mapper.reload_corpus()

    return {
        "status": "published",
        "signatures_total": len(exploit_mapper._signatures),
        "families_total": len(exploit_mapper._families),
    }


@router.post("/searchsploit-expand", response_model=dict)
async def run_searchsploit_expansion(
    request: Request,
    task_id: str = Query(...),
    auto_publish: bool = Query(default=False),
) -> dict:
    """Search exploit knowledge base for vulnerabilities matching the task's services.

    Creates learning candidates for review.  Set auto_publish=True to
    automatically approve and publish low-risk signatures.
    """
    container = request.app.state.container
    task = container.task_service.get_task(task_id)
    services = task.state.get("services", [])

    if not services:
        return {"error": "No services found in task state."}

    total_proposed = 0
    total_published: list[str] = []
    total_review_needed: list[str] = []

    for service in services:
        # Build search query
        query = container.planner.exploit_mapper.get_searchsploit_query(service)
        if not query:
            continue

        # Execute searchsploit lookup
        try:
            result = container.tool_executor.execute(
                task_id=task_id,
                scope=task.scope,
                stage="enumerate",
                tool_name="searchsploit_lookup",
                params={"query": query, "timeout": 60},
            )
        except Exception:
            continue

        if not result.success:
            continue

        search_results = result.structured_data.get("results", [])
        if not search_results:
            continue

        # Generate learning candidates
        capture_result = container.knowledge_capture_service.capture_from_searchsploit(
            task_id=task_id,
            service=service,
            searchsploit_results=search_results,
            auto_publish=auto_publish,
        )

        total_proposed += capture_result.get("proposed", 0)
        total_published.extend(capture_result.get("published", []))
        total_review_needed.extend(capture_result.get("review_needed", []))

    # Reload exploit mapper
    container.planner.exploit_mapper.reload_corpus()

    return {
        "proposed": total_proposed,
        "published": total_published,
        "review_needed": total_review_needed,
        "auto_publish": auto_publish,
    }
