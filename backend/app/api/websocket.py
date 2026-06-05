from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect


router = APIRouter(tags=["websocket"])


@router.websocket("/ws/tasks/{task_id}")
async def task_events(websocket: WebSocket, task_id: str) -> None:
    await websocket.accept()
    container = websocket.app.state.container
    last_event_id = 0
    try:
        task = container.task_service.get_task(task_id)
        await websocket.send_json(
            {
                "type": "task_snapshot",
                "task": task.model_dump(mode="json"),
            }
        )
        while True:
            events = container.task_service.list_events(task_id, after_id=last_event_id)
            for event in events:
                last_event_id = event.id
                await websocket.send_json({"type": "event", "event": event.model_dump(mode="json")})
            task = container.task_service.get_task(task_id)
            await websocket.send_json(
                {
                    "type": "heartbeat",
                    "status": task.status,
                    "stage": task.current_stage,
                }
            )
            await asyncio.sleep(container.settings.websocket_poll_interval)
    except WebSocketDisconnect:
        return
