from __future__ import annotations

import asyncio

from app.agents.graph import PentestGraphRunner


class TaskRuntime:
    def __init__(self, graph_runner: PentestGraphRunner) -> None:
        self.graph_runner = graph_runner
        self._running: dict[str, asyncio.Task] = {}

    async def schedule(self, task_id: str) -> bool:
        existing = self._running.get(task_id)
        if existing and not existing.done():
            return False
        task = asyncio.create_task(self._run(task_id))
        self._running[task_id] = task
        return True

    async def _run(self, task_id: str) -> None:
        try:
            await asyncio.to_thread(self.graph_runner.run, task_id)
        finally:
            self._running.pop(task_id, None)

    def is_running(self, task_id: str) -> bool:
        task = self._running.get(task_id)
        return bool(task and not task.done())
