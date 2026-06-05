from __future__ import annotations

from pathlib import Path

from app.tools.base import sanitize_filename


class ArtifactStore:
    def __init__(self, root_dir: Path) -> None:
        self.root_dir = root_dir
        self.root_dir.mkdir(parents=True, exist_ok=True)

    def task_dir(self, task_id: str) -> Path:
        path = self.root_dir / task_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def write_text(self, task_id: str, filename: str, content: str) -> Path:
        task_dir = self.task_dir(task_id)
        path = task_dir / sanitize_filename(filename)
        path.write_text(content, encoding="utf-8")
        return path
