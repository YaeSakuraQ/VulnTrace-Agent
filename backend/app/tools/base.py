from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from pydantic import BaseModel

from app.schemas.tool import ToolExecutionResult


class ToolExecutionError(RuntimeError):
    """Raised when a tool cannot be executed safely or successfully."""


@dataclass(slots=True)
class ToolContext:
    task_id: str
    artifact_dir: Path
    max_output_chars: int


@dataclass(slots=True)
class ToolSpec:
    name: str
    description: str
    input_model: type[BaseModel]
    risk_level: str
    approval_required: bool
    allowed_stages: tuple[str, ...]
    handler: Callable[[BaseModel, ToolContext], ToolExecutionResult]


def sanitize_filename(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", value.strip())
    return cleaned.strip("_") or "artifact"


def trim_output(content: str, max_chars: int) -> str:
    if len(content) <= max_chars:
        return content
    return content[: max_chars - 100] + "\n...[truncated]..."


def run_command(
    args: list[str],
    *,
    timeout: int,
    max_output_chars: int,
) -> tuple[str, str, int]:
    try:
        completed = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise ToolExecutionError(f"Required tool not found: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        partial_stdout = trim_output(exc.stdout or "", max_output_chars)
        partial_stderr = trim_output(exc.stderr or "", max_output_chars)
        details = [f"Command timed out after {timeout} seconds: {' '.join(args)}"]
        if partial_stdout:
            details.append(f"Partial stdout:\n{partial_stdout}")
        if partial_stderr:
            details.append(f"Partial stderr:\n{partial_stderr}")
        raise ToolExecutionError("\n".join(details)) from exc

    stdout = trim_output(completed.stdout or "", max_output_chars)
    stderr = trim_output(completed.stderr or "", max_output_chars)
    return stdout, stderr, completed.returncode
