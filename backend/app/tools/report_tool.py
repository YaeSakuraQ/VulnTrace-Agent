from __future__ import annotations

from app.schemas.tool import ToolExecutionResult
from app.tools.base import ToolContext


def execute(_: object, context: ToolContext) -> ToolExecutionResult:
    return ToolExecutionResult(
        tool_name="report_tool",
        success=True,
        summary=f"Report artifacts are stored under {context.artifact_dir}.",
        structured_data={},
    )
