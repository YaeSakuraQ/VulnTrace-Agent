from __future__ import annotations

import json

from app.schemas.tool import RawHttpInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError
from app.tools.vuln_verify import _send_raw_http_request, _split_http_response


def execute(params: RawHttpInput, context: ToolContext) -> ToolExecutionResult:
    try:
        response = _send_raw_http_request(params.target, params.port, params.request)
    except OSError as exc:
        raise ToolExecutionError(f"Raw HTTP request failed: {exc}") from exc

    status_code, headers, body = _split_http_response(response)
    structured = {
        "status_code": status_code,
        "headers": headers,
        "body_preview": body[:500],
        "raw_request": params.request,
        "raw_response": response[:2000],
    }
    artifact_path = context.artifact_dir / "raw_http.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    return ToolExecutionResult(
        tool_name="raw_http",
        success=True,
        summary=f"Raw HTTP request returned HTTP {status_code}.",
        raw_output=response[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
