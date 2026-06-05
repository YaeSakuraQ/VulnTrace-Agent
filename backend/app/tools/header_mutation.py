from __future__ import annotations

import json

from app.schemas.tool import HeaderMutationInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError
from app.tools.vuln_verify import _send_raw_http_request, _split_http_response


def execute(params: HeaderMutationInput, context: ToolContext) -> ToolExecutionResult:
    header_lines = [f"{key}: {value}" for key, value in params.headers.items()]
    request = (
        f"{params.method} {params.path} {params.protocol_version}\r\n"
        + "\r\n".join(header_lines)
        + "\r\n\r\n"
        + params.body
    )
    try:
        response = _send_raw_http_request(params.target, params.port, request)
    except OSError as exc:
        raise ToolExecutionError(f"Header mutation request failed: {exc}") from exc

    status_code, headers, body = _split_http_response(response)
    structured = {
        "status_code": status_code,
        "headers": headers,
        "body_preview": body[:500],
        "raw_request": request,
        "raw_response": response[:2000],
        "path": params.path,
        "method": params.method,
    }
    artifact_path = context.artifact_dir / "header_mutation.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    return ToolExecutionResult(
        tool_name="header_mutation",
        success=True,
        summary=f"Mutated-header request to {params.path} returned HTTP {status_code}.",
        raw_output=response[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
