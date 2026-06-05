from __future__ import annotations

import json
import re

import requests

from app.schemas.tool import HttpGetInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError


TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)
WHITESPACE_RE = re.compile(r"\s+")


def execute(params: HttpGetInput, context: ToolContext) -> ToolExecutionResult:
    url = f"{params.scheme}://{params.target}:{params.port}{params.path}"
    try:
        response = requests.request(
            method=params.method,
            url=url,
            headers=params.headers,
            timeout=params.timeout,
            allow_redirects=params.allow_redirects,
            verify=False,
        )
    except requests.RequestException as exc:
        raise ToolExecutionError(f"HTTP request failed for {url}: {exc}") from exc

    title_match = TITLE_RE.search(response.text)
    body = WHITESPACE_RE.sub(" ", response.text).strip()
    body_snippet = body[:400]
    structured = {
        "url": response.url,
        "path": params.path,
        "status_code": response.status_code,
        "title": title_match.group(1).strip() if title_match else "",
        "headers": {str(key): str(value) for key, value in response.headers.items()},
        "body_snippet": body_snippet,
        "method": params.method,
        "request_headers": params.headers,
    }

    artifact_path = context.artifact_dir / "http_get.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    return ToolExecutionResult(
        tool_name="http_get",
        success=True,
        summary=f"{params.method} {params.path} returned HTTP {response.status_code}.",
        raw_output=response.text[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
