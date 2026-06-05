from __future__ import annotations

import json
import re

import requests

from app.schemas.tool import HttpSnapshotInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError


WHITESPACE_RE = re.compile(r"\s+")


def execute(params: HttpSnapshotInput, context: ToolContext) -> ToolExecutionResult:
    snapshots: list[dict[str, object]] = []

    for path in params.paths:
        url = f"{params.scheme}://{params.target}:{params.port}{path}"
        try:
            response = requests.get(
                url,
                timeout=params.timeout,
                allow_redirects=False,
                verify=False,
            )
        except requests.RequestException as exc:
            raise ToolExecutionError(f"HTTP snapshot failed for {url}: {exc}") from exc

        body = WHITESPACE_RE.sub(" ", response.text).strip()
        body_snippet = body[: params.max_body_chars]
        headers = {
            key: value
            for key, value in response.headers.items()
            if key.lower() in {"server", "content-type", "x-powered-by", "location"}
        }
        snapshots.append(
            {
                "url": url,
                "path": path,
                "status_code": response.status_code,
                "headers": headers,
                "content_length": len(response.text),
                "body_snippet": body_snippet,
            }
        )

    artifact_path = context.artifact_dir / "http_snapshot.json"
    artifact_path.write_text(json.dumps(snapshots, indent=2), encoding="utf-8")

    summary = f"Captured {len(snapshots)} HTTP snapshot(s) from {params.target}:{params.port}."
    return ToolExecutionResult(
        tool_name="http_snapshot",
        success=True,
        summary=summary,
        raw_output=json.dumps(snapshots, indent=2),
        structured_data={"snapshots": snapshots},
        artifact_paths=[str(artifact_path)],
    )
