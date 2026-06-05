from __future__ import annotations

import json
import re

import requests

from app.schemas.tool import ToolExecutionResult, WebProbeInput
from app.tools.base import ToolContext, ToolExecutionError


TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def execute(params: WebProbeInput, context: ToolContext) -> ToolExecutionResult:
    responses: list[dict[str, object]] = []

    for path in params.paths:
        url = f"{params.scheme}://{params.target}:{params.port}{path}"
        try:
            response = requests.get(url, timeout=params.timeout, allow_redirects=True, verify=False)
        except requests.RequestException as exc:
            raise ToolExecutionError(f"Web probe failed for {url}: {exc}") from exc

        title_match = TITLE_RE.search(response.text)
        title = title_match.group(1).strip() if title_match else ""
        headers = {
            key: value
            for key, value in response.headers.items()
            if key.lower() in {"server", "content-type", "x-powered-by", "location"}
        }
        responses.append(
            {
                "url": url,
                "path": path,
                "status_code": response.status_code,
                "title": title,
                "headers": headers,
                "content_length": len(response.text),
            }
        )

    artifact_path = context.artifact_dir / "web_probe.json"
    artifact_path.write_text(json.dumps(responses, indent=2), encoding="utf-8")

    summary = f"Collected {len(responses)} HTTP response sample(s) from {params.target}:{params.port}."
    return ToolExecutionResult(
        tool_name="web_probe",
        success=True,
        summary=summary,
        raw_output=json.dumps(responses, indent=2),
        structured_data={"responses": responses},
        artifact_paths=[str(artifact_path)],
    )
