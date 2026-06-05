from __future__ import annotations

import json
import time

import requests

from app.schemas.tool import DirEnumInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError


COMMON_PATHS = [
    "/admin",
    "/login",
    "/robots.txt",
    "/.git/",
    "/backup.zip",
    "/config.php",
    "/phpinfo.php",
    "/server-status",
    "/uploads/",
    "/api/",
    "/test/",
    "/dev/",
]


def execute(params: DirEnumInput, context: ToolContext) -> ToolExecutionResult:
    findings: list[dict[str, object]] = []

    for path in COMMON_PATHS[: params.max_paths]:
        url = f"{params.scheme}://{params.target}:{params.port}{path}"
        try:
            response = requests.get(url, timeout=params.timeout, allow_redirects=False, verify=False)
        except requests.RequestException as exc:
            raise ToolExecutionError(f"Directory enumeration failed for {url}: {exc}") from exc

        if response.status_code < 400 or response.status_code in {401, 403}:
            findings.append(
                {
                    "path": path,
                    "url": url,
                    "status_code": response.status_code,
                    "content_length": len(response.text),
                }
            )
        time.sleep(0.15)

    artifact_path = context.artifact_dir / "dir_enum.json"
    artifact_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    summary = f"Found {len(findings)} interesting path(s) during bounded enumeration."
    return ToolExecutionResult(
        tool_name="dir_enum",
        success=True,
        summary=summary,
        raw_output=json.dumps(findings, indent=2),
        structured_data={"paths": findings},
        artifact_paths=[str(artifact_path)],
    )
