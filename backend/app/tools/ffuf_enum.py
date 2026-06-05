from __future__ import annotations

import json
from pathlib import Path

from app.schemas.tool import FfufEnumInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError, run_command


DEFAULT_WORDS = [
    "admin",
    "login",
    "dashboard",
    "robots.txt",
    "api",
    "uploads",
    "test",
    "dev",
    "backup.zip",
    "phpinfo.php",
]


def execute(params: FfufEnumInput, context: ToolContext) -> ToolExecutionResult:
    words = params.words or DEFAULT_WORDS
    wordlist_path = context.artifact_dir / "ffuf_words.txt"
    wordlist_path.write_text("\n".join(words) + "\n", encoding="utf-8")

    output_path = context.artifact_dir / "ffuf_enum.json"
    base_url = f"{params.scheme}://{params.target}:{params.port}"
    args = [
        "ffuf",
        "-noninteractive",
        "-s",
        "-ac",
        "-w",
        str(wordlist_path),
        "-u",
        f"{base_url}/FUZZ",
        "-t",
        "1",
        "-rate",
        str(params.rate),
        "-timeout",
        str(min(params.timeout, 30)),
        "-maxtime",
        str(params.timeout),
        "-mc",
        "all",
        "-fc",
        "404",
        "-of",
        "json",
        "-o",
        str(output_path),
    ]
    stdout, stderr, return_code = run_command(
        args,
        timeout=params.timeout + 20,
        max_output_chars=context.max_output_chars,
    )
    if return_code != 0:
        raise ToolExecutionError(stderr or stdout or "ffuf enumeration failed.")

    results = _load_results(output_path)
    findings = [
        {
            "path": _path_from_url(item.get("url", "")),
            "url": item.get("url", ""),
            "status_code": item.get("status", 0),
            "content_length": item.get("length", 0),
            "words": item.get("words", 0),
            "lines": item.get("lines", 0),
            "content_type": item.get("content-type", ""),
            "redirect_location": item.get("redirectlocation", ""),
        }
        for item in results
    ]

    output_path.write_text(
        json.dumps(
            {
                "url": base_url,
                "words": words,
                "results": findings,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    summary = f"ffuf checked {len(words)} candidate path(s) and found {len(findings)} match(es)."
    return ToolExecutionResult(
        tool_name="ffuf_enum",
        success=True,
        summary=summary,
        raw_output=stdout,
        structured_data={"paths": findings, "url": base_url},
        artifact_paths=[str(output_path)],
    )


def _load_results(output_path: Path) -> list[dict]:
    try:
        content = output_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []

    if not content.strip():
        return []

    parsed = json.loads(content)
    if isinstance(parsed, dict):
        return list(parsed.get("results", []))
    return []


def _path_from_url(url: str) -> str:
    if not url:
        return "/"
    without_scheme = url.split("://", 1)[-1]
    if "/" not in without_scheme:
        return "/"
    return "/" + without_scheme.split("/", 1)[1]
