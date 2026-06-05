from __future__ import annotations

import json
import re

from app.schemas.tool import ToolExecutionResult, WhatwebProbeInput
from app.tools.base import ToolContext, ToolExecutionError, run_command


# Regex to parse whatweb plain-text output lines like:
# "http://example.com [Apache/2.4.41][PHP/7.4.3][WordPress/5.7]"
WHATWEB_URL_RE = re.compile(r"^(\S+)")
PLUGIN_RE = re.compile(r"\[([^\]]+)\]")


def _check_whatweb_available() -> bool:
    try:
        stdout, _, rc = run_command(["whatweb", "--version"], timeout=10, max_output_chars=2048)
        return rc == 0 and bool(stdout.strip())
    except ToolExecutionError:
        return False


def _run_whatweb(url: str, timeout: int, max_output_chars: int) -> str:
    args = [
        "whatweb",
        "-a", "3",
        url,
    ]
    stdout, stderr, rc = run_command(args, timeout=timeout, max_output_chars=max_output_chars)
    if rc != 0 and not stdout.strip():
        raise ToolExecutionError(stderr or "whatweb returned non-zero exit with no output.")
    return stdout


def _parse_whatweb_output(raw_output: str) -> list[dict]:
    """Parse whatweb plain-text output into structured plugin info."""
    plugins: list[dict] = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Extract all [Plugin] entries on this line
        for m in PLUGIN_RE.finditer(line):
            plugin_str = m.group(1)  # e.g. "Apache/2.4.41"
            name, _, version = plugin_str.partition("/")
            confidence = 100  # default for matched
            # Check for version in the plugin str
            if version:
                name = name.strip()
                version = version.strip()
            else:
                name = name.strip()
                version = ""

            # Skip entries that look like purely numeric or empty
            if not name:
                continue

            plugins.append({
                "name": name,
                "version": version,
                "confidence": confidence,
            })

    return plugins


def execute(params: WhatwebProbeInput, context: ToolContext) -> ToolExecutionResult:
    url = f"{params.scheme}://{params.target}:{params.port}"

    if not _check_whatweb_available():
        raise ToolExecutionError(
            "whatweb binary not found. Install whatweb (apt install whatweb) "
            "to enable web technology fingerprinting."
        )

    raw_output = _run_whatweb(url, params.timeout, context.max_output_chars)
    plugins = _parse_whatweb_output(raw_output)

    structured: dict = {
        "url": url,
        "plugins": plugins,
    }

    if plugins:
        plugin_names = [p["name"] for p in plugins if p["name"]]
        summary = (
            f"whatweb identified {len(plugins)} technology/plugin(s) on {url}: "
            f"{', '.join(plugin_names[:10])}"
        )
    else:
        summary = f"whatweb ran on {url} but found no identifiable technologies."

    artifact_path = context.artifact_dir / "whatweb_probe.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")

    return ToolExecutionResult(
        tool_name="whatweb_probe",
        success=True,
        summary=summary,
        raw_output=raw_output[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
