from __future__ import annotations

import json
import re

from app.schemas.tool import CommixProbeInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError, run_command


def _check_commix_available() -> bool:
    try:
        stdout, _, rc = run_command(
            ["commix", "--version"],
            timeout=10,
            max_output_chars=2048,
        )
        return rc == 0 and bool(stdout.strip())
    except ToolExecutionError:
        return False


def _run_commix(url: str, timeout: int, max_output_chars: int) -> tuple[str, str, int]:
    """Run commix in batch mode for command injection detection."""
    args = [
        "commix",
        "--url", url,
        "--batch",
        "--flush-session",
    ]
    return run_command(args, timeout=timeout, max_output_chars=max_output_chars)


# Patterns to detect successful command injection in commix output
VULN_RE = re.compile(
    r"(?:\[\+\].*?(?:vulnerable|successful)|"
    r"command injection.*?(?:found|detected|vulnerable)|"
    r"the target is vulnerable)",
    re.IGNORECASE,
)

# Payload pattern: e.g. "[+] The payload is: ..."
PAYLOAD_RE = re.compile(r"payload(?:\s+is)?\s*:\s*(.+?)(?:$|\n)", re.IGNORECASE)

# Output pattern: command output in commix results
OUTPUT_RE = re.compile(
    r"(?:\[\*\].*?(?:output|response|result)|"
    r"retrieved.*?:\s*(.+))",
    re.IGNORECASE,
)


def _parse_commix_output(stdout: str) -> tuple[bool, str, str]:
    """Parse commix output for vulnerability, payload, and command output."""
    vulnerable = bool(VULN_RE.search(stdout))

    payload = ""
    m = PAYLOAD_RE.search(stdout)
    if m:
        payload = m.group(1).strip()

    output_str = ""
    for line in stdout.splitlines():
        m = OUTPUT_RE.search(line)
        if m and m.group(1):
            output_str = m.group(1).strip()
            break

    # If no structured output found, capture a snippet of the command execution section
    if vulnerable and not output_str:
        for i, line in enumerate(stdout.splitlines()):
            if i > 0 and ("[+]" in line or "[*]" in line) and len(line) < 500:
                if payload.lower() not in line.lower():
                    output_str = line.strip()
                    break

    return vulnerable, payload, output_str


def execute(params: CommixProbeInput, context: ToolContext) -> ToolExecutionResult:
    if not _check_commix_available():
        raise ToolExecutionError(
            "commix binary not found. Install commix (apt install commix) "
            "to enable command injection detection."
        )

    stdout, stderr, rc = _run_commix(
        params.target, params.timeout, context.max_output_chars
    )

    vulnerable, payload, output_str = _parse_commix_output(stdout)

    structured: dict = {
        "url": params.target,
        "vulnerable": vulnerable,
        "payload": payload,
        "output": output_str,
    }

    if vulnerable:
        pay_str = f" payload: {payload[:120]}" if payload else ""
        out_str = f" output: {output_str[:200]}" if output_str else ""
        summary = f"commix: {params.target} is VULNERABLE to command injection.{pay_str}{out_str}"
    else:
        summary = f"commix: {params.target} does NOT appear vulnerable to command injection."

    artifact_path = context.artifact_dir / "commix_probe.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")

    return ToolExecutionResult(
        tool_name="commix_probe",
        success=True,
        summary=summary,
        raw_output=stdout[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
