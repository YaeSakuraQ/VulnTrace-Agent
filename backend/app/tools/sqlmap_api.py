from __future__ import annotations

import json
import re

from app.schemas.tool import SqlmapApiInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError, run_command

# sqlmap uses --dbs to list databases; this is the detection-only mode.
# Explicitly banned: --os-shell, --os-cmd, --os-pwn, --file-read, --file-write, --reg-read

BANNED_FLAGS = [
    "--os-shell", "--os-cmd", "--os-pwn", "--os-bof",
    "--file-read", "--file-write", "--file-dest",
    "--reg-read", "--reg-add", "--reg-del",
    "--priv-esc", "--sql-shell",
]


def _check_sqlmap_available() -> bool:
    try:
        stdout, _, rc = run_command(
            ["sqlmap", "--version"],
            timeout=10,
            max_output_chars=2048,
        )
        return rc == 0 and bool(stdout.strip())
    except ToolExecutionError:
        return False


def _sanitize_target(target: str) -> str:
    """Ensure the target URL does not contain dangerous flags."""
    lowered = target.lower()
    for flag in BANNED_FLAGS:
        if flag in lowered:
            raise ToolExecutionError(
                f"Dangerous sqlmap flag detected in target URL: {flag}. "
                f"sqlmap_api is restricted to detection-only mode."
            )
    return target


def _run_sqlmap_detect(url: str, timeout: int, max_output_chars: int) -> tuple[str, str, int]:
    """Run sqlmap in safe detection mode: --batch --level=1 --risk=1 --smart --dbs."""
    args = [
        "sqlmap",
        "-u", url,
        "--batch",          # non-interactive
        "--level=1",        # minimal test level
        "--risk=1",         # minimal risk
        "--smart",          # only test positive heuristic params
        "--dbs",            # list databases (detection only, stops after enum)
        "--threads=1",      # single threaded
        "--timeout", "30",  # per-request timeout
    ]
    return run_command(args, timeout=timeout, max_output_chars=max_output_chars)


# Regex to parse sqlmap database output: e.g. "[*] information_schema"
DB_LIST_RE = re.compile(r"\[\*\]\s+(\S+)")

# Regex to detect vulnerable result: "[INFO] the back-end DBMS is" or "[CRITICAL]"
VULN_RE = re.compile(
    r"(?:\[(?:CRITICAL|WARNING)\].*?(?:vulnerable|injectable|identified the following injection)|"
    r"the back-end DBMS is|"
    r"sqlmap identified the following injection point)",
    re.IGNORECASE,
)

# Technique extraction: e.g. "Type: boolean-based blind" or "[INFO] testing 'Boolean-based blind'"
TECHNIQUE_RE = re.compile(
    r"(?:Type:|testing\s+')\s*(.+?)(?:$|\s*->|')",
    re.IGNORECASE,
)


def _parse_sqlmap_output(stdout: str) -> tuple[bool, list[str], str]:
    """Parse sqlmap output for vulnerability status, databases, and technique."""
    vulnerable = bool(VULN_RE.search(stdout))

    dbs: list[str] = []
    for line in stdout.splitlines():
        m = DB_LIST_RE.search(line)
        if m:
            db_name = m.group(1)
            # Skip informational lines that start with [*] but aren't DB names
            if db_name not in ("information_schema",) or "available databases" not in line:
                if not any(kw in line.lower() for kw in ("starting", "ending", "retrieved", "fetching", "resuming")):
                    dbs.append(db_name)

    # Deduplicate
    dbs = sorted(set(dbs))

    technique = ""
    for line in stdout.splitlines():
        m = TECHNIQUE_RE.search(line)
        if m:
            technique = m.group(1).strip()
            break

    return vulnerable, dbs, technique


def execute(params: SqlmapApiInput, context: ToolContext) -> ToolExecutionResult:
    if not _check_sqlmap_available():
        raise ToolExecutionError(
            "sqlmap binary not found. Install sqlmap (apt install sqlmap) "
            "to enable SQL injection detection."
        )

    url = _sanitize_target(params.target)

    stdout, stderr, rc = _run_sqlmap_detect(url, params.timeout, context.max_output_chars)

    vulnerable, dbs, technique = _parse_sqlmap_output(stdout)

    structured: dict = {
        "url": url,
        "vulnerable": vulnerable,
        "dbs": dbs,
        "technique": technique,
    }

    if vulnerable:
        db_str = f", {len(dbs)} database(s) found: {', '.join(dbs[:10])}" if dbs else ""
        tech_str = f" (technique: {technique})" if technique else ""
        summary = f"sqlmap: {url} is VULNERABLE to SQL injection{tech_str}{db_str}."
    else:
        summary = f"sqlmap: {url} does NOT appear vulnerable to SQL injection."

    artifact_path = context.artifact_dir / "sqlmap_api.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")

    return ToolExecutionResult(
        tool_name="sqlmap_api",
        success=True,
        summary=summary,
        raw_output=stdout[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
