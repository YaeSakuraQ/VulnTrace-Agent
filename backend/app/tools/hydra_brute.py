from __future__ import annotations

import json
import re

from app.schemas.tool import HydraBruteInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError, run_command

# Hard-coded top 20 weak passwords (kept minimal intentionally)
# The tool only allows single user+password attempts, not list-based brute force.
TOP_20_WEAK_PASSWORDS = [
    "admin", "password", "123456", "12345678", "qwerty",
    "abc123", "monkey", "1234567", "letmein", "trustno1",
    "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "shadow", "123123", "654321",
]

DEFAULT_PORTS = {
    "ssh": 22,
    "ftp": 21,
    "mysql": 3306,
    "postgres": 5432,
    "rdp": 3389,
}


def _resolve_port(params: HydraBruteInput) -> int:
    """Resolve port: user-specified or protocol default."""
    if params.port != 22 or params.protocol != "ssh":
        # If user explicitly set port, use it; otherwise use default for protocol
        if params.port == 22 and params.protocol != "ssh":
            return DEFAULT_PORTS.get(params.protocol, params.port)
        return params.port
    return DEFAULT_PORTS.get(params.protocol, 22)


def _check_hydra_available() -> bool:
    try:
        stdout, _, rc = run_command(
            ["hydra", "-h"],
            timeout=10,
            max_output_chars=2048,
        )
        return rc == 0 and bool(stdout.strip())
    except ToolExecutionError:
        return False


def _run_hydra_single(
    target: str,
    protocol: str,
    port: int,
    username: str,
    password: str,
    timeout: int,
    max_output_chars: int,
) -> tuple[str, str, int]:
    """Run hydra with a single username/password (NOT a password file)."""
    args = [
        "hydra",
        "-l", username,
        "-p", password,
        "-s", str(port),
        "-t", "1",          # single task
        "-w", str(min(timeout, 30)),  # max wait time per response
        "-f",               # exit after first found
        "-V",               # verbose (show each attempt)
        f"{protocol}://{target}",
    ]
    return run_command(args, timeout=timeout, max_output_chars=max_output_chars)


# Hydra success pattern: e.g. "[22][ssh] host: 192.168.1.1   login: root   password: toor"
HYDRA_SUCCESS_RE = re.compile(
    r"\[\d+\]\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)",
    re.IGNORECASE,
)

# Hydra attempt count pattern: "[ATTEMPT] target ..."
HYDRA_ATTEMPT_RE = re.compile(r"\[ATTEMPT\]", re.IGNORECASE)


def _parse_hydra_output(stdout: str, stderr: str, username: str, password: str) -> tuple[int, list[dict]]:
    """Parse hydra output for success/failure and attempt count."""
    combined = stdout + "\n" + stderr
    found: list[dict] = []

    for line in combined.splitlines():
        m = HYDRA_SUCCESS_RE.search(line)
        if m:
            found.append({
                "username": m.group(3),
                "password": m.group(4),
            })

    # Count attempts
    attempts = 1
    attempt_count = len(HYDRA_ATTEMPT_RE.findall(combined))
    if attempt_count > 0:
        attempts = attempt_count

    return attempts, found


def execute(params: HydraBruteInput, context: ToolContext) -> ToolExecutionResult:
    if not _check_hydra_available():
        raise ToolExecutionError(
            "hydra binary not found. Install hydra (apt install hydra) "
            "to enable brute-force testing."
        )

    if not params.username.strip() or not params.password.strip():
        raise ToolExecutionError("Both username and password are required for hydra_brute.")

    port = _resolve_port(params)

    stdout, stderr, rc = _run_hydra_single(
        target=params.target,
        protocol=params.protocol,
        port=port,
        username=params.username,
        password=params.password,
        timeout=params.timeout,
        max_output_chars=context.max_output_chars,
    )

    attempts, found = _parse_hydra_output(stdout, stderr, params.username, params.password)

    structured: dict = {
        "target": f"{params.target}:{port}",
        "protocol": params.protocol,
        "attempts": attempts,
        "found": found,
    }

    if found:
        cred_str = ", ".join(f"{c['username']}:{c['password']}" for c in found)
        summary = (
            f"hydra {params.protocol} on {params.target}:{port} — "
            f"FOUND credential(s): {cred_str} in {attempts} attempt(s)."
        )
    else:
        summary = (
            f"hydra {params.protocol} on {params.target}:{port} — "
            f"{attempts} attempt(s), no credentials found."
        )

    artifact_path = context.artifact_dir / "hydra_brute.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")

    return ToolExecutionResult(
        tool_name="hydra_brute",
        success=True,
        summary=summary,
        raw_output=stdout[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
