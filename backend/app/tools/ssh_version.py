from __future__ import annotations

import json
import re
import socket
import subprocess

from app.schemas.tool import SshVersionInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError, trim_output


BANNER_RE = re.compile(r"^SSH-\d+\.\d+-(\S+)", re.IGNORECASE)
HOST_KEY_RE = re.compile(r"debug1: kex: host key algorithm:\s*(\S+)", re.IGNORECASE)


def _fetch_via_socket(target: str, port: int, timeout: int) -> str:
    """Read the SSH banner directly from the socket."""
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(256).decode("latin1", errors="replace").strip()
    except socket.timeout:
        raise ToolExecutionError(f"SSH banner read timed out after {timeout}s for {target}:{port}")
    except OSError as exc:
        raise ToolExecutionError(f"SSH socket connection failed for {target}:{port}: {exc}") from exc

    if not banner:
        raise ToolExecutionError(f"No SSH banner received from {target}:{port}")
    return banner


def _fetch_via_ssh_command(target: str, port: int, timeout: int) -> tuple[str, str]:
    """Use ssh -v to obtain the banner and host key algorithms."""
    cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={timeout}",
        "-v",
        "-p", str(port),
        target,
        "exit",
    ]
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
    except FileNotFoundError:
        raise ToolExecutionError("ssh client binary not found on system")
    except subprocess.TimeoutExpired as exc:
        partial = (exc.stderr or "") + (exc.stdout or "")
        return (trim_output(partial or "", 4096), "")
    stderr = completed.stderr or ""
    stdout = completed.stdout or ""
    return trim_output(stderr, 4096), trim_output(stdout, 4096)


def _parse_banner(raw_banner: str) -> dict:
    """Extract version information from an SSH banner string."""
    match = BANNER_RE.match(raw_banner)
    version = match.group(1) if match else ""
    return {"banner": raw_banner, "version": version}


def _extract_host_key_algorithms(ssh_output: str) -> list[str]:
    """Parse ssh -v debug output for host key algorithms."""
    algorithms: list[str] = []
    for line in ssh_output.splitlines():
        m = HOST_KEY_RE.search(line)
        if m:
            algorithms.append(m.group(1))
    return sorted(set(algorithms))


def execute(params: SshVersionInput, context: ToolContext) -> ToolExecutionResult:
    structured: dict = {"banner": "", "version": "", "host_key_algorithms": []}

    # 1) Try direct socket banner grab first (fast and quiet)
    try:
        raw_banner = _fetch_via_socket(params.target, params.port, params.timeout)
        banner_info = _parse_banner(raw_banner)
        structured.update(banner_info)
    except ToolExecutionError:
        raw_banner = ""
        structured["banner"] = "(socket read failed)"

    # 2) Always try the ssh -v method to get host key algorithms
    try:
        ssh_stderr, ssh_stdout = _fetch_via_ssh_command(params.target, params.port, params.timeout)
        if not raw_banner:
            # Fallback banner extraction from ssh output
            for line in ssh_stderr.splitlines():
                line = line.strip()
                if line.lower().startswith("ssh-"):
                    banner_match = BANNER_RE.match(line)
                    if banner_match:
                        structured["banner"] = line
                        structured["version"] = banner_match.group(1)
                        break
        structured["host_key_algorithms"] = _extract_host_key_algorithms(ssh_stderr)
    except ToolExecutionError:
        pass

    # Build summary
    if structured["version"]:
        summary = f"SSH service {structured['version']} on {params.target}:{params.port}."
    elif structured["banner"]:
        summary = f"SSH banner received from {params.target}:{params.port} (unparseable)."
    else:
        summary = f"SSH port open on {params.target}:{params.port} but no banner retrieved."

    if structured["host_key_algorithms"]:
        summary += f" {len(structured['host_key_algorithms'])} host key algorithm(s)."

    artifact_path = context.artifact_dir / "ssh_version.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")

    return ToolExecutionResult(
        tool_name="ssh_version",
        success=True,
        summary=summary,
        raw_output=json.dumps(structured, indent=2)[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
