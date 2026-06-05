from __future__ import annotations

import json
import os
import platform
import subprocess

from app.schemas.tool import LinpeasRunnerInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError, trim_output


def _safe_run(cmd: list[str], timeout: int, max_chars: int) -> str:
    """Run a read-only command safely and return trimmed output."""
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return trim_output((completed.stdout or "").strip(), max_chars)
    except FileNotFoundError:
        return f"(command not found: {cmd[0]})"
    except subprocess.TimeoutExpired:
        return "(command timed out)"
    except PermissionError:
        return "(permission denied)"
    except OSError as exc:
        return f"(OS error: {exc})"


def _check_suid_binaries(timeout: int) -> list[str]:
    """Find SUID binaries (find / -perm -4000)."""
    output = _safe_run(["find", "/", "-perm", "-4000", "-type", "f"], timeout, 4096)
    if not output or output.startswith("("):
        return []
    return [line.strip() for line in output.splitlines() if line.strip()][:50]


def _check_sudo_permissions(timeout: int) -> str:
    """Check current user sudo permissions (sudo -l)."""
    output = _safe_run(["sudo", "-n", "-l"], timeout, 4096)
    return output


def _check_writable_system_files(timeout: int) -> list[str]:
    """Check if /etc/passwd and /etc/shadow are writable."""
    writable: list[str] = []
    for path in ["/etc/passwd", "/etc/shadow"]:
        try:
            if os.access(path, os.W_OK):
                writable.append(path)
        except OSError:
            pass
    # Also check /etc/sudoers writability
    for path in ["/etc/sudoers", "/etc/sudoers.d"]:
        try:
            if os.path.isdir(path):
                if os.access(path, os.W_OK):
                    writable.append(path)
            elif os.access(path, os.W_OK):
                writable.append(path)
        except OSError:
            pass
    return writable


def _check_cron_jobs(timeout: int) -> list[str]:
    """Check cron jobs: /etc/crontab, /etc/cron.d/, user crontab."""
    jobs: list[str] = []

    # System crontab
    output = _safe_run(["cat", "/etc/crontab"], timeout, 4096)
    if output and not output.startswith("("):
        for line in output.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                jobs.append(f"/etc/crontab: {line}")

    # /etc/cron.d/
    output = _safe_run(["ls", "/etc/cron.d/"], timeout, 2048)
    if output and not output.startswith("("):
        jobs.append(f"/etc/cron.d/ entries: {output}")

    # User crontab
    output = _safe_run(["crontab", "-l"], timeout, 2048)
    if output and not output.startswith("(") and "no crontab" not in output.lower():
        jobs.append(f"user crontab: {output}")

    return jobs[:30]


def _check_docker_access(timeout: int) -> bool:
    """Check if current user has Docker group membership or socket access."""
    # Check group membership
    output = _safe_run(["groups"], timeout, 2048)
    if "docker" in output.lower():
        return True

    # Check docker socket accessibility
    try:
        if os.access("/var/run/docker.sock", os.R_OK | os.W_OK):
            return True
    except OSError:
        pass

    # Check if docker command works
    output = _safe_run(["docker", "ps"], timeout, 10 * 1000, 2048)
    if output and not output.startswith("(") and "permission denied" not in output.lower():
        return True

    return False


def _check_capabilities(timeout: int) -> list[str]:
    """Check file capabilities using getcap."""
    output = _safe_run(["getcap", "-r", "/"], timeout, 8192)
    if not output or output.startswith("("):
        return []
    return [line.strip() for line in output.splitlines() if line.strip() and "cap_" in line.lower()][:30]


def _check_unmounted_filesystems(timeout: int) -> list[str]:
    """Check unmounted file systems (from /etc/fstab and lsblk)."""
    mounts: list[str] = []

    # Check /etc/fstab for entries not mounted
    output = _safe_run(["cat", "/etc/fstab"], timeout, 2048)
    if output and not output.startswith("("):
        for line in output.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                mounts.append(f"/etc/fstab: {line}")

    # Check lsblk for unmounted partitions
    output = _safe_run(["lsblk", "-o", "NAME,FSTYPE,SIZE,MOUNTPOINT,LABEL"], timeout, 2048)
    if output and not output.startswith("("):
        mounts.append(f"lsblk: {output}")

    return mounts[:20]


def _check_kernel_exploit_hints(timeout: int) -> list[str]:
    """Collect kernel version and architecture as hints."""
    hints: list[str] = []
    output = _safe_run(["uname", "-a"], timeout, 2048)
    if output and not output.startswith("("):
        hints.append(f"kernel: {output}")
    output = _safe_run(["cat", "/etc/os-release"], timeout, 2048)
    if output and not output.startswith("("):
        hints.append(f"os-release: {output}")
    return hints


def execute(params: LinpeasRunnerInput, context: ToolContext) -> ToolExecutionResult:
    target = params.target
    timeout = params.timeout

    # Only run on Linux (this tool checks local system)
    if platform.system() != "Linux":
        raise ToolExecutionError(
            f"linpeas_runner is only supported on Linux systems. "
            f"Current platform: {platform.system()}."
        )

    suid = _check_suid_binaries(timeout)
    sudo_perm = _check_sudo_permissions(timeout)
    writable = _check_writable_system_files(timeout)
    cron_jobs = _check_cron_jobs(timeout)
    docker = _check_docker_access(timeout)
    caps = _check_capabilities(timeout)
    kernel_hints = _check_kernel_exploit_hints(timeout)

    structured: dict = {
        "target": target,
        "suid_binaries": suid,
        "sudo_permissions": sudo_perm,
        "writable_system_files": writable,
        "cron_jobs": cron_jobs,
        "docker_access": docker,
        "capabilities": caps,
        "kernel_hints": kernel_hints,
    }

    findings: list[str] = []
    if suid:
        findings.append(f"{len(suid)} SUID binary(s)")
    if sudo_perm and not sudo_perm.startswith("("):
        findings.append("sudo permissions found")
    if writable:
        findings.append(f"{len(writable)} writable system file(s): {', '.join(writable)}")
    if cron_jobs:
        findings.append(f"{len(cron_jobs)} cron job(s)")
    if docker:
        findings.append("Docker access DETECTED")
    if caps:
        findings.append(f"{len(caps)} capability(s) set")

    if findings:
        summary = f"linpeas_runner on {target}: {'; '.join(findings)}."
    else:
        summary = f"linpeas_runner on {target}: no privilege escalation vectors found."

    artifact_path = context.artifact_dir / "linpeas_runner.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")

    return ToolExecutionResult(
        tool_name="linpeas_runner",
        success=True,
        summary=summary,
        raw_output=json.dumps(structured, indent=2)[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
