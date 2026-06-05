from __future__ import annotations

import json
import re

from app.schemas.tool import Enum4linuxWrapperInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError, run_command


# Regex patterns to parse enum4linux output
USER_RE = re.compile(r"^\s*\[.*\]\s*(\S+)\s*$")  # catch-all for user lines
SHARE_RE = re.compile(r"^\s*(\S+)\s+(Disk|Printer|IPC|Unknown)\s", re.IGNORECASE)
OS_RE = re.compile(r"OS\s*:\s*(.+?)(?:\[.+?\])?\s*$", re.IGNORECASE)
OS_SECTION_RE = re.compile(r"\[\[\+\]\](?:\s*Enumerating|\s*Getting)\s+OS\b", re.IGNORECASE)
PWD_POLICY_RE = re.compile(r"Password\s+information|\bmin\b.*\blen|Minimum password", re.IGNORECASE)

# Parse net view / SAMR-style user output
# e.g. "user:[Administrator] rid:[0x1f4]"
ENUM4_USER_RE = re.compile(r"user:\[(\S+)\]\s*rid:", re.IGNORECASE)


def _check_enum4linux_available() -> bool:
    try:
        stdout, _, rc = run_command(
            ["enum4linux", "--help"],
            timeout=10,
            max_output_chars=2048,
        )
        if rc == 0 and stdout.strip():
            return True
    except ToolExecutionError:
        pass
    # Check for the Perl script variant
    try:
        stdout, _, rc = run_command(
            ["enum4linux.pl", "--help"],
            timeout=10,
            max_output_chars=2048,
        )
        binary = "enum4linux.pl" if (rc == 0 and stdout.strip()) else None
        return binary is not None
    except ToolExecutionError:
        return False
    return False


def _run_enum4linux(target: str, timeout: int, max_output_chars: int) -> str:
    """Run enum4linux -a and return combined stdout+stderr text."""
    # Try both binary names: python (Kali 2022+) or perl (older)
    args = [
        "enum4linux", "-a", target,
    ]
    try:
        stdout, stderr, rc = run_command(args, timeout=timeout, max_output_chars=max_output_chars)
    except ToolExecutionError as exc:
        if "not found" in str(exc).lower():
            # Try the Perl variant
            args_pl = ["enum4linux.pl", "-a", target]
            stdout, stderr, rc = run_command(args_pl, timeout=timeout, max_output_chars=max_output_chars)
        else:
            raise

    combined = stdout + "\n" + stderr
    if rc != 0 and not combined.strip():
        raise ToolExecutionError("enum4linux returned non-zero exit with no output.")
    return combined


def _parse_users(output: str) -> list[str]:
    """Extract user account names from enum4linux output."""
    users: list[str] = []
    in_user_section = False
    for line in output.splitlines():
        line_stripped = line.strip()
        # Detect user enumeration section
        if "Getting user list" in line_stripped or "Enumerating users" in line_stripped:
            in_user_section = True
            continue
        if in_user_section and ("Getting" in line_stripped or "Enumerating" in line_stripped):
            in_user_section = False
            continue

        if in_user_section or "user:" in line_stripped:
            m = ENUM4_USER_RE.search(line_stripped)
            if m:
                user = m.group(1)
                if user not in users:
                    users.append(user)
            # Also look for SAMR / RID cycler output patterns
            elif "[" in line_stripped and "rid:" not in line_stripped:
                # Fallback for other user output formats
                for part in line_stripped.split():
                    if part.startswith("[") and part.endswith("]") and "\\" not in part:
                        name = part.strip("[]")
                        if name and name not in users and len(name) > 1:
                            users.append(name)

    # Deduplicate
    return sorted(set(users))


def _parse_shares(output: str) -> list[str]:
    """Extract share names from enum4linux output."""
    shares: list[str] = []
    for line in output.splitlines():
        line_stripped = line.strip()
        # Match the share listing format
        m = SHARE_RE.search(line_stripped)
        if m:
            share_name = m.group(1)
            if share_name and share_name not in shares:
                shares.append(share_name)
    return sorted(shares)


def _parse_os_info(output: str) -> str:
    """Extract OS information from enum4linux output."""
    lines = output.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        # Look for OS information section
        m = OS_RE.search(stripped)
        if m:
            return m.group(1).strip()
        if "OS:" in stripped:
            # Capture next line or rest of the line
            after_os = stripped.split("OS:", 1)[-1].strip()
            if after_os:
                return after_os
            # Try next few lines
            for j in range(i + 1, min(i + 5, len(lines))):
                if lines[j].strip():
                    return lines[j].strip()
    return ""


def _parse_password_policy(output: str) -> str:
    """Extract password policy information from enum4linux output."""
    in_policy_section = False
    policy_lines: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if "Password information" in stripped or "Getting password policy" in stripped:
            in_policy_section = True
            continue
        if in_policy_section:
            if (stripped.startswith("[+]") or stripped.startswith("[-]") or
                    ("Enumerating" in stripped)):
                in_policy_section = False
                continue
            if stripped:
                policy_lines.append(stripped)
    return "; ".join(policy_lines) if policy_lines else ""


def execute(params: Enum4linuxWrapperInput, context: ToolContext) -> ToolExecutionResult:
    if not _check_enum4linux_available():
        raise ToolExecutionError(
            "enum4linux binary not found. Install enum4linux (apt install enum4linux) "
            "to enable SMB/NetBIOS deep enumeration."
        )

    raw_output = _run_enum4linux(params.target, params.timeout, context.max_output_chars)
    users = _parse_users(raw_output)
    shares = _parse_shares(raw_output)
    os_info = _parse_os_info(raw_output)
    password_policy = _parse_password_policy(raw_output)

    structured: dict = {
        "target": params.target,
        "users": users,
        "shares": shares,
        "os_info": os_info,
        "password_policy": password_policy,
    }

    parts: list[str] = []
    if users:
        parts.append(f"{len(users)} user(s)")
    if shares:
        parts.append(f"{len(shares)} share(s)")
    if os_info:
        parts.append(f"OS: {os_info[:80]}")
    if password_policy:
        parts.append(f"password policy extracted")

    if parts:
        summary = f"enum4linux on {params.target}: {', '.join(parts)}."
    else:
        summary = f"enum4linux ran on {params.target} but extracted no data."

    artifact_path = context.artifact_dir / "enum4linux_wrapper.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")

    return ToolExecutionResult(
        tool_name="enum4linux_wrapper",
        success=True,
        summary=summary,
        raw_output=raw_output[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
