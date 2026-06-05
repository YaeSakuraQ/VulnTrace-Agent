from __future__ import annotations

import json
import shutil

from app.schemas.tool import ImpacketWrapperInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError, run_command


IMPACKET_TOOLS = [
    "impacket-secretsdump",
    "impacket-smbclient",
    "impacket-wmiexec",
]


def _check_impacket_tool(tool_name: str) -> bool:
    """Check if the specified impacket tool binary exists on PATH."""
    if shutil.which(tool_name):
        return True
    # Try alternate naming conventions
    alt_names = [
        tool_name + ".py",
        tool_name.replace("impacket-", ""),
        tool_name.replace("impacket-", "impacket-") + ".py",
    ]
    for alt in alt_names:
        if shutil.which(alt):
            return True
    return False


def _build_args(params: ImpacketWrapperInput) -> list[str]:
    """Build the argument list for the impacket tool."""
    args = [params.tool]

    if params.tool == "impacket-secretsdump":
        # secretsdump needs credentials and a target
        if params.domain:
            cred = f"{params.domain}/{params.username}"
        else:
            cred = params.username

        if params.nt_hash:
            full_cred = f"{cred}:{params.nt_hash}"
        elif params.password:
            full_cred = f"{cred}:{params.password}"
        else:
            full_cred = cred

        args.append(f"{full_cred}@{params.target}")

    elif params.tool == "impacket-smbclient":
        if params.domain:
            cred = f"{params.domain}/{params.username}"
        else:
            cred = params.username

        if params.nt_hash:
            auth = f"-hashes :{params.nt_hash}"
            args.extend([auth, f"{cred}@{params.target}"])
        elif params.password:
            args.extend([f"{cred}:{params.password}@{params.target}"])
        else:
            args.append(f"//{params.target}")

    elif params.tool == "impacket-wmiexec":
        if params.domain:
            cred = f"{params.domain}/{params.username}"
        else:
            cred = params.username

        if params.nt_hash:
            full_cred = f"{cred}@{params.target}"
            args.extend(["-hashes", f":{params.nt_hash}", full_cred])
        elif params.password:
            args.append(f"{cred}:{params.password}@{params.target}")
        else:
            args.append(f"{cred}@{params.target}")

        if params.command:
            args.append(params.command)
        else:
            args.append("whoami")

    return args


def execute(params: ImpacketWrapperInput, context: ToolContext) -> ToolExecutionResult:
    if not _check_impacket_tool(params.tool):
        raise ToolExecutionError(
            f"Impacket tool '{params.tool}' not found on system PATH. "
            f"Install impacket-scripts (apt install impacket-scripts) or "
            f"pip install impacket. Available tools: {', '.join(IMPACKET_TOOLS)}."
        )

    # Validate credential requirements
    if params.tool in ("impacket-secretsdump", "impacket-wmiexec"):
        if not params.username:
            raise ToolExecutionError(
                f"Tool '{params.tool}' requires a username for authentication."
            )

    args = _build_args(params)

    try:
        stdout, stderr, rc = run_command(
            args,
            timeout=params.timeout,
            max_output_chars=context.max_output_chars,
        )
    except ToolExecutionError as exc:
        if "not found" in str(exc).lower():
            raise ToolExecutionError(
                f"Impacket tool '{params.tool}' execution failed. "
                f"Please verify impacket-scripts is installed."
            ) from exc
        raise

    combined_output = stdout + "\n" + stderr

    # Summary: take first meaningful lines of output
    output_lines = [l for l in combined_output.splitlines() if l.strip()]
    output_summary = "\n".join(output_lines[:20]) if output_lines else "(no output)"

    structured: dict = {
        "tool": params.tool,
        "target": params.target,
        "output_summary": output_summary[: context.max_output_chars],
    }

    # Determine success from stdout content
    has_output = bool(stdout.strip())
    error_keywords = ["STATUS_LOGON_FAILURE", "STATUS_ACCESS_DENIED", "Error", "error:"]
    has_errors = any(kw.lower() in combined_output.lower() for kw in error_keywords)

    if has_output and not has_errors:
        line_count = len(output_lines)
        summary = (
            f"impacket {params.tool} on {params.target}: "
            f"executed successfully ({line_count} output line(s))."
        )
    elif has_errors:
        first_error = ""
        for line in output_lines:
            for kw in error_keywords:
                if kw.lower() in line.lower():
                    first_error = line[:120]
                    break
            if first_error:
                break
        summary = (
            f"impacket {params.tool} on {params.target}: "
            f"error encountered — {first_error}"
        )
    else:
        summary = (
            f"impacket {params.tool} on {params.target}: "
            f"executed with no output."
        )

    artifact_path = context.artifact_dir / "impacket_wrapper.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")

    return ToolExecutionResult(
        tool_name="impacket_wrapper",
        success=True,
        summary=summary,
        raw_output=combined_output[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
