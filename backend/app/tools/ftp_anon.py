from __future__ import annotations

import ftplib
import json
import socket

from app.schemas.tool import FtpAnonInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError


ANON_USERS = ("anonymous", "ftp")
ANON_PASSWORDS = ("anonymous@", "ftp@", "guest@", "")


def _try_anon_login(target: str, port: int, timeout: int) -> tuple[bool, str, list[str]]:
    """Attempt anonymous FTP login and return (success, banner, files)."""
    banner = ""
    files: list[str] = []

    for user in ANON_USERS:
        for pwd in ANON_PASSWORDS:
            try:
                ftp = ftplib.FTP()
                ftp.connect(host=target, port=port, timeout=timeout)
                banner = ftp.getwelcome() or ""
                ftp.login(user=user, passwd=pwd)
                try:
                    listing: list[str] = []
                    ftp.dir(listing.append)
                    files = listing
                except ftplib.error_perm:
                    files = []
                ftp.quit()
                return True, banner, files
            except ftplib.error_perm:
                # Login denied, try next credential pair
                try:
                    ftp.quit()
                except Exception:
                    pass
                continue
            except (socket.timeout, OSError, ftplib.all_errors):
                # Connection-level error — no point retrying credential variants
                return False, banner, files

    return False, banner, files


def execute(params: FtpAnonInput, context: ToolContext) -> ToolExecutionResult:
    try:
        anon_enabled, banner, file_list = _try_anon_login(
            params.target, params.port, params.timeout
        )
    except (socket.timeout, OSError) as exc:
        raise ToolExecutionError(
            f"FTP connection to {params.target}:{params.port} failed: {exc}"
        ) from exc

    structured: dict = {
        "anonymous_enabled": anon_enabled,
        "banner": banner,
        "files": file_list,
    }

    if anon_enabled:
        summary = (
            f"Anonymous FTP login SUCCEEDED on {params.target}:{params.port} "
            f"(banner: {banner[:80]}, {len(file_list)} root file(s))."
        )
    else:
        summary = f"Anonymous FTP login FAILED on {params.target}:{params.port}."

    artifact_path = context.artifact_dir / "ftp_anon.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")

    return ToolExecutionResult(
        tool_name="ftp_anon",
        success=True,
        summary=summary,
        raw_output=json.dumps(structured, indent=2)[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
