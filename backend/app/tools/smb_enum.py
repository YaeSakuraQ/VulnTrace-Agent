from __future__ import annotations

import json
import re
import socket
import struct

from app.schemas.tool import SmbEnumInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError, run_command, trim_output


# SMBv2 negotiate header — the first 4 bytes are the NetBIOS session message length
# Followed by SMBv2 header magic "\xfeSMB"
SMB2_NEGOTIATE = (
    b"\x00\x00\x00\xa4"          # NetBIOS session message length (164 bytes)
    b"\xfeSMB"                    # SMB2 protocol magic
    b"\x40\x00"                   # Structure size (64)
    b"\x00\x00"                   # Credit charge
    b"\x00\x00"                   # Status (NTSTATUS success)
    b"\x00"                       # Channel sequence / reserved
    b"\x00"                       # Reserved
    b"\x00\x00"                   # Credit request
    b"\x00\x00\x00\x00"           # Flags
    b"\x00\x00\x00\x00"           # Next command
    b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Message ID
    b"\x00\x00\x00\x00"           # Reserved
    b"\x00\x00\x00\x00"           # Tree ID
    b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Session ID
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
    b"\x24\x00"                   # Structure size (36)
    b"\x02\x00"                   # Dialect count (2)
    b"\x02\x02"                   # SMB 2.0.2 dialect
    b"\x10\x02"                   # SMB 2.1.0 dialect
    b"\x00"                       # Pad / negotiate context count
    b"\x00\x00"                   # Reserved
    b"\x02\x00\x00\x00"           # Capabilities
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # Client GUID
    b"\x00\x00\x00\x00"           # Negotiate context offset / pad
)

# smbclient share listing output: name|type|comment
SHARE_LINE_RE = re.compile(r"^(.+?)\|(.+?)\|(.*)$")


def _parse_negotiate(data: bytes) -> str:
    """Extract SMB dialect version from negotiate response."""
    if len(data) < 10:
        return "unknown"
    # The dialect revision is a 16-bit LE integer at offset 72 of the SMB2 header
    # (after 4-byte NetBIOS header + 64-byte SMB2 header + 36-byte negotiate response)
    # Simpler: look for the SMB2 header magic
    magic_pos = data.find(b"\xfeSMB")
    if magic_pos < 0:
        # SMBv1 response: starts after NetBIOS header
        if len(data) > 4:
            dialect_bytes = data[4:8]
            if dialect_bytes:
                return f"SMBv1 (dialect 0x{dialect_bytes.hex()})"
        return "SMBv1"
    # SMBv2 dialect revision is at offset 72 from the SMB magic
    smb_start = magic_pos
    if len(data) >= smb_start + 74:
        revision = struct.unpack_from("<H", data, smb_start + 72)[0]
        if revision == 0x02FF:
            return "SMB 2.0.2"
        elif revision == 0x0210:
            return "SMB 2.1.0"
        elif revision == 0x0300:
            return "SMB 3.0"
        elif revision == 0x0302:
            return "SMB 3.0.2"
        elif revision == 0x0311:
            return "SMB 3.1.1"
        else:
            return f"SMB2 (revision 0x{revision:04X})"
    return "SMB2 (unknown revision)"


def _smb_negotiate(target: str, port: int, timeout: int) -> str:
    """Send SMB negotiate packet and parse the response version."""
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(SMB2_NEGOTIATE)
            chunks: list[bytes] = []
            while True:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            data = b"".join(chunks)
    except socket.timeout:
        raise ToolExecutionError(f"SMB negotiate timed out for {target}:{port}")
    except OSError as exc:
        raise ToolExecutionError(f"SMB negotiate connection failed for {target}:{port}: {exc}") from exc

    if not data:
        return "no response"
    return _parse_negotiate(data)


def _list_shares_with_smbclient(target: str, port: int, timeout: int) -> list[dict]:
    """Use smbclient -L to enumerate shares."""
    cmd = [
        "smbclient",
        "-L", f"//{target}",
        "-p", str(port),
        "-N",         # no password
        "-g",         # grepable output (key=value)
    ]
    try:
        stdout, stderr, rc = run_command(
            cmd,
            timeout=timeout,
            max_output_chars=8192,
        )
    except ToolExecutionError:
        # smbclient not installed or timed out
        return []

    shares: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("Anonymous") or line.startswith("do_connect"):
            continue
        m = SHARE_LINE_RE.match(line)
        if m:
            shares.append({
                "name": m.group(1).strip(),
                "type": m.group(2).strip(),
                "comment": m.group(3).strip(),
            })
        elif "|" in line:
            parts = line.split("|", 2)
            shares.append({
                "name": parts[0].strip(),
                "type": parts[1].strip() if len(parts) > 1 else "",
                "comment": parts[2].strip() if len(parts) > 2 else "",
            })
    return shares


def execute(params: SmbEnumInput, context: ToolContext) -> ToolExecutionResult:
    structured: dict = {"smb_version": "", "shares": []}

    # 1) Determine SMB version via negotiate protocol
    try:
        structured["smb_version"] = _smb_negotiate(params.target, params.port, params.timeout)
    except ToolExecutionError as exc:
        structured["smb_version"] = f"negotiate failed: {exc}"

    # 2) Enumerate shares via smbclient
    structured["shares"] = _list_shares_with_smbclient(params.target, params.port, params.timeout)

    if structured["shares"]:
        share_names = [s["name"] for s in structured["shares"]]
        summary = (
            f"SMB {structured['smb_version']} on {params.target}:{params.port}; "
            f"{len(structured['shares'])} share(s): {', '.join(share_names[:10])}"
        )
    else:
        summary = f"SMB {structured['smb_version']} on {params.target}:{params.port}; no shares enumerated."

    artifact_path = context.artifact_dir / "smb_enum.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")

    return ToolExecutionResult(
        tool_name="smb_enum",
        success=True,
        summary=summary,
        raw_output=json.dumps(structured, indent=2)[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
