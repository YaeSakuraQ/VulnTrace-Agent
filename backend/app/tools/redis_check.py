from __future__ import annotations

import json
import re
import socket

from app.schemas.tool import RedisCheckInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError


DANGEROUS_COMMANDS = [
    "CONFIG", "FLUSHALL", "FLUSHDB", "KEYS", "DEBUG",
    "SAVE", "BGSAVE", "SHUTDOWN", "SLAVEOF", "REPLICAOF",
    "MODULE", "EVAL", "SCRIPT",
]


def _send_command(sock: socket.socket, command: str) -> str:
    """Send a Redis command and return the raw response string."""
    parts = command.strip().split()
    args = [str(part) for part in parts]
    msg = f"*{len(args)}\r\n"
    for arg in args:
        msg += f"${len(arg)}\r\n{arg}\r\n"
    sock.sendall(msg.encode("latin1"))

    # Read response
    first_char = sock.recv(1)
    if not first_char:
        return ""
    response = [first_char]

    if first_char == b"+":
        # Simple string: +OK\r\n
        response.append(_read_line(sock))
    elif first_char == b"-":
        # Error: -ERR ...\r\n
        response.append(_read_line(sock))
    elif first_char == b":":
        # Integer
        response.append(_read_line(sock))
    elif first_char == b"$":
        # Bulk string
        bulk_header = _read_line(sock)
        response.append(bulk_header)
        try:
            length = int(bulk_header.strip())
            if length >= 0:
                response.append(sock.recv(length + 2))  # +2 for \r\n
            # length == -1 means nil
        except (ValueError, AttributeError):
            pass
    elif first_char == b"*":
        # Array
        array_header = _read_line(sock).strip()
        response.append(array_header)
        try:
            count = int(array_header)
            for _ in range(min(count, 200)):  # Limit to prevent runaway reads
                resp = _read_response(sock)
                if resp:
                    response.append(resp.encode("latin1"))
                else:
                    break
        except (ValueError, AttributeError):
            pass

    return b"".join(response).decode("latin1", errors="replace")


def _read_line(sock: socket.socket) -> bytes:
    """Read a CRLF-terminated line from the socket."""
    buf = b""
    while True:
        byte = sock.recv(1)
        if not byte:
            break
        buf += byte
        if buf.endswith(b"\r\n"):
            break
    return buf


def _read_response(sock: socket.socket) -> str:
    """Read a full Redis response recursively."""
    first = sock.recv(1)
    if not first:
        return ""
    result = [first]
    if first == b"+" or first == b"-" or first == b":":
        result.append(_read_line(sock))
    elif first == b"$":
        result.append(_read_line(sock))
        try:
            length = int(result[1].strip())
            if length >= 0:
                result.append(sock.recv(length + 2))
        except (ValueError, AttributeError):
            pass
    elif first == b"*":
        result.append(_read_line(sock))
        try:
            count = int(result[1].strip())
            for _ in range(min(count, 100)):
                inner = _read_response(sock)
                if inner:
                    result.append(inner.encode("latin1"))
        except (ValueError, AttributeError):
            pass
    return b"".join(result).decode("latin1", errors="replace")


def execute(params: RedisCheckInput, context: ToolContext) -> ToolExecutionResult:
    structured: dict = {"unauthorized": False, "info": "", "dangerous_commands": []}

    try:
        with socket.create_connection((params.target, params.port), timeout=params.timeout) as sock:
            sock.settimeout(params.timeout)

            # Step 1: PING
            ping_resp = _send_command(sock, "PING")
            if "+PONG" not in ping_resp:
                raise ToolExecutionError(
                    f"Redis did not respond with PONG on {params.target}:{params.port}: {ping_resp.strip()}"
                )
            structured["unauthorized"] = True

            # Step 2: INFO
            try:
                info_resp = _send_command(sock, "INFO")
                structured["info"] = info_resp[:2000]
            except (socket.timeout, OSError):
                structured["info"] = "(INFO timed out)"

            # Step 3: CONFIG GET *
            try:
                config_resp = _send_command(sock, "CONFIG GET *")
                # Check which dangerous commands are present in CONFIG
                config_lower = config_resp.lower()
                for cmd in DANGEROUS_COMMANDS:
                    if cmd.lower() in config_lower:
                        structured["dangerous_commands"].append(cmd)
            except (socket.timeout, OSError):
                pass

    except socket.timeout:
        raise ToolExecutionError(
            f"Redis connection timed out for {params.target}:{params.port}"
        )
    except OSError as exc:
        raise ToolExecutionError(
            f"Redis connection failed for {params.target}:{params.port}: {exc}"
        ) from exc

    if structured["unauthorized"]:
        summary = f"Redis UNAUTHORIZED on {params.target}:{params.port}"
    else:
        summary = f"Redis port open on {params.target}:{params.port} but not unauthorized."

    if structured["dangerous_commands"]:
        summary += f" Dangerous config keys: {', '.join(structured['dangerous_commands'])}"

    artifact_path = context.artifact_dir / "redis_check.json"
    artifact_path.write_text(json.dumps(structured, indent=2, default=str), encoding="utf-8")

    return ToolExecutionResult(
        tool_name="redis_check",
        success=True,
        summary=summary,
        raw_output=json.dumps(structured, indent=2, default=str)[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
