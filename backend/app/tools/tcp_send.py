from __future__ import annotations

import json
import socket

from app.schemas.tool import TcpSendInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError


def execute(params: TcpSendInput, context: ToolContext) -> ToolExecutionResult:
    try:
        payload = params.payload.encode(params.encoding, errors="replace")
    except LookupError as exc:
        raise ToolExecutionError(f"Unsupported encoding {params.encoding}") from exc

    try:
        with socket.create_connection((params.target, params.port), timeout=params.timeout) as sock:
            sock.settimeout(params.timeout)
            sock.sendall(payload)
            chunks: list[bytes] = []
            while True:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
    except OSError as exc:
        raise ToolExecutionError(f"TCP send failed: {exc}") from exc

    response = b"".join(chunks).decode(params.encoding, errors="replace")
    structured = {
        "payload": params.payload,
        "encoding": params.encoding,
        "response_preview": response[:1000],
    }
    artifact_path = context.artifact_dir / "tcp_send.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    return ToolExecutionResult(
        tool_name="tcp_send",
        success=True,
        summary=f"TCP payload sent to {params.target}:{params.port}; received {len(response)} character(s).",
        raw_output=response[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
