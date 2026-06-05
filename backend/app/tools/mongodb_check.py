from __future__ import annotations

import json
import socket
import struct

from app.schemas.tool import MongoDBCheckInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError


# MongoDB Wire Protocol: OP_QUERY for the "admin.$cmd" collection with ismaster command
def _build_ismaster_query() -> bytes:
    """Build a minimal MongoDB OP_QUERY message for { isMaster: 1 }."""
    # The actual message body (BSON): \x10\x00\x00\x00 isMaster\x00\x01\x00\x00\x00\x00
    bson_doc = (
        b"\x10\x00\x00\x00"          # Total document size (16 bytes)
        b"\x10"                       # int32 type
        b"ismaster\x00"              # key "ismaster"
        b"\x01\x00\x00\x00"          # value 1
        b"\x00"                       # BSON document terminator
    )
    # Build header
    message_length = 16 + 12 + len(bson_doc)  # header(16) + section(12) + doc
    request_id = 1
    response_to = 0
    op_code = 2004  # OP_MSG

    # OP_MSG header
    header = struct.pack(
        "<iiii",
        message_length,
        request_id,
        response_to,
        op_code,
    )
    # OP_MSG body: flagBits=0, sections=[kind=0 (body), payload=bson]
    body = struct.pack("<I", 0)  # flagBits
    body += b"\x00"  # section kind (0 = body)
    body += bson_doc

    return header + body


def _parse_reply(data: bytes) -> dict:
    """Extract isMaster result and version from OP_MSG reply."""
    result: dict = {"version": "", "unauthorized": False}
    if len(data) < 20:
        return result

    try:
        msg_len, req_id, resp_to, op_code = struct.unpack_from("<iiii", data, 0)
    except struct.error:
        return result

    if op_code != 2013:  # OP_MSG reply
        # Could be legacy OP_REPLY (1)
        return result

    body = data[16:]
    if not body:
        return result

    # Body starts with flagBits then sections
    payload = body[4:]  # skip flagBits
    # Look for maxWireVersion, version strings, and error indicators
    text = payload.decode("latin1", errors="replace")

    # Heuristic: check for "maxWireVersion" indicating successful connection
    if "maxWireVersion" in text or "ismaster" in text.lower():
        result["unauthorized"] = True

    # Try to extract version string
    # MongoDB wire protocol may include version in the reply
    if "version" in text.lower():
        # Try to find version value
        import re
        ver_match = re.search(rb"version\0\x02([^\x00]+)\x00", payload, re.IGNORECASE)
        if ver_match:
            result["version"] = ver_match.group(1).decode("latin1", errors="replace")
        else:
            # Look for version array
            ver_arr = re.search(rb"versionArray\0", payload)
            if ver_arr:
                result["version"] = "detected (versionArray present)"

    return result


def execute(params: MongoDBCheckInput, context: ToolContext) -> ToolExecutionResult:
    structured: dict = {"unauthorized": False, "version": "", "databases": []}

    try:
        with socket.create_connection((params.target, params.port), timeout=params.timeout) as sock:
            sock.settimeout(params.timeout)
            query = _build_ismaster_query()
            sock.sendall(query)

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
        raise ToolExecutionError(
            f"MongoDB connection timed out for {params.target}:{params.port}"
        )
    except OSError as exc:
        raise ToolExecutionError(
            f"MongoDB connection failed for {params.target}:{params.port}: {exc}"
        ) from exc

    if data:
        parsed = _parse_reply(data)
        structured.update(parsed)
        if not structured["version"]:
            # Set raw reply preview as version hint
            raw_preview = data.decode("latin1", errors="replace")[:500]
            structured["version"] = f"raw: {raw_preview}"
    else:
        structured["version"] = "no response"

    # Attempt to list databases if unauthorized
    if structured["unauthorized"]:
        try:
            with socket.create_connection((params.target, params.port), timeout=params.timeout) as sock2:
                sock2.settimeout(params.timeout)
                # OP_QUERY: { listDatabases: 1 } against admin database
                list_db_bson = (
                    b"\x1e\x00\x00\x00"      # document size
                    b"\x10"                   # int32
                    b"listDatabases\x00"      # key
                    b"\x01\x00\x00\x00"       # value 1
                    b"\x00"                   # terminator
                )
                header = struct.pack(
                    "<iiii",
                    16 + 12 + 8 + 29 + len(list_db_bson),  # msgLen = header + flags + collectionName + numSkip + numReturn + doc
                    2,    # requestID
                    0,    # responseTo
                    2004, # OP_MSG
                )
                # Build OP_MSG with section kind 0
                flags = struct.pack("<I", 0)
                section = b"\x00" + list_db_bson
                sock2.sendall(header + flags + section)

                chunks2: list[bytes] = []
                while True:
                    try:
                        c = sock2.recv(4096)
                    except socket.timeout:
                        break
                    if not c:
                        break
                    chunks2.append(c)
                db_data = b"".join(chunks2)

                # Extract database names from response
                import re
                db_names = re.findall(rb"name\0\x02([^\x00]+)\x00", db_data)
                structured["databases"] = [
                    n.decode("latin1", errors="replace") for n in db_names[:20]
                ]
        except Exception:
            pass

    if structured["unauthorized"]:
        summary = f"MongoDB UNAUTHORIZED on {params.target}:{params.port}"
        if structured["databases"]:
            summary += f"; {len(structured['databases'])} database(s): {', '.join(structured['databases'][:8])}"
    else:
        summary = f"MongoDB port open on {params.target}:{params.port} but requires authentication."

    artifact_path = context.artifact_dir / "mongodb_check.json"
    artifact_path.write_text(json.dumps(structured, indent=2, default=str), encoding="utf-8")

    return ToolExecutionResult(
        tool_name="mongodb_check",
        success=True,
        summary=summary,
        raw_output=json.dumps(structured, indent=2, default=str)[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
