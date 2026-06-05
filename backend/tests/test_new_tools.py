"""Unit tests for newly-added pentest tools.

Each test uses monkeypatch / mock to avoid real network calls.
"""

from __future__ import annotations

import socket
from pathlib import Path

from app.schemas.tool import (
    AssetDiscoveryInput,
    HttpRequestInput,
    MongoDBCheckInput,
    RedisCheckInput,
    SmbEnumInput,
    SqliProbeInput,
    SshVersionInput,
)
from app.tools.base import ToolContext, ToolExecutionError


# ── asset_discovery ───────────────────────────────────────────────────────────

def test_asset_discovery_parses_nmap_xml(monkeypatch, tmp_path: Path) -> None:
    """Asset discovery should parse nmap XML output and return discovered hosts."""
    from app.tools import asset_discovery

    fake_xml = """<?xml version="1.0"?>
<nmaprun>
<host><status state="up"/><address addr="192.168.1.10"/></host>
<host><status state="up"/><address addr="192.168.1.11"/></host>
</nmaprun>"""

    def fake_run_command(args, timeout, max_output_chars):
        return fake_xml, "", 0

    monkeypatch.setattr(asset_discovery, "run_command", fake_run_command)

    params = AssetDiscoveryInput(targets=["192.168.1.0/24"], timeout=30)
    context = ToolContext(task_id="t1", artifact_dir=tmp_path, max_output_chars=12000)

    result = asset_discovery.execute(params, context)

    assert result.success
    assert result.tool_name == "asset_discovery"
    hosts = result.structured_data["hosts"]
    assert len(hosts) == 2
    assert hosts[0]["address"] == "192.168.1.10"
    assert hosts[1]["address"] == "192.168.1.11"


# ── http_request ──────────────────────────────────────────────────────────────

def test_http_request_sends_post_and_returns_response(monkeypatch, tmp_path: Path) -> None:
    """http_request should send a POST and return the structured response."""
    from app.tools import http_request
    import requests as real_requests

    class FakeResponse:
        status_code = 200
        headers = {"Content-Type": "application/json-rpc"}
        text = '{"id":1,"jsonrpc":"2.0","result":{"version":"1.18.8"}}'

        @staticmethod
        def json():
            return {"id": 1, "jsonrpc": "2.0", "result": {"version": "1.18.8"}}

    def fake_request(method, url, **kwargs):
        return FakeResponse()

    # The tool does: import requests; requests.request(...)
    # So we monkeypatch the requests module's request function
    monkeypatch.setattr(real_requests, "request", fake_request)

    params = HttpRequestInput(
        target="127.0.0.1",
        port=6800,
        scheme="http",
        path="/jsonrpc",
        method="POST",
        headers={"Content-Type": "application/json"},
        body='{"jsonrpc":"2.0","id":1,"method":"aria2.getVersion","params":[]}',
        timeout=15,
    )
    context = ToolContext(task_id="t2", artifact_dir=tmp_path, max_output_chars=12000)

    result = http_request.execute(params, context)

    assert result.success
    assert result.tool_name == "http_request"
    assert result.structured_data["status_code"] == 200
    assert result.structured_data["method"] == "POST"


# ── ftp_anon ──────────────────────────────────────────────────────────────────

def test_ftp_anon_handles_unreachable_gracefully(monkeypatch, tmp_path: Path) -> None:
    """When the FTP server is unreachable, the execute method should produce
    a result indicating the failure (not crash)."""
    from app.tools import ftp_anon

    # Override _try_anon_login to simulate connection failure
    def fake_try_anon_login(target, port, timeout):
        return False, "", []

    monkeypatch.setattr(ftp_anon, "_try_anon_login", fake_try_anon_login)

    params = FtPAnonInput_shim(target="10.255.255.1", port=21, timeout=15)
    context = ToolContext(task_id="t3", artifact_dir=tmp_path, max_output_chars=12000)

    result = ftp_anon.execute(params, context)

    assert result.success
    assert result.tool_name == "ftp_anon"
    assert "FAILED" in result.summary


# Need to import FtpAnonInput - it wasn't imported above
from app.schemas.tool import FtpAnonInput as FtPAnonInput_shim


# ── redis_check ───────────────────────────────────────────────────────────────

def test_redis_check_handles_connection_refused(monkeypatch, tmp_path: Path) -> None:
    """When Redis port is closed, redis_check should raise ToolExecutionError."""
    from app.tools import redis_check

    def fake_create_connection(address, timeout):
        raise ConnectionRefusedError("Connection refused")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    params = RedisCheckInput(target="10.255.255.1", port=6379, timeout=15)
    context = ToolContext(task_id="t4", artifact_dir=tmp_path, max_output_chars=12000)

    try:
        redis_check.execute(params, context)
        assert False, "Expected ToolExecutionError was not raised"
    except ToolExecutionError:
        pass


# ── smb_enum ──────────────────────────────────────────────────────────────────

def test_smb_enum_handles_connection_timeout(monkeypatch, tmp_path: Path) -> None:
    """When SMB port times out, smb_enum should handle the error gracefully
    and report the failure in the structured result."""
    from app.tools import smb_enum

    def fake_create_connection(address, timeout):
        raise TimeoutError("timed out")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    params = SmbEnumInput(target="10.255.255.1", port=445, timeout=15)
    context = ToolContext(task_id="t5", artifact_dir=tmp_path, max_output_chars=12000)

    # smb_enum.execute catches ToolExecutionError from _smb_negotiate and continues
    result = smb_enum.execute(params, context)

    assert result.success
    assert result.tool_name == "smb_enum"
    # Should report the failed negotiate in smb_version
    assert "failed" in str(result.structured_data.get("smb_version", "")).lower()


# ── ssh_version ───────────────────────────────────────────────────────────────

def test_ssh_version_reads_banner_and_returns_version(monkeypatch, tmp_path: Path) -> None:
    """ssh_version should read the SSH banner from a raw socket and return version info."""
    from app.tools import ssh_version

    class FakeSock:
        def __init__(self, *args, **kwargs):
            self._data = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"
            self._pos = 0

        def settimeout(self, t):
            pass

        def sendall(self, data):
            pass

        def recv(self, n):
            if self._pos >= len(self._data):
                raise socket.timeout("recv timeout")
            chunk = self._data[self._pos : self._pos + n]
            self._pos += len(chunk)
            return chunk

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    def fake_create_connection(address, timeout):
        return FakeSock()

    # Also mock ssh -v to avoid subprocess calls
    def fake_ssh_command(target, port, timeout):
        return ("", "")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    monkeypatch.setattr(ssh_version, "_fetch_via_ssh_command", fake_ssh_command)

    params = SshVersionInput(target="127.0.0.1", port=22, timeout=15)
    context = ToolContext(task_id="t6", artifact_dir=tmp_path, max_output_chars=12000)

    result = ssh_version.execute(params, context)

    assert result.success
    assert result.tool_name == "ssh_version"
    assert "OpenSSH_8.9p1" in result.structured_data["version"]
    assert result.structured_data["banner"].startswith("SSH-2.0-")


# ── mongodb_check ─────────────────────────────────────────────────────────────

def test_mongodb_check_handles_connection_refused(monkeypatch, tmp_path: Path) -> None:
    """When MongoDB port is closed, mongodb_check should raise ToolExecutionError."""
    from app.tools import mongodb_check

    def fake_create_connection(address, timeout):
        raise ConnectionRefusedError("Connection refused")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    params = MongoDBCheckInput(target="10.255.255.1", port=27017, timeout=15)
    context = ToolContext(task_id="t7", artifact_dir=tmp_path, max_output_chars=12000)

    try:
        mongodb_check.execute(params, context)
        assert False, "Expected ToolExecutionError was not raised"
    except ToolExecutionError:
        pass


# ── sqli_probe ────────────────────────────────────────────────────────────────

def test_sqli_probe_detects_sql_error(monkeypatch, tmp_path: Path) -> None:
    """sqli_probe should detect SQL error patterns in HTTP responses."""
    from app.tools import sqli_probe
    import requests as real_requests

    class FakeResponse:
        status_code = 200
        text = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"

    def fake_get(url, timeout, allow_redirects, verify):
        return FakeResponse()

    monkeypatch.setattr(real_requests, "get", fake_get)

    params = SqliProbeInput(
        target="127.0.0.1",
        port=8080,
        scheme="http",
        path="/search.php",
        param="q",
        timeout=15,
    )
    context = ToolContext(task_id="t8", artifact_dir=tmp_path, max_output_chars=12000)

    result = sqli_probe.execute(params, context)

    assert result.success
    assert result.tool_name == "sqli_probe"
    errors_found = [i for i in result.structured_data["injections"] if i["error_matched"]]
    assert len(errors_found) > 0


def test_sqli_probe_no_errors_clean_response(monkeypatch, tmp_path: Path) -> None:
    """sqli_probe should report no errors when the target returns clean HTML."""
    from app.tools import sqli_probe
    import requests as real_requests

    class FakeCleanResponse:
        status_code = 200
        text = "<html><body><h1>Search Results</h1><p>No results found.</p></body></html>"

    def fake_get(url, timeout, allow_redirects, verify):
        return FakeCleanResponse()

    monkeypatch.setattr(real_requests, "get", fake_get)

    params = SqliProbeInput(
        target="127.0.0.1",
        port=8080,
        scheme="http",
        path="/search.php",
        param="q",
        timeout=15,
    )
    context = ToolContext(task_id="t8b", artifact_dir=tmp_path, max_output_chars=12000)

    result = sqli_probe.execute(params, context)

    assert result.success
    errors_found = [i for i in result.structured_data["injections"] if i["error_matched"]]
    assert len(errors_found) == 0


# ── default_creds ─────────────────────────────────────────────────────────────

def test_default_creds_handles_unreachable(monkeypatch, tmp_path: Path) -> None:
    """default_creds should gracefully handle unreachable targets."""
    import requests as real_requests

    def fake_session_get(self, url, **kwargs):
        raise real_requests.ConnectionError("Connection refused")

    monkeypatch.setattr(real_requests.Session, "get", fake_session_get)

    from app.tools import default_creds
    from app.schemas.tool import DefaultCredsInput

    params = DefaultCredsInput(target="10.255.255.1", port=80, scheme="http", timeout=30)
    context = ToolContext(task_id="t9", artifact_dir=tmp_path, max_output_chars=12000)

    result = default_creds.execute(params, context)

    assert result.success
    assert result.tool_name == "default_creds"
    # Should not have crashed; attempts list may be empty
    assert isinstance(result.structured_data.get("attempts", []), list)
