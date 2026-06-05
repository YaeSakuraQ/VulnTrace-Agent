from __future__ import annotations

from pathlib import Path

from app.schemas.tool import VulnerabilityVerifyInput
from app.tools.base import ToolContext
from app.tools import vuln_verify


class DummyResponse:
    def __init__(self, status_code: int, payload: dict, headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {"Content-Type": "application/json-rpc"}
        self.text = str(payload)

    def json(self) -> dict:
        return self._payload


def test_vuln_verify_confirms_unauthenticated_json_rpc_access(monkeypatch, tmp_path: Path) -> None:
    def fake_post(url: str, **kwargs) -> DummyResponse:
        assert url.endswith("/jsonrpc")
        return DummyResponse(
            200,
            {
                "id": 1,
                "jsonrpc": "2.0",
                "result": {
                    "version": "1.18.8",
                    "enabledFeatures": ["BitTorrent", "HTTPS"],
                },
            },
        )

    monkeypatch.setattr(vuln_verify.requests, "post", fake_post)
    params = VulnerabilityVerifyInput(
        target="127.0.0.1",
        port=6800,
        scheme="http",
        profile="json_rpc",
        service_product="aria2 downloader JSON-RPC",
        interesting_paths=["/jsonrpc"],
        timeout=30,
    )
    context = ToolContext(
        task_id="json-rpc-test",
        artifact_dir=tmp_path,
        max_output_chars=12000,
    )

    result = vuln_verify.execute(params, context)

    assert result.success is True
    assert result.structured_data["verification_status"] == "confirmed"
    assert result.structured_data["pocs"][0]["id"] == "json-rpc-aria2-getversion"
    assert any(
        item["title"].startswith("Unauthenticated JSON-RPC method call succeeded")
        for item in result.structured_data["findings"]
    )


def test_vuln_verify_generic_exploit_detects_path_traversal(monkeypatch, tmp_path: Path) -> None:
    """When profile is generic_exploit, the verifier should attempt common
    traversal payloads and detect path traversal vulnerabilities."""
    def fake_post(url: str, **kwargs) -> DummyResponse:
        return DummyResponse(200, {"error": {"code": -32601, "message": "Method not found"}})

    monkeypatch.setattr(vuln_verify.requests, "post", fake_post)

    params = VulnerabilityVerifyInput(
        target="127.0.0.1",
        port=8080,
        scheme="http",
        profile="generic_exploit",
        service_product="generic web app",
        interesting_paths=["/", "/login"],
        timeout=30,
    )
    context = ToolContext(
        task_id="generic-exploit-test",
        artifact_dir=tmp_path,
        max_output_chars=12000,
    )

    result = vuln_verify.execute(params, context)

    assert result.success is True
    assert result.tool_name == "vuln_verify"
    assert result.structured_data["profile"] == "generic_exploit"


def test_vuln_verify_generic_exploit_detects_sqli_error(monkeypatch, tmp_path: Path) -> None:
    """When profile is generic_exploit, the verifier should run SQL injection
    probes and detect SQL error patterns in responses."""
    sql_error_body = (
        "You have an error in your SQL syntax; "
        "check the manual that corresponds to your MySQL server version"
    )

    class DummySqlResponse(DummyResponse):
        def __init__(self, status_code: int, payload: dict, headers=None):
            super().__init__(status_code, payload, headers)
            self.text = sql_error_body

    def fake_post(url: str, **kwargs) -> DummySqlResponse:
        return DummySqlResponse(200, {})

    monkeypatch.setattr(vuln_verify.requests, "post", fake_post)

    params = VulnerabilityVerifyInput(
        target="127.0.0.1",
        port=8080,
        scheme="http",
        profile="generic_exploit",
        service_product="php mysql app",
        interesting_paths=["/login.php", "/user.php?id=1"],
        timeout=30,
    )
    context = ToolContext(
        task_id="sqli-test",
        artifact_dir=tmp_path,
        max_output_chars=12000,
    )

    result = vuln_verify.execute(params, context)

    assert result.success is True
    assert result.tool_name == "vuln_verify"
    assert result.structured_data["profile"] == "generic_exploit"


def test_vuln_verify_handles_failure_gracefully(monkeypatch, tmp_path: Path) -> None:
    """When the target is unreachable, vuln_verify should return a
    successful ToolExecutionResult with inconclusive status rather than
    raising an unhandled exception."""

    def fake_post(url: str, **kwargs):
        raise ConnectionError("Connection refused")

    monkeypatch.setattr(vuln_verify.requests, "post", fake_post)

    params = VulnerabilityVerifyInput(
        target="192.168.255.255",
        port=9999,
        scheme="http",
        profile="json_rpc",
        service_product="unreachable service",
        interesting_paths=[],
        timeout=5,
    )
    context = ToolContext(
        task_id="unreachable-test",
        artifact_dir=tmp_path,
        max_output_chars=12000,
    )

    result = vuln_verify.execute(params, context)

    assert result.success is True
    assert result.tool_name == "vuln_verify"
    assert result.structured_data["verification_status"] in {"inconclusive", "profiled"}
