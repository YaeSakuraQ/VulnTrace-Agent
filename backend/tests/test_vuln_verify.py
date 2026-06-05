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
