from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas.tool import (
    AssetDiscoveryInput,
    DirEnumInput,
    FfufEnumInput,
    FtpAnonInput,
    HeaderMutationInput,
    HttpGetInput,
    HttpRequestInput,
    HttpSnapshotInput,
    MongoDBCheckInput,
    RawHttpInput,
    RedisCheckInput,
    ServiceFingerprintInput,
    SmbEnumInput,
    SqliProbeInput,
    SshVersionInput,
    TcpSendInput,
    TemplateRunnerInput,
    VulnerabilityVerifyInput,
    WebProbeInput,
)


def test_service_fingerprint_accepts_port_spec() -> None:
    payload = ServiceFingerprintInput.model_validate(
        {"target": "192.168.56.10", "port_spec": "80,443,8080"}
    )
    assert payload.port_spec == "80,443,8080"


def test_web_probe_rejects_invalid_port() -> None:
    with pytest.raises(ValidationError):
        WebProbeInput.model_validate({"target": "127.0.0.1", "port": 70000})


def test_dir_enum_limits_path_count() -> None:
    with pytest.raises(ValidationError):
        DirEnumInput.model_validate(
            {"target": "127.0.0.1", "port": 80, "max_paths": 31}
        )


def test_ffuf_enum_limits_word_count() -> None:
    with pytest.raises(ValidationError):
        FfufEnumInput.model_validate(
            {
                "target": "127.0.0.1",
                "port": 80,
                "words": [str(index) for index in range(21)],
            }
        )


def test_http_snapshot_limits_path_count() -> None:
    with pytest.raises(ValidationError):
        HttpSnapshotInput.model_validate(
            {
                "target": "127.0.0.1",
                "port": 80,
                "paths": [f"/p{index}" for index in range(9)],
            }
        )


def test_vuln_verify_accepts_profile_and_context() -> None:
    payload = VulnerabilityVerifyInput.model_validate(
        {
            "target": "127.0.0.1",
            "port": 8088,
            "profile": "json_rpc",
            "preferred_poc": "dvwa_fi",
            "service_product": "mini_httpd",
            "interesting_paths": ["/etc/passwd"],
        }
    )
    assert payload.profile == "json_rpc"
    assert payload.preferred_poc == "dvwa_fi"
    assert payload.service_product == "mini_httpd"


def test_http_get_accepts_custom_headers() -> None:
    payload = HttpGetInput.model_validate(
        {
            "target": "127.0.0.1",
            "port": 8088,
            "path": "/robots.txt",
            "headers": {"Accept": "*/*"},
        }
    )
    assert payload.path == "/robots.txt"
    assert payload.headers["Accept"] == "*/*"


def test_http_request_accepts_post_body() -> None:
    payload = HttpRequestInput.model_validate(
        {
            "target": "127.0.0.1",
            "port": 6800,
            "method": "POST",
            "path": "/jsonrpc",
            "headers": {"Content-Type": "application/json"},
            "body": '{"jsonrpc":"2.0","method":"rpc.discover","params":[]}',
        }
    )
    assert payload.method == "POST"
    assert payload.path == "/jsonrpc"
    assert payload.headers["Content-Type"] == "application/json"
    # Verify the POST body field is properly accepted and preserved
    assert payload.body == '{"jsonrpc":"2.0","method":"rpc.discover","params":[]}'


def test_header_mutation_accepts_empty_host_header() -> None:
    payload = HeaderMutationInput.model_validate(
        {
            "target": "127.0.0.1",
            "port": 8088,
            "path": "/etc/passwd",
            "headers": {"Host": ""},
        }
    )
    assert payload.headers["Host"] == ""


def test_raw_http_limits_request_size() -> None:
    with pytest.raises(ValidationError):
        RawHttpInput.model_validate(
            {"target": "127.0.0.1", "port": 80, "request": "A" * 7000}
        )


def test_tcp_send_accepts_utf8_payload() -> None:
    payload = TcpSendInput.model_validate(
        {"target": "127.0.0.1", "port": 9000, "payload": "PING", "encoding": "utf-8"}
    )
    assert payload.encoding == "utf-8"


def test_template_runner_accepts_known_template() -> None:
    payload = TemplateRunnerInput.model_validate(
        {"target": "127.0.0.1", "port": 8088, "template": "nikto_scan"}
    )
    assert payload.template == "nikto_scan"


# ── Schema validation tests for new tools ─────────────────────────────────────

def test_asset_discovery_accepts_targets_list() -> None:
    payload = AssetDiscoveryInput.model_validate(
        {"targets": ["192.168.1.1", "10.0.0.1"], "timeout": 30}
    )
    assert payload.targets == ["192.168.1.1", "10.0.0.1"]
    assert payload.timeout == 30


def test_asset_discovery_rejects_empty_targets() -> None:
    with pytest.raises(ValidationError):
        AssetDiscoveryInput.model_validate({"targets": []})


def test_ftp_anon_accepts_target_and_port() -> None:
    payload = FtpAnonInput.model_validate(
        {"target": "192.168.1.10", "port": 2121, "timeout": 20}
    )
    assert payload.target == "192.168.1.10"
    assert payload.port == 2121
    assert payload.timeout == 20


def test_ftp_anon_defaults_to_port_21() -> None:
    payload = FtpAnonInput.model_validate({"target": "10.0.0.5"})
    assert payload.port == 21


def test_redis_check_accepts_target_and_port() -> None:
    payload = RedisCheckInput.model_validate(
        {"target": "192.168.1.10", "port": 6380, "timeout": 20}
    )
    assert payload.target == "192.168.1.10"
    assert payload.port == 6380


def test_redis_check_defaults_to_port_6379() -> None:
    payload = RedisCheckInput.model_validate({"target": "10.0.0.5"})
    assert payload.port == 6379


def test_smb_enum_accepts_target_and_port() -> None:
    payload = SmbEnumInput.model_validate(
        {"target": "192.168.1.10", "port": 445, "timeout": 30}
    )
    assert payload.target == "192.168.1.10"
    assert payload.port == 445


def test_smb_enum_defaults_to_port_445() -> None:
    payload = SmbEnumInput.model_validate({"target": "10.0.0.5"})
    assert payload.port == 445


def test_ssh_version_accepts_target_and_port() -> None:
    payload = SshVersionInput.model_validate(
        {"target": "192.168.1.10", "port": 2222, "timeout": 30}
    )
    assert payload.target == "192.168.1.10"
    assert payload.port == 2222


def test_ssh_version_defaults_to_port_22() -> None:
    payload = SshVersionInput.model_validate({"target": "10.0.0.5"})
    assert payload.port == 22


def test_vuln_verify_accepts_generic_exploit_profile() -> None:
    """The generic_exploit profile should be accepted by VulnerabilityVerifyInput."""
    payload = VulnerabilityVerifyInput.model_validate(
        {
            "target": "127.0.0.1",
            "port": 8080,
            "profile": "generic_exploit",
            "service_product": "generic web app",
            "interesting_paths": ["/", "/login"],
        }
    )
    assert payload.profile == "generic_exploit"


def test_mongodb_check_accepts_target() -> None:
    payload = MongoDBCheckInput.model_validate(
        {"target": "192.168.1.10", "port": 27017, "timeout": 20}
    )
    assert payload.target == "192.168.1.10"
    assert payload.port == 27017


def test_mongodb_check_defaults_to_port_27017() -> None:
    payload = MongoDBCheckInput.model_validate({"target": "10.0.0.5"})
    assert payload.port == 27017


def test_sqli_probe_requires_param() -> None:
    payload = SqliProbeInput.model_validate(
        {
            "target": "127.0.0.1",
            "port": 8080,
            "scheme": "http",
            "path": "/search.php",
            "param": "q",
            "timeout": 20,
        }
    )
    assert payload.param == "q"
    assert payload.path == "/search.php"


def test_sqli_probe_rejects_missing_param() -> None:
    with pytest.raises(ValidationError):
        SqliProbeInput.model_validate(
            {"target": "127.0.0.1", "port": 8080, "path": "/search.php"}
        )
