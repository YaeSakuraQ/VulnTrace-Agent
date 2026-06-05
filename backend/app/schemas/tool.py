from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class ToolExecutionResult(BaseModel):
    tool_name: str
    success: bool
    summary: str
    raw_output: str = ""
    structured_data: dict[str, Any] = Field(default_factory=dict)
    artifact_paths: list[str] = Field(default_factory=list)
    error: str | None = None


class AssetDiscoveryInput(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=16)
    timeout: int = Field(default=60, ge=5, le=180)


class ServiceFingerprintInput(BaseModel):
    target: str
    port_spec: str | None = None
    timeout: int = Field(default=90, ge=5, le=240)


class WebProbeInput(BaseModel):
    target: str
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"
    paths: list[str] = Field(default_factory=lambda: ["/"], max_length=12)
    timeout: int = Field(default=30, ge=5, le=120)


class DirEnumInput(BaseModel):
    target: str
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"
    max_paths: int = Field(default=12, ge=1, le=30)
    timeout: int = Field(default=45, ge=5, le=180)


class FfufEnumInput(BaseModel):
    target: str
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"
    words: list[str] = Field(default_factory=list, min_length=1, max_length=20)
    timeout: int = Field(default=60, ge=10, le=180)
    rate: int = Field(default=5, ge=1, le=20)


class HttpSnapshotInput(BaseModel):
    target: str
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"
    paths: list[str] = Field(default_factory=lambda: ["/"], min_length=1, max_length=8)
    timeout: int = Field(default=20, ge=5, le=120)
    max_body_chars: int = Field(default=240, ge=40, le=2000)


class HttpGetInput(BaseModel):
    target: str
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"
    path: str = "/"
    method: Literal["GET", "HEAD"] = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    allow_redirects: bool = True
    timeout: int = Field(default=15, ge=3, le=120)


class HttpRequestInput(BaseModel):
    target: str
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"
    path: str = "/"
    method: Literal["GET", "HEAD", "OPTIONS", "POST"] = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = Field(default="", max_length=2000)
    allow_redirects: bool = True
    timeout: int = Field(default=15, ge=3, le=120)


class HeaderMutationInput(BaseModel):
    target: str
    port: int = Field(ge=1, le=65535)
    method: Literal["GET", "HEAD", "POST"] = "GET"
    path: str = "/"
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    protocol_version: Literal["HTTP/1.0", "HTTP/1.1"] = "HTTP/1.1"
    timeout: int = Field(default=15, ge=3, le=120)


class RawHttpInput(BaseModel):
    target: str
    port: int = Field(ge=1, le=65535)
    request: str = Field(min_length=1, max_length=6000)
    timeout: int = Field(default=15, ge=3, le=120)


class TcpSendInput(BaseModel):
    target: str
    port: int = Field(ge=1, le=65535)
    payload: str = Field(min_length=1, max_length=6000)
    encoding: Literal["latin1", "utf-8"] = "latin1"
    timeout: int = Field(default=15, ge=3, le=120)


class TemplateRunnerInput(BaseModel):
    target: str
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"
    template: Literal["nikto_scan", "nmap_service"] = "nikto_scan"
    timeout: int = Field(default=30, ge=5, le=180)


class VulnerabilityVerifyInput(BaseModel):
    target: str
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"
    profile: Literal["auto", "php_apache", "mini_httpd", "json_rpc", "generic_web", "generic_exploit"] = "auto"
    preferred_poc: Literal["auto", "dvwa_fi", "none"] = "auto"
    service_name: str = ""
    service_product: str = ""
    service_version: str = ""
    lab_description: str = ""
    page_title: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    interesting_paths: list[str] = Field(default_factory=list, max_length=12)
    timeout: int = Field(default=120, ge=30, le=300)


class SshVersionInput(BaseModel):
    target: str = Field(..., description="SSH target host")
    port: int = Field(default=22, ge=1, le=65535)
    timeout: int = Field(default=15, ge=5, le=60)


class FtpAnonInput(BaseModel):
    target: str
    port: int = Field(default=21, ge=1, le=65535)
    timeout: int = Field(default=15, ge=5, le=60)


class SmbEnumInput(BaseModel):
    target: str
    port: int = Field(default=445, ge=1, le=65535)
    timeout: int = Field(default=15, ge=5, le=60)


class RedisCheckInput(BaseModel):
    target: str
    port: int = Field(default=6379, ge=1, le=65535)
    timeout: int = Field(default=15, ge=5, le=60)


class MongoDBCheckInput(BaseModel):
    target: str
    port: int = Field(default=27017, ge=1, le=65535)
    timeout: int = Field(default=15, ge=5, le=60)


class SqliProbeInput(BaseModel):
    target: str
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"
    path: str = "/"
    param: str = Field(..., description="Query parameter name to inject")
    timeout: int = Field(default=15, ge=5, le=120)


class DefaultCredsInput(BaseModel):
    target: str
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"
    timeout: int = Field(default=30, ge=10, le=120)


# ── Kali tool schemas ────────────────────────────────────────────────────


class GobusterEnumInput(BaseModel):
    target: str = Field(..., description="Target URL or domain")
    mode: Literal["dir", "dns"] = "dir"
    port: int = Field(default=80, ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"
    timeout: int = Field(default=120, ge=30, le=300)


class WhatwebProbeInput(BaseModel):
    target: str = Field(..., description="Target URL to fingerprint")
    port: int = Field(default=80, ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"
    timeout: int = Field(default=60, ge=15, le=180)


class SearchsploitLookupInput(BaseModel):
    query: str = Field(..., description="Service/version string to search Exploit-DB for")


class Enum4linuxWrapperInput(BaseModel):
    target: str = Field(..., description="Target host for SMB enumeration")
    timeout: int = Field(default=180, ge=30, le=600)


class HydraBruteInput(BaseModel):
    target: str = Field(..., description="Target host for brute-force")
    protocol: Literal["ssh", "ftp", "mysql", "postgres", "rdp"] = Field(..., description="Protocol to attack")
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(..., description="Single username to test")
    password: str = Field(..., description="Single password to test")
    timeout: int = Field(default=60, ge=15, le=180)


class SqlmapApiInput(BaseModel):
    target: str = Field(..., description="Target URL with parameters, e.g. http://host/page.php?id=1")
    timeout: int = Field(default=180, ge=30, le=600)


class CommixProbeInput(BaseModel):
    target: str = Field(..., description="Target URL with parameters, e.g. http://host/page.php?cmd=127.0.0.1")
    timeout: int = Field(default=120, ge=30, le=300)


class LinpeasRunnerInput(BaseModel):
    target: str = Field(default="localhost", description="Target host identifier for result labeling")
    timeout: int = Field(default=120, ge=15, le=300)


class ImpacketWrapperInput(BaseModel):
    tool: Literal["impacket-secretsdump", "impacket-smbclient", "impacket-wmiexec"] = Field(..., description="Impacket tool to execute")
    target: str = Field(..., description="Target host (IP or hostname)")
    domain: str = Field(default="", description="Domain name")
    username: str = Field(default="", description="Username for authentication")
    password: str = Field(default="", description="Password for authentication")
    nt_hash: str = Field(default="", description="NTLM hash for pass-the-hash")
    command: str = Field(default="", description="Command to execute (for wmiexec)")
    timeout: int = Field(default=180, ge=30, le=600)


class WpscanProbeInput(BaseModel):
    target: str = Field(..., description="Target WordPress URL base, e.g. http://host/")
    timeout: int = Field(default=180, ge=30, le=600)
