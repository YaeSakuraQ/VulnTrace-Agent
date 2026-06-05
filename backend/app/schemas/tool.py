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
    profile: Literal["auto", "php_apache", "mini_httpd", "generic_web"] = "auto"
    preferred_poc: Literal["auto", "dvwa_fi", "none"] = "auto"
    service_name: str = ""
    service_product: str = ""
    service_version: str = ""
    lab_description: str = ""
    page_title: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    interesting_paths: list[str] = Field(default_factory=list, max_length=12)
    timeout: int = Field(default=120, ge=30, le=300)
