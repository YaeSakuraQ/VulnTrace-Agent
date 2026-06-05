from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from app.core.config import Settings
from app.core.risk_policy import RiskTolerance, get_policy
from app.core.scope_guard import ScopeGuard
from app.schemas.tool import (
    AssetDiscoveryInput,
    DefaultCredsInput,
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
    ToolExecutionResult,
    VulnerabilityVerifyInput,
    WebProbeInput,
)
from app.services.artifact_store import ArtifactStore
from app.tools import (
    asset_discovery,
    default_creds,
    dir_enum,
    ffuf_enum,
    ftp_anon,
    header_mutation,
    http_get,
    http_request,
    http_snapshot,
    mongodb_check,
    raw_http,
    redis_check,
    report_tool,
    service_fingerprint,
    smb_enum,
    sqli_probe,
    ssh_version,
    tcp_send,
    template_runner,
    vuln_verify,
    web_probe,
)
from app.tools.base import ToolContext, ToolExecutionError, ToolSpec, sanitize_filename


class ToolExecutor:
    def __init__(
        self,
        *,
        settings: Settings,
        scope_guard: ScopeGuard,
        artifact_store: ArtifactStore,
    ) -> None:
        self.settings = settings
        self.scope_guard = scope_guard
        self.artifact_store = artifact_store
        self.registry: dict[str, ToolSpec] = {
            "asset_discovery": ToolSpec(
                name="asset_discovery",
                description="Low-intensity host discovery using nmap -sn.",
                input_model=AssetDiscoveryInput,
                risk_level=get_policy("asset_discovery").risk_level,
                approval_required=get_policy("asset_discovery").approval_required,
                allowed_stages=("*",),
                handler=asset_discovery.execute,
            ),
            "service_fingerprint": ToolSpec(
                name="service_fingerprint",
                description="Bounded service detection using nmap -sV --version-light.",
                input_model=ServiceFingerprintInput,
                risk_level=get_policy("service_fingerprint").risk_level,
                approval_required=get_policy("service_fingerprint").approval_required,
                allowed_stages=("*",),
                handler=service_fingerprint.execute,
            ),
            "web_probe": ToolSpec(
                name="web_probe",
                description="Low-risk HTTP fingerprinting using structured requests.",
                input_model=WebProbeInput,
                risk_level=get_policy("web_probe").risk_level,
                approval_required=get_policy("web_probe").approval_required,
                allowed_stages=("*",),
                handler=web_probe.execute,
            ),
            "dir_enum": ToolSpec(
                name="dir_enum",
                description="Rate-limited enumeration over a fixed small path set.",
                input_model=DirEnumInput,
                risk_level=get_policy("dir_enum").risk_level,
                approval_required=get_policy("dir_enum").approval_required,
                allowed_stages=("*",),
                handler=dir_enum.execute,
            ),
            "ffuf_enum": ToolSpec(
                name="ffuf_enum",
                description="Bounded ffuf content discovery over a tiny curated wordlist.",
                input_model=FfufEnumInput,
                risk_level=get_policy("ffuf_enum").risk_level,
                approval_required=get_policy("ffuf_enum").approval_required,
                allowed_stages=("*",),
                handler=ffuf_enum.execute,
            ),
            "http_snapshot": ToolSpec(
                name="http_snapshot",
                description="Capture short HTTP body snippets and key headers for selected paths.",
                input_model=HttpSnapshotInput,
                risk_level=get_policy("http_snapshot").risk_level,
                approval_required=get_policy("http_snapshot").approval_required,
                allowed_stages=("*",),
                handler=http_snapshot.execute,
            ),
            "http_get": ToolSpec(
                name="http_get",
                description="Structured HTTP observation primitive.",
                input_model=HttpGetInput,
                risk_level=get_policy("http_get").risk_level,
                approval_required=get_policy("http_get").approval_required,
                allowed_stages=("*",),
                handler=http_get.execute,
            ),
            "http_request": ToolSpec(
                name="http_request",
                description="Structured standard HTTP request primitive for bounded API interaction.",
                input_model=HttpRequestInput,
                risk_level=get_policy("http_request").risk_level,
                approval_required=get_policy("http_request").approval_required,
                allowed_stages=("*",),
                handler=http_request.execute,
            ),
            "header_mutation": ToolSpec(
                name="header_mutation",
                description="HTTP request primitive with explicit header mutation control.",
                input_model=HeaderMutationInput,
                risk_level=get_policy("header_mutation").risk_level,
                approval_required=get_policy("header_mutation").approval_required,
                allowed_stages=("*",),
                handler=header_mutation.execute,
            ),
            "raw_http": ToolSpec(
                name="raw_http",
                description="Raw HTTP primitive for protocol-level exploit attempts.",
                input_model=RawHttpInput,
                risk_level=get_policy("raw_http").risk_level,
                approval_required=get_policy("raw_http").approval_required,
                allowed_stages=("*",),
                handler=raw_http.execute,
            ),
            "tcp_send": ToolSpec(
                name="tcp_send",
                description="Low-level TCP payload primitive.",
                input_model=TcpSendInput,
                risk_level=get_policy("tcp_send").risk_level,
                approval_required=get_policy("tcp_send").approval_required,
                allowed_stages=("*",),
                handler=tcp_send.execute,
            ),
            "template_runner": ToolSpec(
                name="template_runner",
                description="Run a bounded scanner template such as Nikto or nmap.",
                input_model=TemplateRunnerInput,
                risk_level=get_policy("template_runner").risk_level,
                approval_required=get_policy("template_runner").approval_required,
                allowed_stages=("*",),
                handler=template_runner.execute,
            ),
            "vuln_verify": ToolSpec(
                name="vuln_verify",
                description="Controlled Nikto verification requiring approval.",
                input_model=VulnerabilityVerifyInput,
                risk_level=get_policy("vuln_verify").risk_level,
                approval_required=get_policy("vuln_verify").approval_required,
                allowed_stages=("*",),
                handler=vuln_verify.execute,
            ),
            "report_tool": ToolSpec(
                name="report_tool",
                description="Local report generation helper.",
                input_model=AssetDiscoveryInput,
                risk_level=get_policy("report_tool").risk_level,
                approval_required=get_policy("report_tool").approval_required,
                allowed_stages=("*",),
                handler=report_tool.execute,
            ),
            # ── New tools ──────────────────────────────────────────────
            "ssh_version": ToolSpec(
                name="ssh_version",
                description="SSH version fingerprinting via banner grab and ssh -v.",
                input_model=SshVersionInput,
                risk_level=get_policy("ssh_version").risk_level,
                approval_required=get_policy("ssh_version").approval_required,
                allowed_stages=("service_fingerprint", "exploit"),
                handler=ssh_version.execute,
            ),
            "ftp_anon": ToolSpec(
                name="ftp_anon",
                description="Anonymous FTP login check against a bounded credential set.",
                input_model=FtpAnonInput,
                risk_level=get_policy("ftp_anon").risk_level,
                approval_required=get_policy("ftp_anon").approval_required,
                allowed_stages=("service_fingerprint", "exploit"),
                handler=ftp_anon.execute,
            ),
            "smb_enum": ToolSpec(
                name="smb_enum",
                description="SMB share enumeration and version detection via negotiate protocol.",
                input_model=SmbEnumInput,
                risk_level=get_policy("smb_enum").risk_level,
                approval_required=get_policy("smb_enum").approval_required,
                allowed_stages=("service_fingerprint", "exploit"),
                handler=smb_enum.execute,
            ),
            "redis_check": ToolSpec(
                name="redis_check",
                description="Redis unauthorized access check using PING / INFO / CONFIG GET.",
                input_model=RedisCheckInput,
                risk_level=get_policy("redis_check").risk_level,
                approval_required=get_policy("redis_check").approval_required,
                allowed_stages=("service_fingerprint", "exploit"),
                handler=redis_check.execute,
            ),
            "mongodb_check": ToolSpec(
                name="mongodb_check",
                description="MongoDB unauthorized access check using ismaster wire protocol.",
                input_model=MongoDBCheckInput,
                risk_level=get_policy("mongodb_check").risk_level,
                approval_required=get_policy("mongodb_check").approval_required,
                allowed_stages=("service_fingerprint", "exploit"),
                handler=mongodb_check.execute,
            ),
            "sqli_probe": ToolSpec(
                name="sqli_probe",
                description="Structured SQL injection probing with bounded payload set.",
                input_model=SqliProbeInput,
                risk_level=get_policy("sqli_probe").risk_level,
                approval_required=get_policy("sqli_probe").approval_required,
                allowed_stages=("exploit",),
                handler=sqli_probe.execute,
            ),
            "default_creds": ToolSpec(
                name="default_creds",
                description="Default credential check against known service account lists.",
                input_model=DefaultCredsInput,
                risk_level=get_policy("default_creds").risk_level,
                approval_required=get_policy("default_creds").approval_required,
                allowed_stages=("exploit",),
                handler=default_creds.execute,
            ),
        }

    def execute(
        self,
        *,
        task_id: str,
        scope: list[str],
        stage: str,
        tool_name: str,
        params: dict,
        risk_tolerance: str | None = None,
    ) -> ToolExecutionResult:
        if tool_name not in self.registry:
            raise ToolExecutionError(f"Tool {tool_name} is not registered.")

        spec = self.registry[tool_name]
        if "*" not in spec.allowed_stages and stage not in spec.allowed_stages:
            raise ToolExecutionError(f"Tool {tool_name} is not allowed in stage {stage}.")

        # Risk-policy gate: verify the tool is permitted under the current tolerance.
        if risk_tolerance:
            try:
                tolerance = RiskTolerance(risk_tolerance)
            except ValueError:
                tolerance = RiskTolerance.MODERATE
            policy = get_policy(tool_name, tolerance=tolerance)
            if policy.approval_required:
                raise ToolExecutionError(
                    f"Tool {tool_name} requires approval under risk tolerance "
                    f"{tolerance.value}."
                )

        validated = spec.input_model.model_validate(params)
        targets = self._extract_targets(validated)
        if targets:
            self.scope_guard.ensure_targets_allowed(targets, scope)

        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        artifact_dir = self.artifact_store.task_dir(task_id) / sanitize_filename(
            f"{timestamp}_{tool_name}"
        )
        artifact_dir.mkdir(parents=True, exist_ok=True)
        context = ToolContext(
            task_id=task_id,
            artifact_dir=artifact_dir,
            max_output_chars=self.settings.max_output_chars,
        )
        return spec.handler(validated, context)

    def describe_stage_tools(self, stage: str) -> list[dict[str, str | bool]]:
        return [
            {
                "name": spec.name,
                "description": spec.description,
                "risk_level": spec.risk_level,
                "approval_required": spec.approval_required,
            }
            for spec in self.registry.values()
            if stage in spec.allowed_stages
        ]

    def _extract_targets(self, validated: object) -> list[str]:
        if hasattr(validated, "targets"):
            return list(getattr(validated, "targets"))
        if hasattr(validated, "target"):
            return [str(getattr(validated, "target"))]
        return []
