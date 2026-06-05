from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

from app.agents.prompts import SYSTEM_PROMPT, build_planner_prompt, build_reflection_prompt
from app.core.llm_provider import LLMProvider
from app.core.risk_policy import get_policy
from app.schemas.tool import (
    AssetDiscoveryInput,
    DirEnumInput,
    FfufEnumInput,
    HeaderMutationInput,
    HttpGetInput,
    HttpRequestInput,
    HttpSnapshotInput,
    RawHttpInput,
    ServiceFingerprintInput,
    TcpSendInput,
    TemplateRunnerInput,
    VulnerabilityVerifyInput,
    WebProbeInput,
)
from app.services.exploit_knowledge_mapper import ExploitKnowledgeMapper
from app.services.knowledge_capture_service import KnowledgeCaptureService
from app.services.knowledge_retriever import KnowledgeRetriever


class PlanDecision(BaseModel):
    stage: str
    tool_name: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    rationale: str
    expected_evidence: list[str] = Field(default_factory=list)
    risk_level: str = "low"
    requires_approval: bool = False
    stop: bool = False
    stop_reason: str | None = None
    source: str = "heuristic"
    families: list[str] = Field(default_factory=list)
    family_details: list[dict[str, str]] = Field(default_factory=list)
    selected_family: str | None = None


class ReflectionDecision(BaseModel):
    summary: str
    hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    next_candidates: list[dict[str, Any]] = Field(default_factory=list)
    stop: bool = False
    stop_reason: str | None = None
    source: str = "heuristic"
    failure_class: str = "none"
    selected_family: str | None = None
    rejected_families: list[str] = Field(default_factory=list)
    family_switch_reason: str | None = None


class PlannerService:
    TOOL_PARAM_MODELS = {
        "asset_discovery": AssetDiscoveryInput,
        "service_fingerprint": ServiceFingerprintInput,
        "http_get": HttpGetInput,
        "http_request": HttpRequestInput,
        "web_probe": WebProbeInput,
        "dir_enum": DirEnumInput,
        "ffuf_enum": FfufEnumInput,
        "http_snapshot": HttpSnapshotInput,
        "template_runner": TemplateRunnerInput,
        "header_mutation": HeaderMutationInput,
        "raw_http": RawHttpInput,
        "tcp_send": TcpSendInput,
        "vuln_verify": VulnerabilityVerifyInput,
    }

    PORT_SERVICE_MAP: dict[int, tuple[str, str]] = {
        21: ("ftp_anon", "Check FTP anonymous login"),
        22: ("ssh_version", "Check SSH version and weak auth"),
        25: ("smtp_check", "Check SMTP open relay"),
        53: ("dns_check", "Check DNS zone transfer"),
        445: ("smb_enum", "Enumerate SMB shares"),
        1433: ("mssql_check", "Check MSSQL default credentials"),
        1521: ("oracle_check", "Check Oracle listener"),
        3306: ("mysql_check", "Check MySQL default credentials"),
        3389: ("rdp_check", "Check RDP connectivity"),
        5432: ("postgres_check", "Check PostgreSQL default credentials"),
        5900: ("vnc_check", "Check VNC authentication"),
        6379: ("redis_check", "Check Redis unauthorized access"),
        8080: ("web_probe", "Probe web service on common alt port"),
        8443: ("web_probe", "Probe HTTPS on common alt port"),
        27017: ("mongodb_check", "Check MongoDB unauthorized access"),
    }

    def __init__(
        self,
        *,
        deepseek_client: LLMProvider,
        exploit_mapper: ExploitKnowledgeMapper,
        knowledge_retriever: KnowledgeRetriever,
        knowledge_capture_service: KnowledgeCaptureService | None = None,
    ) -> None:
        self.deepseek_client = deepseek_client
        self.exploit_mapper = exploit_mapper
        self.knowledge_retriever = knowledge_retriever
        self.knowledge_capture_service = knowledge_capture_service

    def plan(self, state: dict[str, Any]) -> PlanDecision:
        return self.choose_action(state)

    def choose_action(self, state: dict[str, Any]) -> PlanDecision:
        heuristic_plan = self._heuristic_plan(state)
        query = self._build_knowledge_query(state)
        knowledge_hits = self.knowledge_retriever.search(query)
        reflection_candidates = self._normalized_reflection_candidates(state)
        learning_candidates = (
            [item.model_dump() for item in self.knowledge_capture_service.suggest(state)]
            if self.knowledge_capture_service
            else []
        )
        exploit_candidates = [item.model_dump() for item in self.exploit_mapper.suggest(state)]

        if self.deepseek_client.enabled and not heuristic_plan.stop:
            try:
                llm_plan = self.deepseek_client.invoke_structured(
                    PlanDecision,
                    SYSTEM_PROMPT,
                    build_planner_prompt(
                        state=state,
                        allowed_tools=self.allowed_tool_specs_for_stage(heuristic_plan.stage),
                        reflection_candidates=reflection_candidates,
                        knowledge_hits=knowledge_hits,
                        exploit_candidates=[*learning_candidates, *exploit_candidates],
                        heuristic_plan=heuristic_plan.model_dump(),
                    ),
                )
                validated = self._hydrate_plan_policy(self._validate_plan(llm_plan))
                validated.source = "llm"
                return validated
            except Exception as exc:
                logger.error("LLM plan failed, falling back to heuristic: %s", exc, exc_info=True)

        return self._hydrate_plan_policy(heuristic_plan)

    def reflect(self, state: dict[str, Any]) -> ReflectionDecision:
        heuristic = self._heuristic_reflection(state)
        query = self._build_knowledge_query(state)
        knowledge_hits = self.knowledge_retriever.search(query)
        learning_candidates = (
            [item.model_dump() for item in self.knowledge_capture_service.suggest(state)]
            if self.knowledge_capture_service
            else []
        )
        exploit_candidates = [*learning_candidates, *[item.model_dump() for item in self.exploit_mapper.suggest(state)]]

        if self.deepseek_client.enabled and state.get("last_result"):
            try:
                reflected = self.deepseek_client.invoke_structured(
                    ReflectionDecision,
                    SYSTEM_PROMPT,
                    build_reflection_prompt(
                        state=state,
                        knowledge_hits=knowledge_hits,
                        exploit_candidates=exploit_candidates,
                    ),
                )
                reflected.source = "llm"
                return reflected
            except Exception as exc:
                logger.error("LLM reflect failed, falling back to heuristic: %s", exc, exc_info=True)
        heuristic.next_candidates = self._prioritize_candidates(exploit_candidates)[:3]
        heuristic.source = "heuristic"
        return heuristic

    def allowed_tools_for_stage(self, stage: str) -> list[str]:
        if stage == "report":
            return ["report_tool"]
        return [
            "asset_discovery",
            "service_fingerprint",
            "http_get",
            "http_request",
            "web_probe",
            "dir_enum",
            "ffuf_enum",
            "http_snapshot",
            "template_runner",
            "header_mutation",
            "raw_http",
            "tcp_send",
            "vuln_verify",
        ]

    def allowed_tool_specs_for_stage(self, stage: str) -> list[dict[str, Any]]:
        specs = []
        for tool_name in self.allowed_tools_for_stage(stage):
            if tool_name == "report_tool":
                continue
            model = self.TOOL_PARAM_MODELS.get(tool_name)
            specs.append(
                {
                    "name": tool_name,
                    "risk_level": get_policy(tool_name).risk_level,
                    "approval_required": get_policy(tool_name).approval_required,
                    "params_schema": model.model_json_schema() if model else {},
                }
            )
        return specs

    # ── heuristic plan dispatcher ──────────────────────────────────────────

    def _heuristic_plan(self, state: dict[str, Any]) -> PlanDecision:
        """Cascade through stage-specific handlers, returning the first
        non-None PlanDecision.  Each sub-method returns None when its stage
        has nothing left to do and the dispatcher should try the next one."""

        approved_action = state.get("approved_action")
        if approved_action:
            return self._plan_from_approved_action(state, approved_action)

        result = self._heuristic_plan_asset_discovery(state)
        if result is not None:
            return result

        result = self._heuristic_plan_service_fingerprint(state)
        if result is not None:
            return result

        result = self._heuristic_plan_web_recon(state)
        if result is not None:
            return result

        result = self._heuristic_plan_exploit(state)
        if result is not None:
            return result

        return self._heuristic_plan_finalize(state)

    # ── stage-specific heuristic helpers ────────────────────────────────────

    def _plan_from_approved_action(
        self, state: dict[str, Any], approved_action: dict[str, Any]
    ) -> PlanDecision:
        tool_name = approved_action["tool_name"]
        policy = get_policy(tool_name)
        return PlanDecision(
            stage=state.get("current_stage", "exploit"),
            tool_name=tool_name,
            params=approved_action.get("params", {}),
            rationale="Resume the user-approved high-risk action.",
            expected_evidence=["Verification output and supporting evidence"],
            risk_level=policy.risk_level,
            requires_approval=False,
            source="approved_action",
            families=list(approved_action.get("families", [])),
            family_details=list(approved_action.get("family_details", [])),
            selected_family=approved_action.get("selected_family"),
        )

    def _heuristic_plan_asset_discovery(
        self, state: dict[str, Any]
    ) -> PlanDecision | None:
        hosts = state.get("hosts", [])
        actions = state.get("actions", [])

        if hosts:
            return None  # hosts already discovered, move to next stage

        if any(action.get("tool_name") == "asset_discovery" for action in actions):
            return PlanDecision(
                stage="generate_report",
                rationale="Host discovery already ran and did not reveal live hosts.",
                expected_evidence=["Final report"],
                stop=True,
                stop_reason="No live hosts were discovered inside the approved scope.",
            )
        return PlanDecision(
            stage="observe",
            tool_name="asset_discovery",
            params={"targets": state.get("scope", [])},
            rationale="Start with low-risk host discovery inside the approved scope.",
            expected_evidence=["List of live hosts"],
            risk_level="low",
        )

    def _heuristic_plan_service_fingerprint(
        self, state: dict[str, Any]
    ) -> PlanDecision | None:
        hosts = state.get("hosts", [])
        services = state.get("services", [])
        actions = state.get("actions", [])

        fingerprinted_targets = {service["target"] for service in services} | {
            action.get("params", {}).get("target")
            for action in actions
            if action.get("tool_name") == "service_fingerprint"
        }
        next_host = next(
            (host["address"] for host in hosts if host["address"] not in fingerprinted_targets),
            None,
        )
        if next_host:
            return PlanDecision(
                stage="observe",
                tool_name="service_fingerprint",
                params={"target": next_host, "port_spec": state.get("ports")},
                rationale="Fingerprint reachable services on the newly discovered host.",
                expected_evidence=["Open ports and service banners"],
                risk_level="low",
            )
        return None

    def _heuristic_plan_web_recon(self, state: dict[str, Any]) -> PlanDecision | None:
        services = state.get("services", [])
        evidence = state.get("evidence", [])
        actions = state.get("actions", [])

        web_services = [service for service in services if self._is_web_service(service)]

        # ── HTTP GET baseline probe ─────────────────────────────────────────
        probed_endpoints = {
            (item.get("target"), item.get("port"))
            for item in evidence
            if item.get("kind") in {"web_probe", "http_get", "http_request"}
        } | {
            (
                action.get("params", {}).get("target"),
                action.get("params", {}).get("port"),
            )
            for action in actions
            if action.get("tool_name") in {"web_probe", "http_get", "http_request"}
        }
        next_web_service = next(
            (
                service
                for service in web_services
                if (service["target"], service["port"]) not in probed_endpoints
            ),
            None,
        )
        if next_web_service:
            scheme = "https" if next_web_service["port"] in {443, 8443} else "http"
            return PlanDecision(
                stage="observe",
                tool_name="http_get",
                params={
                    "target": next_web_service["target"],
                    "port": next_web_service["port"],
                    "scheme": scheme,
                    "path": "/",
                    "headers": {},
                },
                rationale="Collect a baseline HTTP response before branching into exploit or enumeration actions.",
                expected_evidence=["HTTP status, title, headers, and response snippet"],
                risk_level="low",
            )

        # ── Safe RPC probe ──────────────────────────────────────────────────
        safe_rpc_probe = self._build_safe_rpc_probe_plan(state, web_services)
        if safe_rpc_probe is not None:
            return safe_rpc_probe

        # ── Directory enumeration ───────────────────────────────────────────
        enumerated_endpoints = {
            (item.get("target"), item.get("port"))
            for item in evidence
            if item.get("kind") == "dir_enum"
        } | {
            (
                action.get("params", {}).get("target"),
                action.get("params", {}).get("port"),
            )
            for action in actions
            if action.get("tool_name") == "dir_enum"
        }
        next_enum_target = next(
            (
                service
                for service in web_services
                if not self._is_json_rpc_candidate(state, service)
                if (service["target"], service["port"]) not in enumerated_endpoints
            ),
            None,
        )
        if next_enum_target:
            scheme = "https" if next_enum_target["port"] in {443, 8443} else "http"
            return PlanDecision(
                stage="enumerate",
                tool_name="dir_enum",
                params={
                    "target": next_enum_target["target"],
                    "port": next_enum_target["port"],
                    "scheme": scheme,
                    "max_paths": 12,
                },
                rationale="Run a bounded directory check to validate common exposure patterns.",
                expected_evidence=["Interesting paths, status codes, and access signals"],
                risk_level="medium",
            )

        # ── FFUF enumeration ────────────────────────────────────────────────
        ffuf_targets = {
            (item.get("target"), item.get("port"))
            for item in evidence
            if item.get("kind") == "ffuf_enum"
        } | {
            (
                action.get("params", {}).get("target"),
                action.get("params", {}).get("port"),
            )
            for action in actions
            if action.get("tool_name") == "ffuf_enum"
        }
        next_ffuf_target = next(
            (
                service
                for service in web_services
                if not self._is_json_rpc_candidate(state, service)
                if (service["target"], service["port"]) not in ffuf_targets
            ),
            None,
        )
        if next_ffuf_target:
            scheme = "https" if next_ffuf_target["port"] in {443, 8443} else "http"
            return PlanDecision(
                stage="enumerate",
                tool_name="ffuf_enum",
                params={
                    "target": next_ffuf_target["target"],
                    "port": next_ffuf_target["port"],
                    "scheme": scheme,
                    "words": [
                        "admin",
                        "login",
                        "dashboard",
                        "robots.txt",
                        "api",
                        "uploads",
                        "test",
                        "dev",
                        "backup.zip",
                        "phpinfo.php",
                    ],
                    "timeout": 45,
                    "rate": 4,
                },
                rationale="Run a tiny ffuf pass to uncover obvious content gaps that the fixed path list may miss.",
                expected_evidence=["Additional interesting paths and response patterns"],
                risk_level="medium",
            )

        # ── HTTP snapshot ───────────────────────────────────────────────────
        snapshotted_targets = {
            (item.get("target"), item.get("port"))
            for item in evidence
            if item.get("kind") == "http_snapshot"
        } | {
            (
                action.get("params", {}).get("target"),
                action.get("params", {}).get("port"),
            )
            for action in actions
            if action.get("tool_name") == "http_snapshot"
        }
        next_snapshot_target = next(
            (
                service
                for service in web_services
                if not self._is_json_rpc_candidate(state, service)
                if (service["target"], service["port"]) not in snapshotted_targets
            ),
            None,
        )
        if next_snapshot_target:
            scheme = "https" if next_snapshot_target["port"] in {443, 8443} else "http"
            return PlanDecision(
                stage="observe",
                tool_name="http_snapshot",
                params={
                    "target": next_snapshot_target["target"],
                    "port": next_snapshot_target["port"],
                    "scheme": scheme,
                    "paths": self._build_snapshot_paths(state, next_snapshot_target),
                },
                rationale="Capture short body snippets for the most interesting paths before escalating to high-risk verification.",
                expected_evidence=["Response snippets, redirects, and concrete content clues"],
                risk_level="low",
            )

        # ── Template scanner ────────────────────────────────────────────────
        template_scanned_targets = {
            (
                action.get("tool_name"),
                action.get("params", {}).get("target"),
                action.get("params", {}).get("port"),
                action.get("params", {}).get("template"),
            )
            for action in actions
            if action.get("tool_name") == "template_runner"
        }
        next_verify_target = next(
            (
                service
                for service in web_services
                if (
                    "template_runner",
                    service["target"],
                    service["port"],
                    "nikto_scan",
                )
                not in template_scanned_targets
                and self._has_meaningful_web_evidence(state, service)
                and self._guess_verify_profile(state, service) != "json_rpc"
            ),
            None,
        )
        if next_verify_target:
            return PlanDecision(
                stage="observe",
                tool_name="template_runner",
                params={
                    "target": next_verify_target["target"],
                    "port": next_verify_target["port"],
                    "scheme": "https" if next_verify_target["port"] in {443, 8443} else "http",
                    "template": "nikto_scan",
                    "timeout": 30,
                },
                rationale="Run a bounded scanner template to enrich exploit hypotheses before choosing a concrete exploit primitive.",
                expected_evidence=["Additional observations and version-specific clues"],
                risk_level="medium",
            )

        return None  # nothing more to do in web recon, fall through to exploit

    def _heuristic_plan_exploit(self, state: dict[str, Any]) -> PlanDecision | None:
        services = state.get("services", [])

        reflection_candidates = self._normalized_reflection_candidates(state)
        learning_candidates = (
            [
                item.model_dump() if hasattr(item, "model_dump") else item
                for item in self.knowledge_capture_service.suggest(state)
            ]
            if self.knowledge_capture_service
            else []
        )
        exploit_candidates = self.exploit_mapper.suggest(state)

        # ── Reflection candidates take highest priority ──────────────────────
        if reflection_candidates:
            candidate = reflection_candidates[0]
            return PlanDecision(
                stage=str(candidate.get("stage", "exploit")),
                tool_name=str(candidate.get("tool_name")),
                params=dict(candidate.get("params", {})),
                rationale=str(candidate.get("rationale", "Reflection identified a refined next exploit action.")),
                expected_evidence=[str(item) for item in candidate.get("expected_evidence", [])],
                risk_level=str(candidate.get("risk_level", "high")),
                requires_approval=bool(candidate.get("requires_approval", True)),
                source=str(candidate.get("source", "reflection")),
                families=list(candidate.get("families", [])),
                family_details=list(candidate.get("family_details", [])),
                selected_family=candidate.get("selected_family"),
            )

        # ── Learning candidates ─────────────────────────────────────────────
        if learning_candidates:
            candidate = learning_candidates[0]
            return PlanDecision(
                stage=str(candidate.get("stage", "exploit")),
                tool_name=str(candidate.get("tool_name")),
                params=dict(candidate.get("params", {})),
                rationale=str(candidate.get("rationale", "Reviewed learning candidate selected.")),
                expected_evidence=[str(item) for item in candidate.get("expected_evidence", [])],
                risk_level=str(candidate.get("risk_level", "medium")),
                requires_approval=bool(candidate.get("requires_approval", False)),
                source=str(candidate.get("source", "learning")),
                families=list(candidate.get("families", [])),
                family_details=list(candidate.get("family_details", [])),
                selected_family=candidate.get("selected_family"),
            )

        # ── Exploit mapper candidates ───────────────────────────────────────
        if exploit_candidates:
            candidate = exploit_candidates[0]
            return PlanDecision(
                stage="exploit",
                tool_name=candidate.tool_name,
                params=candidate.params,
                rationale=candidate.rationale,
                expected_evidence=candidate.expected_evidence,
                risk_level=candidate.risk_level,
                requires_approval=candidate.requires_approval,
                source="mapper",
                families=list(candidate.families),
                family_details=list(candidate.family_details),
                selected_family=candidate.selected_family,
            )

        # ── Vulnerability verification ──────────────────────────────────────
        web_services = [service for service in services if self._is_web_service(service)]
        next_verify_target = next(
            (
                service
                for service in web_services
                if self._should_run_generic_verifier(state, service)
            ),
            None,
        )
        if next_verify_target:
            profile = self._guess_verify_profile(state, next_verify_target)
            return PlanDecision(
                stage="exploit",
                tool_name="vuln_verify",
                params=self._build_verify_params(state, next_verify_target),
                rationale=(
                    "Observation completed with enough structured evidence to run a controlled verifier."
                    if profile != "json_rpc"
                    else "JSON-RPC interaction indicators are strong enough to justify a controlled verifier for unauthorized method access."
                ),
                expected_evidence=(
                    ["Verification status, findings, and concrete PoC evidence"]
                    if profile != "json_rpc"
                    else ["Evidence that safe JSON-RPC methods can or cannot be invoked without authentication"]
                ),
                risk_level="high",
                requires_approval=True,
            )

        return None

    def _heuristic_plan_finalize(self, state: dict[str, Any]) -> PlanDecision:
        services = state.get("services", [])
        actions = state.get("actions", [])
        web_services = [service for service in services if self._is_web_service(service)]

        if web_services and not any(
            action.get("tool_name") in {"header_mutation", "raw_http", "tcp_send", "vuln_verify", "http_request"}
            for action in actions
        ):
            return PlanDecision(
                stage="report",
                rationale="Observation and enumeration completed, but they did not produce enough evidence to justify a concrete exploit action.",
                expected_evidence=["Final report"],
                stop=True,
                stop_reason="Observation completed without a justified exploit action.",
            )

        return PlanDecision(
            stage="report",
            rationale="The bounded action loop completed and no higher-value next action remains.",
            expected_evidence=["Final report"],
            stop=True,
            stop_reason="No further safe actions are pending.",
        )

    # ── reflection helpers ──────────────────────────────────────────────────

    def _heuristic_reflection(self, state: dict[str, Any]) -> ReflectionDecision:
        last_result = state.get("last_result") or {}
        if not last_result:
            return ReflectionDecision(summary="No tool result is available to reflect on.")

        summary = str(last_result.get("summary") or state.get("last_summary") or "No summary.")
        tool_name = str(last_result.get("tool_name", "unknown"))
        structured = last_result.get("structured_data", {}) or {}
        hypotheses: list[dict[str, Any]] = []
        next_candidates: list[dict[str, Any]] = []
        failure_class = self._classify_failure(state, last_result)
        previous_family = str((state.get("last_decision") or {}).get("selected_family") or "") or None

        if tool_name == "http_get":
            body_snippet = str(structured.get("body_snippet", ""))
            if "404" in body_snippet:
                hypotheses.append(
                    {
                        "title": "Default path may be unhelpful; try protocol mutation or targeted exploit paths",
                        "rationale": "The base path only returned a generic 404 response.",
                        "severity": "medium",
                        "status": "unverified",
                    }
                )

        if tool_name == "http_request":
            path = str(structured.get("path", ""))
            body_snippet = str(structured.get("body_snippet", "")).lower()
            status_code = int(structured.get("status_code", 0) or 0)
            if path in {"/jsonrpc", "/rpc", "/api/jsonrpc"}:
                if "no such method" in body_snippet:
                    hypotheses.append(
                        {
                            "title": "The RPC endpoint is reachable, but the method name is incorrect",
                            "rationale": "A structured method-not-found response proves the endpoint exists and parsed the request.",
                            "severity": "medium",
                            "status": "partially_verified",
                        }
                    )
                    service = (state.get("services") or [{}])[0]
                    next_candidates.append(
                        {
                            "tool_name": "http_request",
                            "stage": "enumerate",
                            "params": {
                                "target": service.get("target", state.get("scope", [""])[0]),
                                "port": service.get("port", int(str(state.get("ports", "0")).split(",")[0].split("-")[0] or 0)),
                                "scheme": "https" if int(service.get("port", 0) or 0) in {443, 8443} else "http",
                                "path": path,
                                "method": "POST",
                                "headers": {"Content-Type": "application/json"},
                                "body": self._build_safe_rpc_probe_body(service),
                                "allow_redirects": False,
                                "timeout": 15,
                            },
                            "rationale": "Retry the reachable RPC endpoint with a safer service-aware capability method.",
                            "expected_evidence": ["A structured JSON-RPC result or a clearer authorization/error signal"],
                            "source": "reflection",
                        }
                    )
                elif status_code == 200 and "\"result\"" in body_snippet:
                    hypotheses.append(
                        {
                            "title": "The RPC endpoint accepted a safe method call without authentication",
                            "rationale": "A JSON-RPC result object indicates the endpoint is both reachable and actionable.",
                            "severity": "high",
                            "status": "verified",
                        }
                    )
                    service = (state.get("services") or [{}])[0]
                    next_candidates.append(
                        {
                            "tool_name": "vuln_verify",
                            "stage": "exploit",
                            "params": self._build_verify_params(state, service),
                            "rationale": "Use the controlled verifier to consolidate unauthorized RPC evidence into structured findings and PoC output.",
                            "expected_evidence": ["Structured verification status, findings, and safe PoC evidence"],
                            "source": "reflection",
                        }
                    )

        if tool_name in {"header_mutation", "raw_http", "vuln_verify"}:
            status_code = int(structured.get("status_code", 0) or 0)
            body_preview = str(structured.get("body_preview", "")).lower()
            raw_response = str(structured.get("raw_response", "")).lower()
            if status_code in {400, 403, 404}:
                title = {
                    400: "Exploit syntax may be wrong; adjust request shape or protocol details",
                    403: "Exploit path may be correct but blocked; try a lower-level primitive or alternate header shape",
                    404: "Exploit target may require a different path construction or virtual-host behavior",
                }[status_code]
                rationale = {
                    400: "The server rejected the exploit request as malformed, which suggests the primitive should be retried with a different HTTP shape.",
                    403: "The server understood the request but refused it, so the current exploit formulation may be blocked rather than invalid.",
                    404: "The server handled the request but did not resolve the targeted resource, so another exploit path should be attempted.",
                }[status_code]
                hypotheses.append(
                    {
                        "title": title,
                        "rationale": rationale,
                        "severity": "medium",
                        "status": "unverified",
                    }
                )
            if "can't parse request" in body_preview or "can't parse request" in raw_response:
                hypotheses.append(
                    {
                        "title": "The exploit likely needs a more standards-compliant request line or header layout",
                        "rationale": "The target reported that it could not parse the request, so a raw primitive should be retried with cleaner syntax.",
                        "severity": "medium",
                        "status": "unverified",
                    }
                )

        selected_family = None
        rejected_families: list[str] = []
        family_switch_reason = None
        candidate_models = self._prioritize_candidates([item.model_dump() for item in self.exploit_mapper.suggest(state)])
        if candidate_models:
            next_candidates = self._prioritize_candidates([*next_candidates, *candidate_models])[:3]
        if next_candidates:
            selected_family = next_candidates[0].get("selected_family")
            if previous_family and selected_family and previous_family != selected_family:
                rejected_families = [previous_family]
                family_switch_reason = (
                    f"Previous family `{previous_family}` produced failure class `{failure_class}`; "
                    f"switch to `{selected_family}` for the next exploit attempt."
                )
            elif previous_family and selected_family == previous_family:
                family_switch_reason = (
                    f"Failure class `{failure_class}` still favors the same family `{selected_family}`, "
                    "but with a more refined primitive or request shape."
                )

        return ReflectionDecision(
            summary=summary,
            hypotheses=hypotheses,
            next_candidates=next_candidates,
            failure_class=failure_class,
            selected_family=selected_family,
            rejected_families=rejected_families,
            family_switch_reason=family_switch_reason,
        )

    def _normalized_reflection_candidates(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        reflection = state.get("last_reflection") or {}
        candidates = reflection.get("next_candidates", [])
        normalized: list[dict[str, Any]] = []
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            tool_name = candidate.get("tool_name")
            if not tool_name:
                continue
            try:
                tool_name, params = self._normalize_candidate_tool(tool_name, candidate.get("params", {}))
                plan = PlanDecision.model_validate(
                    {
                        "stage": candidate.get("stage", "exploit"),
                        "tool_name": tool_name,
                        "params": params,
                        "rationale": candidate.get("rationale", "Reflection-proposed candidate."),
                        "expected_evidence": candidate.get("expected_evidence", []),
                        "risk_level": candidate.get("risk_level", "high"),
                        "requires_approval": candidate.get("requires_approval", True),
                        "stop": False,
                        "source": candidate.get("source", "reflection"),
                        "families": candidate.get("families", []),
                        "family_details": candidate.get("family_details", []),
                        "selected_family": candidate.get("selected_family"),
                    }
                )
                validated = self._hydrate_plan_policy(self._validate_plan(plan))
                normalized.append(validated.model_dump())
            except Exception:
                continue
        return self._prioritize_candidates(normalized)

    def _prioritize_candidates(self, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        def priority(item: dict[str, Any]) -> tuple:
            source = str(item.get("source", ""))
            return (
                0 if source in {"reflection", "corpus_reflection", "llm_reflection"} else 1 if source == "learning" else 2,
                1 if bool(item.get("fallback_only", False)) else 0,
                0 if str(item.get("confidence", "")) == "high" else 1,
                str(item.get("title", "")),
            )

        return sorted(candidates, key=priority)

    def _classify_failure(self, state: dict[str, Any], last_result: dict[str, Any]) -> str:
        if not last_result:
            return "none"
        summary = str(last_result.get("summary", "")).lower()
        error = str(last_result.get("error", "")).lower()
        structured = last_result.get("structured_data", {}) or {}
        status_code = int(structured.get("status_code", 0) or 0)
        headers = {str(k).lower(): str(v) for k, v in (structured.get("headers") or {}).items()}
        location = headers.get("location", "")
        body_preview = str(structured.get("body_preview", "")).lower()
        raw_response = str(structured.get("raw_response", "")).lower()

        if "timed out" in summary or "timed out" in error:
            return "timeout"
        if 300 <= status_code < 400 or location:
            return "unexpected_redirect"
        if status_code == 403:
            return "blocked_request"
        if status_code == 404:
            return "target_not_found"
        if "no such method" in body_preview or "no such method" in raw_response:
            return "method_not_found"
        if status_code == 400 or "can't parse request" in body_preview or "can't parse request" in raw_response:
            return "parse_failure"
        return "none"

    def _build_knowledge_query(self, state: dict[str, Any]) -> str:
        service_names = " ".join(
            f"{service.get('service', '')} {service.get('product', '')}"
            for service in state.get("services", [])
        )
        return f"{state.get('objective', '')} {service_names}".strip()

    def _validate_plan(self, plan: PlanDecision) -> PlanDecision:
        if plan.stop:
            return plan
        if not plan.tool_name:
            raise ValueError("Planner returned a non-stop action without a tool name.")
        plan = self._coerce_plan(plan)
        allowed = self.allowed_tools_for_stage(plan.stage)
        if plan.tool_name not in allowed:
            raise ValueError(f"Tool {plan.tool_name} is not allowed in stage {plan.stage}.")
        model = self.TOOL_PARAM_MODELS.get(plan.tool_name)
        if model is not None:
            validated_params = model.model_validate(plan.params)
            plan.params = validated_params.model_dump()
        return plan

    def _hydrate_plan_policy(self, plan: PlanDecision) -> PlanDecision:
        if plan.stop or not plan.tool_name:
            return plan
        policy = get_policy(plan.tool_name)
        plan.risk_level = policy.risk_level
        plan.requires_approval = policy.approval_required
        if plan.tool_name == "http_request":
            method = str(plan.params.get("method", "GET")).upper()
            if method in {"GET", "HEAD", "OPTIONS"}:
                plan.risk_level = "low"
                plan.requires_approval = False
            elif plan.stage == "exploit":
                plan.risk_level = "high"
                plan.requires_approval = True
            else:
                plan.risk_level = "medium"
                plan.requires_approval = False
        logger.info(
            "Plan decision: tool=%s stage=%s risk=%s approval=%s",
            plan.tool_name, plan.stage, plan.risk_level, plan.requires_approval,
        )
        return plan

    def _normalize_candidate_tool(self, tool_name: str, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        alias = tool_name.lower()
        if alias in {"http_post", "http_head", "http_options"}:
            method = {
                "http_post": "POST",
                "http_head": "HEAD",
                "http_options": "OPTIONS",
            }[alias]
            updated = dict(params)
            updated["method"] = method
            return "http_request", updated
        return tool_name, params

    def _coerce_plan(self, plan: PlanDecision) -> PlanDecision:
        if plan.tool_name != "raw_http" or plan.stage == "exploit":
            return plan
        parsed = self._parse_standard_http_request(plan.params)
        if not parsed:
            return plan
        return PlanDecision(
            stage=plan.stage,
            tool_name="http_request",
            params=parsed,
            rationale=plan.rationale,
            expected_evidence=plan.expected_evidence,
            risk_level=plan.risk_level,
            requires_approval=plan.requires_approval,
            stop=plan.stop,
            stop_reason=plan.stop_reason,
            source=plan.source,
            families=plan.families,
            family_details=plan.family_details,
            selected_family=plan.selected_family,
        )

    def _parse_standard_http_request(self, params: dict[str, Any]) -> dict[str, Any] | None:
        request = str(params.get("request", ""))
        if not request:
            return None
        lines = request.split("\r\n")
        if len(lines) < 2:
            return None
        request_line = lines[0].split()
        if len(request_line) != 3:
            return None
        method, path, protocol = request_line
        if method not in {"GET", "HEAD", "OPTIONS", "POST"}:
            return None
        if protocol not in {"HTTP/1.0", "HTTP/1.1"} or not path.startswith("/"):
            return None
        headers: dict[str, str] = {}
        body_lines: list[str] = []
        in_body = False
        for line in lines[1:]:
            if in_body:
                body_lines.append(line)
                continue
            if line == "":
                in_body = True
                continue
            if ":" not in line:
                return None
            key, value = line.split(":", 1)
            header_name = key.strip()
            header_value = value.strip()
            if header_name.lower() == "host" and not header_value:
                return None
            headers[header_name] = header_value
        scheme = "https" if int(params.get("port", 0) or 0) in {443, 8443} else "http"
        return {
            "target": params.get("target"),
            "port": params.get("port"),
            "scheme": scheme,
            "path": path,
            "method": method,
            "headers": headers,
            "body": "\r\n".join(body_lines),
            "allow_redirects": method != "POST",
            "timeout": params.get("timeout", 15),
        }

    def _is_web_service(self, service: dict[str, Any]) -> bool:
        name = str(service.get("service", "")).lower()
        port = int(service.get("port", 0))
        return "http" in name or port in {80, 443, 3000, 4173, 5000, 5173, 8000, 8080, 8443}

    def _build_snapshot_paths(self, state: dict[str, Any], service: dict[str, Any]) -> list[str]:
        target = service["target"]
        port = service["port"]
        interesting_paths: list[str] = []
        for item in state.get("evidence", []):
            if item.get("target") != target or item.get("port") != port:
                continue
            if item.get("kind") not in {"dir_enum", "ffuf_enum"}:
                continue
            path = item.get("data", {}).get("path")
            if isinstance(path, str) and path not in interesting_paths:
                interesting_paths.append(path)

        if "/" not in interesting_paths:
            interesting_paths.insert(0, "/")
        return interesting_paths[:4]

    def _has_meaningful_web_evidence(self, state: dict[str, Any], service: dict[str, Any]) -> bool:
        target = service["target"]
        port = service["port"]
        product = str(service.get("product", "")).lower()
        service_name = str(service.get("service", "")).lower()
        lab_description = str(state.get("lab_description", "")).lower()

        # Some lab vulnerabilities are actionable from the banner/profile alone, even if
        # the default path only returns 404. mini_httpd in Vulhub is one such case.
        if "mini_httpd" in product or "mini_httpd" in service_name or "mini_httpd" in lab_description:
            return True

        for item in state.get("evidence", []):
            if item.get("target") != target or item.get("port") != port:
                continue
            if item.get("kind") in {"dir_enum", "ffuf_enum"}:
                return True
            if item.get("kind") == "web_probe":
                status_code = int(item.get("data", {}).get("status_code", 0))
                title = str(item.get("data", {}).get("title", "")).strip()
                if status_code < 400 or (title and "404" not in title.lower()):
                    return True
            if item.get("kind") == "http_snapshot":
                snapshot = item.get("data", {})
                status_code = int(snapshot.get("status_code", 0))
                body_snippet = str(snapshot.get("body_snippet", "")).strip()
                if status_code < 400:
                    return True
                lowered_snippet = body_snippet.lower()
                if body_snippet and "404" not in lowered_snippet and "not found" not in lowered_snippet:
                    return True
            if item.get("kind") in {"http_get", "http_request"}:
                status_code = int(item.get("data", {}).get("status_code", 0))
                path = str(item.get("data", {}).get("path", ""))
                if path in {"/jsonrpc", "/rpc", "/api/jsonrpc"} and status_code in {200, 400, 401, 403, 405, 500}:
                    return True
        return False

    def _build_safe_rpc_probe_plan(
        self,
        state: dict[str, Any],
        web_services: list[dict[str, Any]],
    ) -> PlanDecision | None:
        observed_rpc_requests = {
            (
                action.get("tool_name"),
                action.get("params", {}).get("target"),
                action.get("params", {}).get("port"),
                action.get("params", {}).get("path"),
                action.get("params", {}).get("method"),
            )
            for action in state.get("actions", [])
            if action.get("tool_name") in {"http_request", "http_get"}
        }
        for service in web_services:
            rpc_path = self._guess_rpc_path(state, service)
            if not rpc_path or not self._is_json_rpc_candidate(state, service):
                continue
            marker = ("http_request", service["target"], service["port"], rpc_path, "POST")
            if marker in observed_rpc_requests:
                continue
            body = self._build_safe_rpc_probe_body(service)
            return PlanDecision(
                stage="enumerate",
                tool_name="http_request",
                params={
                    "target": service["target"],
                    "port": service["port"],
                    "scheme": "https" if service["port"] in {443, 8443} else "http",
                    "path": rpc_path,
                    "method": "POST",
                    "headers": {"Content-Type": "application/json"},
                    "body": body,
                    "allow_redirects": False,
                    "timeout": 15,
                },
                rationale="A discovered RPC-like endpoint warrants one safe structured capability probe before exploit-specific validation.",
                expected_evidence=["HTTP status and JSON-RPC response proving whether the endpoint accepts unauthenticated method calls"],
                risk_level="medium",
                requires_approval=False,
            )
        return None

    def _should_run_generic_verifier(self, state: dict[str, Any], service: dict[str, Any]) -> bool:
        if not self._has_meaningful_web_evidence(state, service):
            return False
        target = service["target"]
        port = service["port"]
        for action in state.get("actions", []):
            if action.get("tool_name") != "vuln_verify":
                continue
            params = action.get("params", {})
            if params.get("target") == target and int(params.get("port", 0) or 0) == port:
                return False
        profile = self._guess_verify_profile(state, service)
        if profile == "generic_web":
            return False
        return True

    def _build_verify_params(self, state: dict[str, Any], service: dict[str, Any]) -> dict[str, Any]:
        profile = self._guess_verify_profile(state, service)
        scheme = "https" if service["port"] in {443, 8443} else "http"
        headers = self._collect_headers(state, service)
        return {
            "target": service["target"],
            "port": service["port"],
            "scheme": scheme,
            "profile": profile,
            "preferred_poc": "dvwa_fi" if profile == "php_apache" and self._looks_like_dvwa(state, service) else "none",
            "service_name": str(service.get("service", "")),
            "service_product": str(service.get("product", "")),
            "service_version": str(service.get("version", "")),
            "lab_description": str(state.get("lab_description", "")),
            "page_title": self._collect_page_title(state, service),
            "headers": headers,
            "interesting_paths": self._collect_interesting_paths(state, service),
            "timeout": 45 if profile == "php_apache" else 30 if profile in {"mini_httpd", "json_rpc"} else 60,
        }

    def _guess_verify_profile(self, state: dict[str, Any], service: dict[str, Any]) -> str:
        title = self._collect_page_title(state, service).lower()
        lab_description = str(state.get("lab_description", "")).lower()
        product = str(service.get("product", "")).lower()
        service_name = str(service.get("service", "")).lower()
        headers = " ".join(self._collect_headers(state, service).values()).lower()
        interesting_paths = " ".join(self._collect_interesting_paths(state, service)).lower()

        if "mini_httpd" in product or "mini_httpd" in service_name or "mini_httpd" in lab_description:
            return "mini_httpd"
        if self._looks_like_dvwa(state, service):
            return "php_apache"
        if "apache" in product and "php" in headers:
            return "php_apache"
        if any(marker in interesting_paths for marker in ["/login.php", "/setup.php", "/phpinfo.php"]):
            return "php_apache"
        if self._is_json_rpc_candidate(state, service):
            return "json_rpc"
        return "generic_web"

    def _collect_page_title(self, state: dict[str, Any], service: dict[str, Any]) -> str:
        target = service["target"]
        port = service["port"]
        for item in state.get("evidence", []):
            if item.get("target") != target or item.get("port") != port:
                continue
            if item.get("kind") == "web_probe":
                title = str(item.get("data", {}).get("title", "")).strip()
                if title:
                    return title
        return ""

    def _collect_headers(self, state: dict[str, Any], service: dict[str, Any]) -> dict[str, str]:
        target = service["target"]
        port = service["port"]
        for item in state.get("evidence", []):
            if item.get("target") != target or item.get("port") != port:
                continue
            if item.get("kind") == "web_probe":
                headers = item.get("data", {}).get("headers", {})
                if isinstance(headers, dict):
                    return {str(key): str(value) for key, value in headers.items()}
        return {}

    def _collect_interesting_paths(self, state: dict[str, Any], service: dict[str, Any]) -> list[str]:
        target = service["target"]
        port = service["port"]
        paths: list[str] = []
        for item in state.get("evidence", []):
            if item.get("target") != target or item.get("port") != port:
                continue
            if item.get("kind") not in {"dir_enum", "ffuf_enum"}:
                continue
            path = item.get("data", {}).get("path")
            if isinstance(path, str) and path not in paths:
                paths.append(path)
        return paths[:8]

    def _is_json_rpc_candidate(self, state: dict[str, Any], service: dict[str, Any]) -> bool:
        service_text = " ".join(
            [
                str(service.get("service", "")),
                str(service.get("product", "")),
                str(service.get("version", "")),
                str(state.get("lab_description", "")),
            ]
        ).lower()
        if any(marker in service_text for marker in ["json-rpc", "json rpc", "xml-rpc", "aria2", "rpc"]):
            return True
        target = service["target"]
        port = service["port"]
        for item in state.get("evidence", []):
            if item.get("target") != target or item.get("port") != port:
                continue
            if item.get("kind") not in {"http_get", "http_request"}:
                continue
            path = str(item.get("data", {}).get("path", ""))
            status_code = int(item.get("data", {}).get("status_code", 0))
            body_snippet = str(item.get("data", {}).get("body_snippet", "")).lower()
            if path in {"/jsonrpc", "/rpc", "/api/jsonrpc"} and status_code in {200, 400, 401, 403, 405}:
                return True
            if "json-rpc" in body_snippet or "invalid request" in body_snippet:
                return True
        return False

    def _guess_rpc_path(self, state: dict[str, Any], service: dict[str, Any]) -> str | None:
        interesting_paths = self._collect_interesting_paths(state, service)
        for path in interesting_paths:
            if path in {"/jsonrpc", "/rpc", "/api/jsonrpc"}:
                return path
        target = service["target"]
        port = service["port"]
        for item in state.get("evidence", []):
            if item.get("target") != target or item.get("port") != port:
                continue
            path = str(item.get("data", {}).get("path", ""))
            if path in {"/jsonrpc", "/rpc", "/api/jsonrpc"}:
                return path
        service_text = " ".join(
            [
                str(service.get("service", "")),
                str(service.get("product", "")),
                str(service.get("version", "")),
                str(state.get("lab_description", "")),
            ]
        ).lower()
        if "aria2" in service_text:
            return "/jsonrpc"
        if "json-rpc" in service_text or "json rpc" in service_text:
            return "/jsonrpc"
        if "xml-rpc" in service_text:
            return "/rpc"
        return None

    def _build_safe_rpc_probe_body(self, service: dict[str, Any]) -> str:
        service_text = " ".join(
            [
                str(service.get("service", "")),
                str(service.get("product", "")),
                str(service.get("version", "")),
            ]
        ).lower()
        if "aria2" in service_text:
            return '{"jsonrpc":"2.0","id":1,"method":"aria2.getVersion","params":[]}'
        return '{"jsonrpc":"2.0","id":1,"method":"rpc.discover","params":[]}'

    def _looks_like_dvwa(self, state: dict[str, Any], service: dict[str, Any]) -> bool:
        title = self._collect_page_title(state, service).lower()
        lab_description = str(state.get("lab_description", "")).lower()
        interesting_paths = " ".join(self._collect_interesting_paths(state, service)).lower()
        return (
            "dvwa" in title
            or "dvwa" in lab_description
            or "/login.php" in interesting_paths
            or "/setup.php" in interesting_paths
        )
