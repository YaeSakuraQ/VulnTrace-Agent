from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.agents.prompts import SYSTEM_PROMPT, build_planner_prompt, build_reflection_prompt
from app.core.risk_policy import get_policy
from app.schemas.tool import (
    AssetDiscoveryInput,
    DirEnumInput,
    FfufEnumInput,
    HeaderMutationInput,
    HttpGetInput,
    HttpSnapshotInput,
    RawHttpInput,
    ServiceFingerprintInput,
    TcpSendInput,
    TemplateRunnerInput,
    VulnerabilityVerifyInput,
    WebProbeInput,
)
from app.services.exploit_knowledge_mapper import ExploitKnowledgeMapper
from app.services.deepseek_client import DeepSeekClient
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

    def __init__(
        self,
        *,
        deepseek_client: DeepSeekClient,
        exploit_mapper: ExploitKnowledgeMapper,
        knowledge_retriever: KnowledgeRetriever,
    ) -> None:
        self.deepseek_client = deepseek_client
        self.exploit_mapper = exploit_mapper
        self.knowledge_retriever = knowledge_retriever

    def plan(self, state: dict[str, Any]) -> PlanDecision:
        return self.choose_action(state)

    def choose_action(self, state: dict[str, Any]) -> PlanDecision:
        heuristic_plan = self._heuristic_plan(state)
        query = self._build_knowledge_query(state)
        knowledge_hits = self.knowledge_retriever.search(query)
        reflection_candidates = self._normalized_reflection_candidates(state)
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
                        exploit_candidates=exploit_candidates,
                        heuristic_plan=heuristic_plan.model_dump(),
                    ),
                )
                validated = self._validate_plan(llm_plan)
                validated.risk_level = get_policy(validated.tool_name).risk_level if validated.tool_name else validated.risk_level
                validated.requires_approval = (
                    get_policy(validated.tool_name).approval_required if validated.tool_name else False
                )
                validated.source = "llm"
                return validated
            except Exception:
                pass

        if heuristic_plan.source == "heuristic":
            heuristic_plan.source = "heuristic"
        return heuristic_plan

    def reflect(self, state: dict[str, Any]) -> ReflectionDecision:
        heuristic = self._heuristic_reflection(state)
        query = self._build_knowledge_query(state)
        knowledge_hits = self.knowledge_retriever.search(query)
        exploit_candidates = [item.model_dump() for item in self.exploit_mapper.suggest(state)]

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
            except Exception:
                pass
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

    def _heuristic_plan(self, state: dict[str, Any]) -> PlanDecision:
        approved_action = state.get("approved_action")
        if approved_action:
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

        hosts = state.get("hosts", [])
        services = state.get("services", [])
        evidence = state.get("evidence", [])
        actions = state.get("actions", [])
        reflection_candidates = self._normalized_reflection_candidates(state)
        exploit_candidates = self.exploit_mapper.suggest(state)

        if not hosts:
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

        fingerprinted_targets = {service["target"] for service in services} | {
            action.get("params", {}).get("target")
            for action in actions
            if action.get("tool_name") == "service_fingerprint"
        }
        next_host = next((host["address"] for host in hosts if host["address"] not in fingerprinted_targets), None)
        if next_host:
            return PlanDecision(
                stage="observe",
                tool_name="service_fingerprint",
                params={"target": next_host, "port_spec": state.get("ports")},
                rationale="Fingerprint reachable services on the newly discovered host.",
                expected_evidence=["Open ports and service banners"],
                risk_level="low",
            )

        web_services = [service for service in services if self._is_web_service(service)]
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

        probed_endpoints = {
            (item.get("target"), item.get("port"))
            for item in evidence
            if item.get("kind") == "web_probe"
        } | {
            (
                action.get("params", {}).get("target"),
                action.get("params", {}).get("port"),
            )
            for action in actions
            if action.get("tool_name") == "web_probe"
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

        if web_services and not any(
            action.get("tool_name") in {"header_mutation", "raw_http", "tcp_send", "vuln_verify"}
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

    def _heuristic_reflection(self, state: dict[str, Any]) -> ReflectionDecision:
        last_result = state.get("last_result") or {}
        if not last_result:
            return ReflectionDecision(summary="No tool result is available to reflect on.")

        summary = str(last_result.get("summary") or state.get("last_summary") or "No summary.")
        tool_name = str(last_result.get("tool_name", "unknown"))
        structured = last_result.get("structured_data", {}) or {}
        hypotheses: list[dict[str, Any]] = []
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

        next_candidates = []
        selected_family = None
        rejected_families: list[str] = []
        family_switch_reason = None
        candidate_models = self._prioritize_candidates([item.model_dump() for item in self.exploit_mapper.suggest(state)])
        if candidate_models:
            next_candidates = candidate_models[:3]
            selected_family = candidate_models[0].get("selected_family")
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
                plan = PlanDecision.model_validate(
                    {
                        "stage": candidate.get("stage", "exploit"),
                        "tool_name": tool_name,
                        "params": candidate.get("params", {}),
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
                validated = self._validate_plan(plan)
                normalized.append(validated.model_dump())
            except Exception:
                continue
        return self._prioritize_candidates(normalized)

    def _prioritize_candidates(self, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        def priority(item: dict[str, Any]) -> tuple:
            source = str(item.get("source", ""))
            return (
                0 if source in {"reflection", "corpus_reflection", "llm_reflection"} else 1,
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
        allowed = self.allowed_tools_for_stage(plan.stage)
        if plan.tool_name not in allowed:
            raise ValueError(f"Tool {plan.tool_name} is not allowed in stage {plan.stage}.")
        model = self.TOOL_PARAM_MODELS.get(plan.tool_name)
        if model is not None:
            validated_params = model.model_validate(plan.params)
            plan.params = validated_params.model_dump()
        return plan


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
        return False

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
            "timeout": 45 if profile == "php_apache" else 30 if profile == "mini_httpd" else 60,
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
