from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

try:
    from langgraph.graph import END, START, StateGraph

    LANGGRAPH_AVAILABLE = True
except Exception:  # pragma: no cover - exercised indirectly by import fallback
    END = "__end__"
    START = "__start__"
    StateGraph = None
    LANGGRAPH_AVAILABLE = False

from app.agents.constants import VERIFICATION_TOOLS, EXPLOIT_TOOLS
from app.agents.planner import PlannerService
from app.agents.result_parser import ResultParser
from app.agents.state import AgentState
from app.agents.report_agent import ReportAgent
from app.core.risk_policy import RiskLevel, RiskTolerance, get_policy
from app.core.scope_guard import ScopeGuard, ScopeValidationError
from app.schemas.task import TaskUpdate
from app.services.approval_service import ApprovalService
from app.services.knowledge_capture_service import KnowledgeCaptureService
from app.services.task_service import TaskService
from app.services.tool_executor import ToolExecutor
from app.tools.base import ToolExecutionError


class PentestGraphRunner:
    # When True, a single confirmed finding stops the loop immediately.
    # When False (default), the runner continues until every service has at
    # least one confirmed finding or max_steps is exhausted.
    stop_on_first_finding: bool = False

    # Maximum number of consecutive tool failures before the graph stops.
    max_consecutive_failures: int = 3

    def __init__(
        self,
        *,
        task_service: TaskService,
        approval_service: ApprovalService,
        scope_guard: ScopeGuard,
        tool_executor: ToolExecutor,
        planner: PlannerService,
        result_parser: ResultParser,
        report_agent: ReportAgent,
        knowledge_capture_service: KnowledgeCaptureService | None = None,
    ) -> None:
        self.task_service = task_service
        self.approval_service = approval_service
        self.scope_guard = scope_guard
        self.tool_executor = tool_executor
        self.planner = planner
        self.result_parser = result_parser
        self.report_agent = report_agent
        self.knowledge_capture_service = knowledge_capture_service
        self.graph = self._build_graph()

    def run(self, task_id: str) -> dict[str, Any]:
        task = self.task_service.get_task(task_id)
        if task.status in {"completed", "stopped"}:
            return task.state

        state = task.state
        state["status"] = "running"
        self.task_service.update_task(
            task_id,
            TaskUpdate(
                status="running",
                state=state,
                started_at=task.started_at or datetime.now(UTC),
            ),
        )
        self.task_service.add_event(
            task_id,
            event_type="task_run_requested",
            stage=state.get("current_stage"),
            message="Task execution started.",
            payload={"status": "running"},
        )
        final_state = self.graph.invoke(state)
        return final_state

    def _build_graph(self):
        if not LANGGRAPH_AVAILABLE:
            return _FallbackGraph(self)

        builder = StateGraph(AgentState)
        builder.add_node("bootstrap", self._bootstrap)
        builder.add_node("validate_scope", self._validate_scope)
        builder.add_node("assess_context", self._assess_context)
        builder.add_node("choose_action", self._choose_action)
        builder.add_node("risk_check", self._risk_check)
        builder.add_node("human_approval", self._human_approval)
        builder.add_node("execute_action", self._execute_tool)
        builder.add_node("parse_result", self._parse_result)
        builder.add_node("reflect_result", self._reflect_result)
        builder.add_node("update_path_graph", self._update_path_graph)
        builder.add_node("decide_next", self._decide_continue)
        builder.add_node("generate_report", self._generate_report)
        builder.add_node("finish", self._finish)

        builder.add_edge(START, "bootstrap")
        builder.add_conditional_edges(
            "bootstrap",
            self._after_bootstrap,
            {"execute_action": "execute_action", "validate_scope": "validate_scope"},
        )
        builder.add_edge("validate_scope", "assess_context")
        builder.add_edge("assess_context", "choose_action")
        builder.add_conditional_edges(
            "choose_action",
            self._after_choose_action,
            {"generate_report": "generate_report", "risk_check": "risk_check"},
        )
        builder.add_conditional_edges(
            "risk_check",
            self._after_risk_check,
            {"human_approval": "human_approval", "execute_action": "execute_action"},
        )
        builder.add_edge("human_approval", END)
        builder.add_edge("execute_action", "parse_result")
        builder.add_edge("parse_result", "reflect_result")
        builder.add_edge("reflect_result", "update_path_graph")
        builder.add_edge("update_path_graph", "decide_next")
        builder.add_conditional_edges(
            "decide_next",
            self._after_decide_continue,
            {"choose_action": "choose_action", "generate_report": "generate_report"},
        )
        builder.add_edge("generate_report", "finish")
        builder.add_edge("finish", END)
        return builder.compile()

    def _bootstrap(self, state: AgentState) -> AgentState:
        if state.get("step_count", 0) >= state.get("max_steps", 8):
            state["stop_reason"] = "Reached the maximum number of bounded workflow steps."
        return state

    def _validate_scope(self, state: AgentState) -> AgentState:
        try:
            self.scope_guard.validate_scope(list(state.get("scope", [])))
        except ScopeValidationError as exc:
            state["status"] = "failed"
            state["stop_reason"] = str(exc)
            self.task_service.add_event(
                state["task_id"],
                event_type="scope_validation_failed",
                stage="validate_scope",
                message=str(exc),
                payload={},
            )
            return state

        state["current_stage"] = "observe"
        self._persist_state(state, message="Scope validation passed.")
        return state

    def _assess_context(self, state: AgentState) -> AgentState:
        if state.get("stop_reason"):
            state["current_stage"] = "report"
            return state
        state["current_stage"] = "assess"
        self._persist_state(state, message="Context assessed for the next action decision.")
        return state

    def _choose_action(self, state: AgentState) -> AgentState:
        decision = self.planner.choose_action(state)
        state["last_decision"] = decision.model_dump()
        state["current_stage"] = decision.stage
        state["status"] = "running"
        self._persist_state(
            state,
            message=f"Chose next action: {decision.tool_name or 'stop'} @ {decision.stage}.",
            payload={"decision": state["last_decision"]},
            event_type="action_chosen",
        )
        return state

    def _risk_check(self, state: AgentState) -> AgentState:
        plan = state.get("last_decision") or {}

        # ── Resolve runtime risk tolerance from task state ──────────────
        risk_tolerance_str = state.get("risk_tolerance", "moderate")
        try:
            risk_tolerance = RiskTolerance(risk_tolerance_str)
        except ValueError:
            risk_tolerance = RiskTolerance.MODERATE

        if state.get("pending_approval") and not state.get("approved_action"):
            state["status"] = "waiting_approval"
            self._persist_state(
                state,
                message="Task is still waiting for user approval.",
                payload={"approval": state.get("pending_approval")},
                event_type="approval_pending",
            )
            return state

        tool_name = plan.get("tool_name")
        if not tool_name or plan.get("stop"):
            state["status"] = "running"
            return state

        # Determine approval requirement using the policy + tolerance.
        try:
            policy = get_policy(tool_name, tolerance=risk_tolerance)
        except KeyError:
            policy = get_policy(tool_name)

        # NONE tolerance: skip all approval gates.
        if risk_tolerance == RiskTolerance.NONE:
            state["status"] = "running"
            return state

        # RELAXED tolerance: skip approval for non-CRITICAL tools.
        if risk_tolerance == RiskTolerance.RELAXED and policy.risk_level in {
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
        }:
            state["status"] = "running"
            return state

        if policy.approval_required and not state.get("approved_action"):
            approval = self.approval_service.create_approval(
                state["task_id"],
                tool_name=plan["tool_name"],
                target=plan["params"].get("target", ",".join(plan["params"].get("targets", []))),
                risk_level=plan.get("risk_level", "high"),
                reason=plan.get("rationale", ""),
                params=plan.get("params", {}),
            )
            state["pending_approval"] = approval.model_dump(mode="json")
            state["status"] = "waiting_approval"
            self._persist_state(
                state,
                message=f"Action {plan['tool_name']} requires user approval.",
                payload={"approval": state["pending_approval"]},
                event_type="approval_requested",
            )
            return state

        state["status"] = "running"
        return state

    def _human_approval(self, state: AgentState) -> AgentState:
        return state

    def _execute_tool(self, state: AgentState) -> AgentState:
        action = state.get("approved_action") or state.get("last_decision") or {}
        tool_name = action.get("tool_name")
        params = action.get("params", {})
        stage = action.get("stage", state.get("current_stage", ""))
        try:
            result = self.tool_executor.execute(
                task_id=state["task_id"],
                scope=list(state.get("scope", [])),
                stage=stage,
                tool_name=tool_name,
                params=params,
                risk_tolerance=state.get("risk_tolerance"),
            )
        except ToolExecutionError as exc:
            state["last_result"] = {
                "tool_name": tool_name,
                "success": False,
                "summary": str(exc),
                "error": str(exc),
                "structured_data": {},
                "artifact_paths": [],
            }
            state["last_summary"] = str(exc)
            state["error_count"] = state.get("error_count", 0) + 1
            if tool_name in VERIFICATION_TOOLS:
                state["stop_reason"] = "Exploit action failed before reproduction."
            state["approved_action"] = None
            state["pending_approval"] = None
            state.setdefault("actions", []).append(
                {
                    "tool_name": tool_name,
                    "stage": stage,
                    "params": params,
                    "success": False,
                    "summary": str(exc),
                }
            )
            self._persist_state(
                state,
                message=f"Tool {tool_name} failed: {exc}",
                payload={"tool_name": tool_name, "params": params},
                event_type="tool_failed",
            )
            return state

        state["step_count"] = state.get("step_count", 0) + 1
        state.setdefault("actions", []).append(
            {
                "tool_name": tool_name,
                "stage": stage,
                "params": params,
                "success": True,
                "summary": result.summary,
            }
        )
        state["last_result"] = result.model_dump()
        state["approved_action"] = None
        state["pending_approval"] = None
        for artifact_path in result.artifact_paths:
            self.task_service.add_artifact(
                state["task_id"],
                artifact_type=tool_name,
                title=f"{tool_name} output",
                path=artifact_path,
                summary=result.summary,
            )
        self._persist_state(
            state,
            message=f"Tool {tool_name} completed successfully.",
            payload={"tool_name": tool_name, "summary": result.summary},
            event_type="tool_completed",
        )
        return state

    def _parse_result(self, state: AgentState) -> AgentState:
        last_result = state.get("last_result")
        if not last_result:
            return state
        from app.schemas.tool import ToolExecutionResult

        parsed = ToolExecutionResult.model_validate(last_result)

        # ── searchsploit auto-knowledge-capture ────────────────────────────
        # When searchsploit returns new exploits for an unknown service,
        # auto-generate learning candidates for user review.
        if (
            parsed.tool_name == "searchsploit_lookup"
            and parsed.success
            and self.knowledge_capture_service
        ):
            self._capture_searchsploit_results(state, parsed)

        self.result_parser.apply(state, parsed)
        self._persist_state(
            state,
            message="Structured result parsing completed.",
            payload={"summary": state.get("last_summary")},
            event_type="result_parsed",
        )
        return state

    def _capture_searchsploit_results(
        self, state: AgentState, parsed: "ToolExecutionResult"
    ) -> None:
        """Feed searchsploit results into the knowledge capture pipeline."""
        try:
            results = parsed.structured_data.get("results", [])
            if not results:
                return

            services = state.get("services", [])
            if not services:
                return

            for service in services:
                # Only capture for unmatched services
                if self.planner.exploit_mapper.has_candidates_for_service(service):
                    continue

                capture_result = self.knowledge_capture_service.capture_from_searchsploit(
                    task_id=state["task_id"],
                    device=service,
                    searchsploit_results=results,
                    auto_publish=False,  # user reviews first for safety
                )

                if capture_result.get("proposed", 0) > 0:
                    self.task_service.add_event(
                        state["task_id"],
                        event_type="knowledge_expansion_proposed",
                        stage=state.get("current_stage", "enumerate"),
                        message=(
                            f"searchsploit found {len(results)} results for "
                            f"{service.get('product', service.get('service', 'unknown'))}. "
                            f"{capture_result['proposed']} new exploit signature(s) proposed for review."
                        ),
                        payload=capture_result,
                    )
        except Exception as exc:
            logging.getLogger(__name__).warning("Failed to capture searchsploit results: %s", exc)

    def _reflect_result(self, state: AgentState) -> AgentState:
        reflection = self.planner.reflect(state)
        state["last_reflection"] = reflection.model_dump()
        state.setdefault("reflections", []).append(state["last_reflection"])
        state["last_summary"] = reflection.summary
        for item in reflection.hypotheses:
            self.result_parser._append_hypothesis(
                state,
                title=str(item.get("title", "Reflection hypothesis")),
                rationale=str(item.get("rationale", "")),
                severity=str(item.get("severity", "medium")),
            )
        if reflection.stop and reflection.stop_reason:
            state["stop_reason"] = reflection.stop_reason
        self._persist_state(
            state,
            message="Reflected on the latest action result.",
            payload={"reflection": state["last_reflection"]},
            event_type="result_reflected",
        )
        return state

    def _update_path_graph(self, state: AgentState) -> AgentState:
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []

        for host in state.get("hosts", []):
            host_id = f"host:{host['address']}"
            nodes.append({"id": host_id, "label": host["address"], "type": "host"})

        for service in state.get("services", []):
            service_id = f"service:{service['target']}:{service['port']}"
            nodes.append(
                {
                    "id": service_id,
                    "label": f"{service['service']}:{service['port']}",
                    "type": "service",
                }
            )
            edges.append(
                {
                    "source": f"host:{service['target']}",
                    "target": service_id,
                    "label": "exposes",
                }
            )

        for finding in state.get("findings", []):
            title = finding.get("title", "untitled")
            finding_id = f"finding:{abs(hash(title))}"
            nodes.append(
                {
                    "id": finding_id,
                    "label": title[:80],
                    "type": "finding",
                }
            )
            for service in state.get("services", []):
                if str(service["port"]) in finding.get("evidence_summary", "") or service["target"] in finding.get("evidence_summary", ""):
                    edges.append(
                        {
                            "source": f"service:{service['target']}:{service['port']}",
                            "target": finding_id,
                            "label": "supports",
                        }
                    )

        dedup_nodes = {node["id"]: node for node in nodes}
        dedup_edges = {
            (edge["source"], edge["target"], edge["label"]): edge for edge in edges
        }
        state["path_graph"] = {
            "nodes": list(dedup_nodes.values()),
            "edges": list(dedup_edges.values()),
        }
        self._persist_state(
            state,
            message="Updated attack path graph.",
            payload={"path_graph": state["path_graph"]},
            event_type="graph_updated",
        )
        return state

    def _decide_continue(self, state: AgentState) -> AgentState:
        """Determine whether the graph loop should continue or stop.

        With stop_on_first_finding=False (default), the loop only stops when
        max_steps is exhausted or every service has at least one confirmed
        finding.  An early-stop guard for consecutive failures is also applied.
        """
        if state.get("status") == "failed":
            return state

        # ── Consecutive failure guard (actions-based) ────────────────────
        actions = state.get("actions", [])
        if actions:
            recent_count = 0
            for action in reversed(actions):
                if not action.get("success", True):
                    recent_count += 1
                else:
                    break
            if recent_count >= self.max_consecutive_failures:
                state["stop_reason"] = "Too many consecutive tool failures."
                return state

        # ── Error count guard (backward compatible) ──────────────────────
        if state.get("error_count", 0) >= self.max_consecutive_failures:
            state["stop_reason"] = "Too many consecutive tool failures."
            return state

        # ── Max steps guard ──────────────────────────────────────────────
        if state.get("step_count", 0) >= state.get("max_steps", 8):
            state["stop_reason"] = "Reached the maximum number of bounded workflow steps."
            return state

        # ── stop_on_first_finding guard ──────────────────────────────────
        if self.stop_on_first_finding:
            confirmed = [
                item for item in state.get("findings", [])
                if str(item.get("confidence", "")).lower() == "confirmed"
            ]
            if confirmed:
                state["stop_reason"] = state.get("stop_reason") or "Confirmed exploit evidence collected."
                return state

        # ── All-services-covered guard ───────────────────────────────────
        services = state.get("services", [])
        findings = state.get("findings", [])
        if services:
            confirmed_targets = set()
            for finding in findings:
                if str(finding.get("confidence", "")).lower() != "confirmed":
                    continue
                evidence_summary = finding.get("evidence_summary", "")
                for service in services:
                    if str(service["port"]) in evidence_summary or service["target"] in evidence_summary:
                        confirmed_targets.add((service["target"], service["port"]))
            all_covered = all(
                (s["target"], s["port"]) in confirmed_targets
                for s in services
            )
            if all_covered:
                state["stop_reason"] = state.get("stop_reason") or "All services have at least one confirmed finding."
                return state

        return state

    def _generate_report(self, state: AgentState) -> AgentState:
        terminal_status = self._derive_terminal_status(state)
        if terminal_status in {"failed", "paused", "completed"}:
            state["status"] = terminal_status
        task = self.task_service.get_task(state["task_id"])
        task = self.task_service.update_task(
            state["task_id"],
            TaskUpdate(
                current_stage="report",
                state=state,
                status=terminal_status,
                stop_reason=state.get("stop_reason"),
            ),
        )
        events = self.task_service.list_events(task.id)
        approvals = self.approval_service.list_approvals(task.id)
        artifacts = self.task_service.list_artifacts(task.id)
        markdown_content, _, report_path = self.report_agent.generate(task, events, approvals, artifacts)
        self.task_service.add_artifact(
            task.id,
            artifact_type="report",
            title="Final report",
            path=report_path,
            summary="Markdown report generated from task state and evidence.",
        )
        state["report_path"] = report_path
        state["last_summary"] = "Final report generated."
        self._persist_state(
            state,
            message="Generated final report.",
            payload={"report_path": report_path, "report_size": len(markdown_content)},
            event_type="report_generated",
        )
        return state

    def _finish(self, state: AgentState) -> AgentState:
        finished_at = datetime.now(UTC)
        if state.get("status") == "waiting_approval":
            return state

        final_status = self._derive_terminal_status(state)
        if not state.get("report_path"):
            final_status = "paused"

        state["status"] = final_status
        self.task_service.update_task(
            state["task_id"],
            TaskUpdate(
                status=final_status,
                current_stage="finish" if final_status in {"completed", "failed"} else state.get("current_stage"),
                state=state,
                report_path=state.get("report_path"),
                stop_reason=state.get("stop_reason"),
                finished_at=finished_at if final_status in {"completed", "failed"} else None,
            ),
        )
        self.task_service.add_event(
            state["task_id"],
            event_type="task_finished",
            stage="finish",
            message=f"Task finished with status {final_status}.",
            payload={"stop_reason": state.get("stop_reason")},
        )
        if self.knowledge_capture_service and final_status in {"completed", "failed"}:
            task = self.task_service.get_task(state["task_id"])
            events = self.task_service.list_events(task.id)
            approvals = self.approval_service.list_approvals(task.id)
            artifacts = self.task_service.list_artifacts(task.id)
            created = self.knowledge_capture_service.capture_from_task(task, events, approvals, artifacts)
            if created:
                self.task_service.add_event(
                    state["task_id"],
                    event_type="learning_candidates_generated",
                    stage="finish",
                    message=f"Generated {len(created)} learning candidate(s) for review.",
                    payload={"candidate_ids": [item.id for item in created]},
                )
        return state

    def _derive_terminal_status(self, state: AgentState) -> str:
        if state.get("status") == "failed":
            return "failed"
        stop_reason = str(state.get("stop_reason") or "")
        # Use prefix / exact substring matches for precision,
        # then fall back to broader `in` checks for backward compatibility.
        if stop_reason.startswith("too many consecutive"):
            return "failed"
        elif "verification failed" in stop_reason:
            return "failed"
        elif "rejected by user" in stop_reason:
            return "paused"
        elif "rejected" in stop_reason:
            return "paused"
        return "completed"

    def _after_bootstrap(self, state: AgentState) -> str:
        """Route to execute_action if there is a pending approved action.

        Before routing, perform a light scope check to ensure the approved
        action's targets are still within the task scope.
        """
        approved_action = state.get("approved_action")
        if approved_action:
            scope = set(state.get("scope", []))
            params = approved_action.get("params", {})
            action_targets = set(
                params.get("targets", [])
                if isinstance(params.get("targets"), list)
                else ([params["target"]] if params.get("target") else [])
            )
            if action_targets and scope:
                out_of_scope = action_targets - scope
                if out_of_scope:
                    self.task_service.add_event(
                        state["task_id"],
                        event_type="scope_recheck_blocked",
                        stage="bootstrap",
                        message=f"Approved action targets {out_of_scope} are outside the current scope.",
                        payload={"out_of_scope": list(out_of_scope), "scope": list(scope)},
                    )
                    state["approved_action"] = None
                    state["pending_approval"] = None
                    state["stop_reason"] = "Approved action rejected: targets outside scope."
                    return "validate_scope"
            return "execute_action"
        return "validate_scope"

    def _after_choose_action(self, state: AgentState) -> str:
        plan = state.get("last_decision") or {}
        return "generate_report" if plan.get("stop") else "risk_check"

    def _after_risk_check(self, state: AgentState) -> str:
        return "human_approval" if state.get("status") == "waiting_approval" else "execute_action"

    def _after_decide_continue(self, state: AgentState) -> str:
        if state.get("status") == "failed" or state.get("stop_reason"):
            return "generate_report"
        return "choose_action"

    def _persist_state(
        self,
        state: AgentState,
        *,
        message: str,
        payload: dict[str, Any] | None = None,
        event_type: str = "stage_updated",
    ) -> None:
        self.task_service.update_task(
            state["task_id"],
            TaskUpdate(
                status=state.get("status", "running"),
                current_stage=state.get("current_stage", ""),
                state=dict(state),
                report_path=state.get("report_path"),
                stop_reason=state.get("stop_reason"),
            ),
        )
        self.task_service.add_event(
            state["task_id"],
            event_type=event_type,
            stage=state.get("current_stage"),
            message=message,
            payload=payload or {},
        )


class _FallbackGraph:
    def __init__(self, runner: PentestGraphRunner) -> None:
        self.runner = runner

    def invoke(self, state: AgentState) -> AgentState:
        node = "bootstrap"
        step_counter = 0
        max_iterations = max(50, state.get("max_steps", 8) * 3)

        while True:
            step_counter += 1
            if step_counter > max_iterations:
                state["stop_reason"] = "fallback graph exceeded max iterations"
                state["status"] = "failed"
                return state

            if node == "bootstrap":
                state = self.runner._bootstrap(state)
                node = self.runner._after_bootstrap(state)
                continue
            if node == "validate_scope":
                state = self.runner._validate_scope(state)
                node = "assess_context"
                continue
            if node == "assess_context":
                state = self.runner._assess_context(state)
                node = "choose_action"
                continue
            if node == "choose_action":
                state = self.runner._choose_action(state)
                node = self.runner._after_choose_action(state)
                continue
            if node == "risk_check":
                state = self.runner._risk_check(state)
                node = self.runner._after_risk_check(state)
                if node == "human_approval":
                    state = self.runner._human_approval(state)
                    return state
                continue
            if node == "execute_action":
                state = self.runner._execute_tool(state)
                node = "parse_result"
                continue
            if node == "parse_result":
                state = self.runner._parse_result(state)
                node = "reflect_result"
                continue
            if node == "reflect_result":
                state = self.runner._reflect_result(state)
                node = "update_path_graph"
                continue
            if node == "update_path_graph":
                state = self.runner._update_path_graph(state)
                node = "decide_next"
                continue
            if node == "decide_next":
                state = self.runner._decide_continue(state)
                node = self.runner._after_decide_continue(state)
                continue
            if node == "generate_report":
                state = self.runner._generate_report(state)
                node = "finish"
                continue
            if node == "finish":
                state = self.runner._finish(state)
                return state
            raise RuntimeError(f"Unknown fallback graph node: {node}")
