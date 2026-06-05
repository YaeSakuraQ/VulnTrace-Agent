from __future__ import annotations

import json
from datetime import UTC, datetime
from urllib.parse import urlparse

import markdown

from app.schemas.task import ArtifactRecord, TaskDetail, TaskEvent
from app.services.artifact_store import ArtifactStore
from app.schemas.approval import ApprovalRecord


class ReportAgent:
    def __init__(self, artifact_store: ArtifactStore) -> None:
        self.artifact_store = artifact_store

    def generate(
        self,
        task: TaskDetail,
        events: list[TaskEvent],
        approvals: list[ApprovalRecord],
        artifacts: list[ArtifactRecord],
    ) -> tuple[str, str, str]:
        state = task.state
        markdown_content = self._build_markdown(task, state, events, approvals, artifacts)
        html_content = markdown.markdown(markdown_content, extensions=["tables", "fenced_code"])
        markdown_path = self.artifact_store.write_text(task.id, "report.md", markdown_content)
        self.artifact_store.write_text(task.id, "report.html", html_content)
        return markdown_content, html_content, str(markdown_path)

    def _build_markdown(
        self,
        task: TaskDetail,
        state: dict,
        events: list[TaskEvent],
        approvals: list[ApprovalRecord],
        artifacts: list[ArtifactRecord],
    ) -> str:
        findings = state.get("findings", [])
        hypotheses = state.get("hypotheses", [])
        evidence = state.get("evidence", [])
        pocs = self._resolve_report_pocs(state, artifacts)
        reflections = state.get("reflections", [])
        verdict_title, verdict_detail = self._derive_verification_verdict(state)
        failed_actions = [item for item in state.get("actions", []) if not item.get("success", True)]
        lines = [
            f"# {task.name}",
            "",
            "## 测试概览",
            f"- 任务编号：`{task.id}`",
            f"- 授权范围：`{', '.join(task.scope)}`",
            f"- 目标说明：{task.lab_description or '未填写'}",
            f"- 测试目标：{task.objective}",
            f"- 当前状态：{task.status}",
            f"- 当前阶段：{task.current_stage}",
            f"- 执行结论：{verdict_title}",
            f"- 停止原因：{task.stop_reason or '无'}",
            f"- 生成时间：{datetime.now(UTC).isoformat()}",
            "",
            "## 发现主机",
        ]

        hosts = state.get("hosts", [])
        if hosts:
            for host in hosts:
                lines.append(f"- `{host['address']}` ({host.get('status', 'unknown')})")
        else:
            lines.append("- 未发现在线主机")

        lines.extend(["", "## 服务清单"])
        services = state.get("services", [])
        if services:
            for service in services:
                lines.append(
                    f"- `{service['target']}:{service['port']}` {service.get('service', 'unknown')} {service.get('product', '')} {service.get('version', '')}".strip()
                )
        else:
            lines.append("- 未识别到开放服务")

        lines.extend(["", "## 已确认或疑似发现"])
        if findings:
            for finding in findings:
                lines.append(
                    f"- [{finding.get('confidence', 'suspected')}] {finding['title']} | 风险：{finding.get('severity', 'unknown')} | 证据：{finding.get('evidence_summary', '无')}"
                )
        else:
            lines.append("- 未发现需要记录的安全问题")

        lines.extend(["", "## PoC 明细"])
        if pocs:
            for index, poc in enumerate(pocs, start=1):
                lines.extend(
                    [
                        f"### PoC {index}: {poc.get('title', '未命名 PoC')}",
                        f"- 状态：{poc.get('status', 'unknown')}",
                        f"- 模块：{poc.get('module', 'unknown')}",
                        f"- 目标：`{poc.get('method', 'GET')} {poc.get('url', '')}`",
                    ]
                )
                success_evidence = poc.get("success_evidence", [])
                if success_evidence:
                    lines.append(
                        "- 成功证据："
                        + ", ".join(f"`{item}`" for item in success_evidence if str(item).strip())
                    )
                notes = [str(item).strip() for item in poc.get("notes", []) if str(item).strip()]
                if notes:
                    for note in notes[:4]:
                        lines.append(f"- 说明：{note}")
                params = poc.get("params", {})
                if params:
                    lines.extend(
                        [
                            "",
                            "参数：",
                            "```json",
                            json.dumps(params, ensure_ascii=False, indent=2),
                            "```",
                        ]
                    )
                request_excerpt = str(poc.get("request_excerpt", "")).strip()
                if request_excerpt:
                    lines.extend(
                        [
                            "请求摘录：",
                            "```http",
                            request_excerpt,
                            "```",
                        ]
                    )
                response_excerpt = str(poc.get("response_excerpt", "")).strip()
                if response_excerpt:
                    lines.extend(
                        [
                            "响应摘录：",
                            "```text",
                            response_excerpt,
                            "```",
                        ]
                    )
                evidence_files = [str(item) for item in poc.get("evidence_files", []) if str(item).strip()]
                if evidence_files:
                    lines.append("- 证据文件：")
                    for path in evidence_files:
                        lines.append(f"  - `{path}`")
                lines.append("")
        else:
            lines.append("- 未记录可复用的 PoC 细节")

        lines.extend(["", "## 反思与下一跳"])
        if reflections:
            for index, reflection in enumerate(reflections[-3:], start=1):
                lines.append(f"### Reflection {index}")
                lines.append(f"- 来源：{reflection.get('source', 'unknown')}")
                lines.append(f"- 摘要：{reflection.get('summary', '')}")
                lines.append(f"- 失败类型：{reflection.get('failure_class', 'none')}")
                if reflection.get("selected_family"):
                    lines.append(f"- 当前选择的 family：`{reflection.get('selected_family')}`")
                rejected = reflection.get("rejected_families", [])
                if rejected:
                    lines.append(
                        "- 放弃的 family："
                        + ", ".join(f"`{item}`" for item in rejected if str(item).strip())
                    )
                if reflection.get("family_switch_reason"):
                    lines.append(f"- 切换原因：{reflection.get('family_switch_reason')}")
                hypotheses_items = reflection.get("hypotheses", [])
                if hypotheses_items:
                    lines.append("- 新增假设：")
                    for item in hypotheses_items:
                        lines.append(f"  - {item.get('title', '')}：{item.get('rationale', '')}")
                next_candidates = reflection.get("next_candidates", [])
                if next_candidates:
                    lines.append("- 下一跳候选：")
                    for candidate in next_candidates:
                        family_labels = [
                            detail.get("title", detail.get("id", ""))
                            for detail in candidate.get("family_details", [])
                            if isinstance(detail, dict)
                        ]
                        family_text = f" | families: {', '.join(family_labels)}" if family_labels else ""
                        lines.append(
                            f"  - `{candidate.get('tool_name', 'unknown')}` {candidate.get('title', '')}{family_text}"
                        )
                        rationale = str(candidate.get("rationale", "")).strip()
                        if rationale:
                            lines.append(f"    - rationale: {rationale}")
                lines.append("")
        else:
            lines.append("- 暂无反思记录")

        lines.extend(["", "## 验证结论", f"- 结论：{verdict_title}", f"- 说明：{verdict_detail}"])
        if failed_actions:
            for action in failed_actions[-4:]:
                lines.append(
                    f"- 失败动作：`{action.get('tool_name', 'unknown')}` @ {action.get('stage', 'unknown')} | {action.get('summary', '执行失败')}"
                )

        lines.extend(["", "## 未验证假设"])
        unverified = [item for item in hypotheses if item.get("status") != "confirmed"]
        if unverified:
            for item in unverified:
                lines.append(f"- {item['title']}：{item.get('rationale', '')}")
        else:
            lines.append("- 无")

        lines.extend(["", "## 证据摘要"])
        if evidence:
            for item in evidence[-12:]:
                lines.append(f"- {item.get('kind', 'evidence')}：{item.get('summary', '')}")
        else:
            lines.append("- 无")

        lines.extend(["", "## 审批记录"])
        if approvals:
            for approval in approvals:
                lines.append(
                    f"- `{approval.tool_name}` -> {approval.status} | 风险：{approval.risk_level} | 说明：{approval.reason}"
                )
        else:
            lines.append("- 无需人工审批")

        lines.extend(["", "## 运行轨迹"])
        for event in events[-20:]:
            lines.append(f"- {event.created_at.isoformat()} | {event.event_type} | {event.message}")

        lines.extend(["", "## 证据文件"])
        if artifacts:
            for artifact in artifacts:
                lines.append(f"- `{artifact.path}`：{artifact.summary}")
        else:
            lines.append("- 无")

        lines.extend(
            [
                "",
                "## 边界声明",
                "- 本报告仅覆盖用户授权的本地靶场范围。",
                "- 高风险验证动作仅在审批通过后执行。",
                "- 无证据支撑的内容保留为假设，不作为确认漏洞结论。",
            ]
        )
        return "\n".join(lines)

    def _resolve_report_pocs(
        self,
        state: dict,
        artifacts: list[ArtifactRecord],
    ) -> list[dict]:
        recorded = [item for item in state.get("pocs", []) if isinstance(item, dict)]
        if recorded:
            return recorded
        confirmed_findings = [
            item
            for item in state.get("findings", [])
            if str(item.get("confidence", "")).lower() == "confirmed"
        ]
        if not confirmed_findings:
            return []
        synthesized = self._synthesize_pocs_from_confirmed_findings(
            confirmed_findings,
            state,
            artifacts,
        )
        return synthesized or []

    def _synthesize_pocs_from_confirmed_findings(
        self,
        confirmed_findings: list[dict],
        state: dict,
        artifacts: list[ArtifactRecord],
    ) -> list[dict]:
        synthesized: list[dict] = []
        used_keys: set[tuple[str, str]] = set()
        for finding in confirmed_findings:
            evidence_item = self._select_best_evidence_for_finding(finding, state)
            action = self._select_best_action_for_finding(finding, state, evidence_item)
            title = str(finding.get("title", "Confirmed finding")).strip()
            target_url = self._extract_target_url(evidence_item, action)
            method = self._extract_method(evidence_item, action)
            poc_id = self._slugify(f"auto-{title}")[:80]
            key = (poc_id, target_url)
            if key in used_keys:
                continue
            used_keys.add(key)
            module = self._infer_module(evidence_item, action)
            params = dict(action.get("params", {})) if isinstance(action, dict) else {}
            request_excerpt = self._build_request_excerpt(evidence_item, action)
            response_excerpt = self._build_response_excerpt(evidence_item)
            success_evidence = self._build_success_evidence(finding, evidence_item)
            evidence_files = self._select_evidence_files(artifacts, evidence_item, action)
            synthesized.append(
                {
                    "id": poc_id,
                    "title": f"{title} (Auto-generated PoC draft)",
                    "module": module,
                    "status": "confirmed",
                    "method": method,
                    "url": target_url,
                    "params": params,
                    "request_excerpt": request_excerpt,
                    "response_excerpt": response_excerpt,
                    "success_evidence": success_evidence,
                    "notes": [
                        "This PoC entry was synthesized from confirmed evidence because the execution path did not persist an explicit reusable PoC object.",
                        "Review the request/response excerpts and artifact files before reusing this PoC outside the current lab snapshot.",
                    ],
                    "evidence_files": evidence_files,
                }
            )
        return synthesized

    def _select_best_evidence_for_finding(self, finding: dict, state: dict) -> dict | None:
        confirmed_title = str(finding.get("title", "")).lower()
        evidence = [item for item in state.get("evidence", []) if isinstance(item, dict)]
        ranked_kinds = self._preferred_evidence_kinds(confirmed_title)
        for kind in ranked_kinds:
            for item in reversed(evidence):
                if item.get("kind") == kind:
                    return item
        return evidence[-1] if evidence else None

    def _select_best_action_for_finding(
        self,
        finding: dict,
        state: dict,
        evidence_item: dict | None,
    ) -> dict | None:
        title = str(finding.get("title", "")).lower()
        actions = [item for item in state.get("actions", []) if isinstance(item, dict)]
        preferred_tools = self._preferred_action_tools(title)
        if evidence_item and evidence_item.get("kind") in preferred_tools:
            preferred_tools.insert(0, str(evidence_item.get("kind")))
        for tool_name in preferred_tools:
            for action in reversed(actions):
                if action.get("tool_name") == tool_name and action.get("success", False):
                    return action
        for action in reversed(actions):
            if action.get("success", False):
                return action
        return None

    def _preferred_evidence_kinds(self, finding_title: str) -> list[str]:
        if "json-rpc" in finding_title or "rpc" in finding_title:
            return ["json_rpc_probe", "http_request", "raw_http", "vuln_verify"]
        if "file read" in finding_title or "passwd" in finding_title:
            return ["raw_http", "header_mutation", "vuln_verify"]
        return ["vuln_verify", "raw_http", "header_mutation", "http_request", "tcp_send"]

    def _preferred_action_tools(self, finding_title: str) -> list[str]:
        if "json-rpc" in finding_title or "rpc" in finding_title:
            return ["vuln_verify", "http_request", "raw_http"]
        if "file read" in finding_title or "passwd" in finding_title:
            return ["header_mutation", "raw_http", "vuln_verify"]
        return ["vuln_verify", "header_mutation", "raw_http", "tcp_send", "http_request"]

    def _extract_target_url(self, evidence_item: dict | None, action: dict | None) -> str:
        if evidence_item:
            data = evidence_item.get("data", {})
            url = str(data.get("url", "")).strip()
            if url:
                return url
        if action:
            params = action.get("params", {})
            target = str(params.get("target", "")).strip()
            port = params.get("port")
            scheme = str(params.get("scheme", "")).strip() or ("https" if int(port or 0) in {443, 8443} else "http")
            path = str(params.get("path", "/")).strip() or "/"
            if target and port:
                return f"{scheme}://{target}:{port}{path}"
        return ""

    def _extract_method(self, evidence_item: dict | None, action: dict | None) -> str:
        if evidence_item:
            method = str(evidence_item.get("data", {}).get("method", "")).strip()
            if method:
                return method
        if action:
            method = str(action.get("params", {}).get("method", "")).strip()
            if method:
                return method
        return "GET"

    def _infer_module(self, evidence_item: dict | None, action: dict | None) -> str:
        if evidence_item:
            kind = str(evidence_item.get("kind", "")).strip()
            if kind:
                return kind
        if action:
            tool_name = str(action.get("tool_name", "")).strip()
            if tool_name:
                return tool_name
        return "auto_generated"

    def _build_request_excerpt(self, evidence_item: dict | None, action: dict | None) -> str:
        if evidence_item:
            data = evidence_item.get("data", {})
            raw_request = str(data.get("raw_request", "")).strip()
            if raw_request:
                return raw_request
            method = str(data.get("method", "")).strip()
            path = str(data.get("path", "")).strip()
            headers = data.get("request_headers", {}) if isinstance(data.get("request_headers", {}), dict) else {}
            body = str(data.get("request_body", "")).strip()
            if method and path:
                lines = [f"{method} {path} HTTP/1.1"]
                host = self._host_header_from_url(str(data.get("url", "")))
                if host:
                    lines.append(f"Host: {host}")
                for key, value in headers.items():
                    lines.append(f"{key}: {value}")
                if body:
                    lines.extend(["", body])
                return "\n".join(lines)
        if action:
            params = action.get("params", {})
            request = str(params.get("request", "")).strip()
            if request:
                return request
            method = str(params.get("method", "")).strip()
            path = str(params.get("path", "")).strip()
            if method and path:
                lines = [f"{method} {path} HTTP/1.1"]
                target = str(params.get("target", "")).strip()
                port = params.get("port")
                if target and port:
                    lines.append(f"Host: {target}:{port}")
                headers = params.get("headers", {}) if isinstance(params.get("headers", {}), dict) else {}
                for key, value in headers.items():
                    lines.append(f"{key}: {value}")
                body = str(params.get("body", "")).strip()
                if body:
                    lines.extend(["", body])
                return "\n".join(lines)
        return ""

    def _build_response_excerpt(self, evidence_item: dict | None) -> str:
        if not evidence_item:
            return ""
        data = evidence_item.get("data", {})
        raw_response = str(data.get("raw_response", "")).strip()
        if raw_response:
            return raw_response[:800]
        body_snippet = str(data.get("body_snippet", "")).strip()
        if body_snippet:
            return body_snippet[:800]
        return ""

    def _build_success_evidence(self, finding: dict, evidence_item: dict | None) -> list[str]:
        evidence_markers: list[str] = []
        summary = str(finding.get("evidence_summary", "")).strip()
        if summary:
            evidence_markers.append(summary)
        if evidence_item:
            data = evidence_item.get("data", {})
            for key in ["body_snippet", "path"]:
                value = str(data.get(key, "")).strip()
                if value:
                    evidence_markers.append(value[:160])
            json_blob = data.get("json")
            if isinstance(json_blob, dict) and json_blob:
                evidence_markers.append(json.dumps(json_blob, ensure_ascii=False)[:200])
            body_preview = str(data.get("body_preview", "")).strip()
            if body_preview:
                evidence_markers.append(body_preview[:160])
        deduped: list[str] = []
        for item in evidence_markers:
            if item and item not in deduped:
                deduped.append(item)
        return deduped[:4]

    def _select_evidence_files(
        self,
        artifacts: list[ArtifactRecord],
        evidence_item: dict | None,
        action: dict | None,
    ) -> list[str]:
        candidate_types: list[str] = []
        if evidence_item:
            candidate_types.append(str(evidence_item.get("kind", "")))
        if action:
            candidate_types.append(str(action.get("tool_name", "")))
        selected: list[str] = []
        for artifact in artifacts:
            if artifact.artifact_type in candidate_types and artifact.path not in selected:
                selected.append(artifact.path)
        return selected[:4]

    def _host_header_from_url(self, url: str) -> str:
        if not url:
            return ""
        parsed = urlparse(url)
        return parsed.netloc

    def _slugify(self, value: str) -> str:
        normalized = []
        for char in value.lower():
            if char.isalnum():
                normalized.append(char)
            else:
                normalized.append("-")
        slug = "".join(normalized)
        while "--" in slug:
            slug = slug.replace("--", "-")
        return slug.strip("-") or "auto-poc"

    def _derive_verification_verdict(self, state: dict) -> tuple[str, str]:
        findings = state.get("findings", [])
        actions = state.get("actions", [])
        stop_reason = str(state.get("stop_reason") or "").lower()
        confirmed_findings = [
            item for item in findings if str(item.get("confidence", "")).lower() == "confirmed"
        ]
        verification_actions = [
            item
            for item in actions
            if item.get("tool_name") in {"vuln_verify", "header_mutation", "raw_http", "tcp_send"}
        ]
        failed_verifications = [
            item for item in verification_actions if not item.get("success", True)
        ]
        successful_verifications = [
            item for item in verification_actions if item.get("success", False)
        ]

        if confirmed_findings:
            return "已确认问题", "高风险验证已完成，并形成了可确认的漏洞证据。"
        if "exploit action failed before reproduction" in stop_reason:
            return (
                "验证失败/未复现",
                "具体利用动作已执行但未形成成功复现证据，当前没有证据证明漏洞已被成功利用。",
            )
        if failed_verifications:
            return (
                "验证失败/未复现",
                "高风险验证工具未成功完成，当前没有证据证明漏洞已被成功利用或复现。",
            )
        if successful_verifications:
            return "已验证但未复现", "受控验证已执行，但没有形成可确认漏洞的证据。"
        if actions:
            return "仅完成探测/未进入成功验证", "当前结果主要来自探测与枚举，尚未形成成功的高风险验证证据。"
        return "流程未完成", "没有足够的执行证据用于形成验证结论。"
