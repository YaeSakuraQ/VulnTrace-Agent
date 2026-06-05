from __future__ import annotations

from typing import Any

from app.schemas.tool import ToolExecutionResult


class ResultParser:
    def apply(self, state: dict[str, Any], result: ToolExecutionResult) -> dict[str, Any]:
        if not result.success:
            state["error_count"] = state.get("error_count", 0) + 1
            state["last_summary"] = result.error or result.summary
            return state

        state["error_count"] = 0
        state["last_result"] = result.model_dump()
        state["last_summary"] = result.summary

        if result.tool_name == "asset_discovery":
            self._merge_hosts(state, result.structured_data.get("hosts", []))
        elif result.tool_name == "service_fingerprint":
            self._merge_services(state, result.structured_data.get("services", []))
        elif result.tool_name == "web_probe":
            self._merge_web_probe(state, result.structured_data.get("responses", []))
        elif result.tool_name == "http_get":
            self._merge_http_get(state, result.structured_data)
        elif result.tool_name == "http_request":
            self._merge_http_request(state, result.structured_data)
        elif result.tool_name == "dir_enum":
            self._merge_dir_enum(state, result.structured_data.get("paths", []))
        elif result.tool_name == "ffuf_enum":
            self._merge_ffuf_enum(state, result.structured_data.get("paths", []))
        elif result.tool_name == "http_snapshot":
            self._merge_http_snapshot(state, result.structured_data.get("snapshots", []))
        elif result.tool_name == "template_runner":
            self._merge_template_runner(state, result.structured_data)
        elif result.tool_name in {"header_mutation", "raw_http"}:
            self._merge_raw_http_like(state, result.tool_name, result.structured_data)
        elif result.tool_name == "tcp_send":
            self._merge_tcp_send(state, result.structured_data)
        elif result.tool_name == "vuln_verify":
            self._merge_verify(
                state,
                issues=result.structured_data.get("issues", []),
                url=result.structured_data.get("url", ""),
                profile=result.structured_data.get("profile", ""),
                verification_status=result.structured_data.get("verification_status", ""),
                findings=result.structured_data.get("findings", []),
                evidence=result.structured_data.get("evidence", []),
                pocs=result.structured_data.get("pocs", []),
            )

        return state

    def _merge_hosts(self, state: dict[str, Any], hosts: list[dict[str, Any]]) -> None:
        existing = {host["address"] for host in state.get("hosts", [])}
        for host in hosts:
            if host["address"] not in existing:
                state.setdefault("hosts", []).append(host)

    def _merge_services(self, state: dict[str, Any], services: list[dict[str, Any]]) -> None:
        existing = {
            (service["target"], service["port"], service["protocol"])
            for service in state.get("services", [])
        }
        for service in services:
            key = (service["target"], service["port"], service["protocol"])
            if key in existing:
                continue
            state.setdefault("services", []).append(service)
            existing.add(key)
            if "http" in str(service.get("service", "")).lower() or int(service.get("port", 0)) in {80, 443, 3000, 4173, 5000, 5173, 8080, 8443}:
                self._append_hypothesis(
                    state,
                    title=f"Inspect web surface on {service['target']}:{service['port']}",
                    rationale="HTTP-facing service discovered during fingerprinting.",
                    severity="medium",
                )

    def _merge_web_probe(self, state: dict[str, Any], responses: list[dict[str, Any]]) -> None:
        for response in responses:
            state.setdefault("evidence", []).append(
                {
                    "kind": "web_probe",
                    "target": self._extract_target(response["url"]),
                    "port": self._extract_port(response["url"]),
                    "summary": f"{response['path']} -> {response['status_code']} {response.get('title', '')}".strip(),
                    "data": response,
                }
            )

    def _merge_dir_enum(self, state: dict[str, Any], paths: list[dict[str, Any]]) -> None:
        for item in paths:
            state.setdefault("evidence", []).append(
                {
                    "kind": "dir_enum",
                    "target": self._extract_target(item["url"]),
                    "port": self._extract_port(item["url"]),
                    "summary": f"{item['path']} returned {item['status_code']}",
                    "data": item,
                }
            )
            if any(marker in item["path"] for marker in [".git", "backup", "phpinfo", "server-status"]):
                state.setdefault("findings", []).append(
                    {
                        "title": f"Interesting exposed path: {item['path']}",
                        "severity": "medium",
                        "confidence": "suspected",
                        "evidence_summary": f"{item['path']} returned status {item['status_code']}",
                    }
                )

    def _merge_http_get(self, state: dict[str, Any], response: dict[str, Any]) -> None:
        if not response:
            return
        state.setdefault("evidence", []).append(
            {
                "kind": "http_get",
                "target": self._extract_target(response.get("url", "")),
                "port": self._extract_port(response.get("url", "")),
                "summary": f"{response.get('path', '/')} -> {response.get('status_code', 0)} {response.get('title', '')}".strip(),
                "data": response,
            }
        )

    def _merge_http_request(self, state: dict[str, Any], response: dict[str, Any]) -> None:
        if not response:
            return
        state.setdefault("evidence", []).append(
            {
                "kind": "http_request",
                "target": self._extract_target(response.get("url", "")),
                "port": self._extract_port(response.get("url", "")),
                "summary": (
                    f"{response.get('method', 'GET')} {response.get('path', '/')} -> "
                    f"{response.get('status_code', 0)} {response.get('title', '')}"
                ).strip(),
                "data": response,
            }
        )

    def _merge_ffuf_enum(self, state: dict[str, Any], paths: list[dict[str, Any]]) -> None:
        for item in paths:
            state.setdefault("evidence", []).append(
                {
                    "kind": "ffuf_enum",
                    "target": self._extract_target(item["url"]),
                    "port": self._extract_port(item["url"]),
                    "summary": f"{item['path']} returned {item['status_code']}",
                    "data": item,
                }
            )
            if item.get("status_code") in {200, 301, 302, 401, 403}:
                state.setdefault("findings", []).append(
                    {
                        "title": f"Interesting ffuf match: {item['path']}",
                        "severity": "medium",
                        "confidence": "suspected",
                        "evidence_summary": f"ffuf observed status {item['status_code']} on {item['path']}",
                    }
                )

    def _merge_http_snapshot(self, state: dict[str, Any], snapshots: list[dict[str, Any]]) -> None:
        for item in snapshots:
            state.setdefault("evidence", []).append(
                {
                    "kind": "http_snapshot",
                    "target": self._extract_target(item["url"]),
                    "port": self._extract_port(item["url"]),
                    "summary": f"{item['path']} -> {item['status_code']} snapshot captured",
                    "data": item,
                }
            )

    def _merge_template_runner(self, state: dict[str, Any], result: dict[str, Any]) -> None:
        target_url = str(result.get("target", ""))
        state.setdefault("evidence", []).append(
            {
                "kind": "template_runner",
                "target": self._extract_target(target_url),
                "port": self._extract_port(target_url),
                "summary": f"{result.get('template', 'template')} produced {len(result.get('issues', []))} issue(s)",
                "data": result,
            }
        )
        for issue in result.get("issues", []):
            state.setdefault("findings", []).append(
                {
                    "title": str(issue),
                    "severity": "medium",
                    "confidence": "suspected",
                    "evidence_summary": f"Template runner observation against {target_url}",
                }
            )

    def _merge_raw_http_like(
        self,
        state: dict[str, Any],
        tool_name: str,
        result: dict[str, Any],
    ) -> None:
        body_preview = str(result.get("body_preview", ""))
        status_code = int(result.get("status_code", 0))
        target = state.get("scope", [""])[0]
        port = int(state.get("ports", "0").split(",")[0].split("-")[0] or 0)
        state.setdefault("evidence", []).append(
            {
                "kind": tool_name,
                "target": target,
                "port": port,
                "summary": f"{tool_name} returned HTTP {status_code}",
                "data": result,
            }
        )
        if "root:x:0:0:" in body_preview:
            state.setdefault("findings", []).append(
                {
                    "title": "Arbitrary file read reproduced from raw HTTP primitive",
                    "severity": "high",
                    "confidence": "confirmed",
                    "evidence_summary": "The response preview contained /etc/passwd markers after a concrete exploit request.",
                }
            )
            # ── Also create a PoC record so the frontend summary tab shows it ──
            poc_id = f"{tool_name}-file-read-{target}-{port}"
            existing_keys = {
                (str(i.get("id", "")), str(i.get("url", "")))
                for i in state.get("pocs", [])
            }
            poc_key = (
                poc_id,
                f"http://{target}:{port}{result.get('path', '/')}",
            )
            if poc_key not in existing_keys:
                state.setdefault("pocs", []).append(
                    {
                        "id": poc_id,
                        "title": "Arbitrary file read (e.g. /etc/passwd)",
                        "status": "confirmed",
                        "module": tool_name,
                        "method": result.get("method", "GET"),
                        "path": result.get("path", "/etc/passwd"),
                        "url": f"http://{target}:{port}{result.get('path', '/etc/passwd')}",
                        "params": result.get("raw_request", ""),
                        "request_excerpt": result.get("raw_request", "")[:600],
                        "response_excerpt": result.get("raw_response", "")[:600],
                        "success_evidence": [
                            "/etc/passwd content confirmed",
                            body_preview[:120],
                        ],
                        "evidence_files": [],
                    }
                )

    def _merge_tcp_send(self, state: dict[str, Any], result: dict[str, Any]) -> None:
        target = state.get("scope", [""])[0]
        port = int(state.get("ports", "0").split(",")[0].split("-")[0] or 0)
        state.setdefault("evidence", []).append(
            {
                "kind": "tcp_send",
                "target": target,
                "port": port,
                "summary": "Low-level TCP payload executed.",
                "data": result,
            }
        )

    def _merge_verify(
        self,
        state: dict[str, Any],
        *,
        issues: list[dict[str, Any]],
        url: str,
        profile: str,
        verification_status: str,
        findings: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
        pocs: list[dict[str, Any]],
    ) -> None:
        state.setdefault("evidence", []).append(
            {
                "kind": "vuln_verify",
                "target": self._extract_target(url),
                "port": self._extract_port(url),
                "summary": f"Profile {profile or 'auto'} verification status: {verification_status or 'unknown'}",
                "data": {
                    "url": url,
                    "issues": issues,
                    "profile": profile,
                    "verification_status": verification_status,
                },
            }
        )
        existing_poc_keys = {
            (
                str(item.get("id", "")),
                str(item.get("url", "")),
                str(item.get("status", "")),
            )
            for item in state.get("pocs", [])
        }
        for poc in pocs:
            key = (
                str(poc.get("id", "")),
                str(poc.get("url", "")),
                str(poc.get("status", "")),
            )
            if key in existing_poc_keys:
                continue
            state.setdefault("pocs", []).append(poc)
            existing_poc_keys.add(key)
        for item in evidence:
            item_url = str(item.get("data", {}).get("url", url) or url)
            state.setdefault("evidence", []).append(
                {
                    "kind": str(item.get("kind", "vuln_verify_detail")),
                    "target": str(item.get("target") or self._extract_target(item_url)),
                    "port": int(item.get("port") or self._extract_port(item_url)),
                    "summary": str(item.get("summary", "")),
                    "data": item.get("data", {}),
                }
            )
        if findings:
            for finding in findings:
                state.setdefault("findings", []).append(
                    {
                        "title": finding.get("title", "Verification observation"),
                        "severity": finding.get("severity", "medium"),
                        "confidence": finding.get("confidence", "suspected"),
                        "evidence_summary": finding.get("evidence_summary", f"Verification against {url}"),
                    }
                )
            return
        for issue in issues:
            state.setdefault("findings", []).append(
                {
                    "title": issue["detail"],
                    "severity": "medium",
                    "confidence": "suspected",
                    "evidence_summary": f"Nikto verification against {url}",
                }
            )

    def _append_hypothesis(
        self,
        state: dict[str, Any],
        *,
        title: str,
        rationale: str,
        severity: str,
    ) -> None:
        existing = {item["title"] for item in state.get("hypotheses", [])}
        if title in existing:
            return
        state.setdefault("hypotheses", []).append(
            {
                "title": title,
                "rationale": rationale,
                "severity": severity,
                "status": "unverified",
            }
        )

    def _extract_target(self, url: str) -> str:
        without_scheme = url.split("://", 1)[-1]
        return without_scheme.split(":", 1)[0]

    def _extract_port(self, url: str) -> int:
        try:
            return int(url.split("://", 1)[-1].split(":", 1)[1].split("/", 1)[0])
        except (IndexError, ValueError):
            return 0
