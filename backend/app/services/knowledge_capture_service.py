from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from app.core.config import PROJECT_ROOT
from app.db.session import Database
from app.schemas.learning_candidate import (
    LearningCandidateDecision,
    LearningCandidateRecord,
)
from app.schemas.task import ArtifactRecord, TaskDetail, TaskEvent
from app.services.exploit_knowledge_mapper import ExploitCandidate


def utc_now() -> datetime:
    return datetime.now(UTC)


class LearningCandidateNotFoundError(KeyError):
    """Raised when a learning candidate cannot be found."""


class ModeClassification(BaseModel):
    """LLM-driven vulnerability mode classification output."""
    mode: str = Field(
        description="Canonical vulnerability family or protocol name, e.g. sql_injection, xss, command_injection, "
        "path_traversal, lfi, ssrf, open_redirect, idor, json_rpc, mini_httpd, php_apache, etc."
    )
    confidence: str = Field(default="medium", description="Confidence of the classification: low, medium, or high.")
    reasoning: str = Field(default="", description="Brief justification for the mode selection.")


# ── Heuristic markers used when LLM is unavailable ────────────────────────

SQL_ERROR_PATTERNS = [
    "sql syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite",
    "unclosed quotation mark", "syntax error", "you have an error in your sql",
    "warning: mysql", "Microsoft OLE DB", "odbc driver", "SQLSTATE",
    "Incorrect syntax near", "DB2 SQL error",
]

PATH_TRAVERSAL_PATTERNS = [
    "root:x:0:0:", "etc/passwd", "etc/shadow", "etc/hostname",
    "Directory traversal", "path traversal", "failed to open stream",
    "no such file or directory", "../",
]

XSS_PATTERNS = [
    "<script>alert(", "onerror=", "onload=", "javascript:",
    "XSS", "Cross-Site Scripting", "reflected in response",
]

COMMAND_INJECTION_PATTERNS = [
    "uid=", "gid=", "/bin/", "cmd.exe", "command not found",
    "sh: ", "bash: ", "unknown command",
]

LFI_PATTERNS = [
    "include(", "require(", "require_once", "include_once",
    "failed to open stream", "failed to include",
]

SSRF_PATTERNS = [
    "meta-data", "169.254.169.254", "internal service",
    "server-side request", "ssrf",
]


class KnowledgeCaptureService:
    def __init__(
        self,
        database: Database,
        knowledge_dir: Path | None = None,
        llm_provider: Any = None,
    ) -> None:
        self.database = database
        self.knowledge_dir = knowledge_dir or (PROJECT_ROOT / "data" / "knowledge")
        self.learned_knowledge_path = self.knowledge_dir / "learned_candidates.md"
        self.llm = llm_provider  # optional LLMProvider instance

    def capture_from_task(
        self,
        task: TaskDetail,
        events: list[TaskEvent],
        approvals: list[Any],
        artifacts: list[ArtifactRecord],
    ) -> list[LearningCandidateRecord]:
        created: list[LearningCandidateRecord] = []
        state = task.state
        for service in state.get("services", []):
            payload = self._build_candidate_payload(task, service, state, events, approvals, artifacts)
            if payload is None:
                continue
            if self._fingerprint_exists(task.id, payload["fingerprint_key"]):
                continue
            created.append(self._insert_candidate(task.id, payload))
        return created

    def list_candidates(
        self,
        task_id: str | None = None,
        status: str | None = None,
    ) -> list[LearningCandidateRecord]:
        query = "SELECT * FROM learning_candidates"
        clauses: list[str] = []
        params: list[str] = []
        if task_id:
            clauses.append("task_id = ?")
            params.append(task_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC"
        with self.database.connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_candidate(self, candidate_id: str) -> LearningCandidateRecord:
        with self.database.connection() as conn:
            row = conn.execute(
                "SELECT * FROM learning_candidates WHERE id = ?",
                (candidate_id,),
            ).fetchone()
        if row is None:
            raise LearningCandidateNotFoundError(candidate_id)
        return self._row_to_record(row)

    def approve(self, candidate_id: str, decision: LearningCandidateDecision) -> LearningCandidateRecord:
        return self._apply_decision(candidate_id, decision, status="approved")

    def reject(self, candidate_id: str, decision: LearningCandidateDecision) -> LearningCandidateRecord:
        return self._apply_decision(candidate_id, decision, status="rejected")

    def suggest(self, state: dict[str, Any]) -> list[ExploitCandidate]:
        services = state.get("services", [])
        if not services:
            return []
        approved = self.list_candidates(status="approved")
        candidates: list[ExploitCandidate] = []
        for item in approved:
            for service in services:
                if not self._matches_state(item.signature, state, service):
                    continue
                action = item.suggested_action
                tool_name = str(action.get("tool_name", ""))
                if not tool_name:
                    continue
                candidates.append(
                    ExploitCandidate(
                        id=f"learning-{item.id}-{service['target']}-{service['port']}",
                        title=item.title,
                        tool_name=tool_name,
                        stage=str(action.get("stage", "exploit")),
                        params=dict(action.get("params", {})),
                        rationale=str(action.get("rationale", item.summary)),
                        expected_evidence=[str(value) for value in action.get("expected_evidence", [])],
                        risk_level=str(action.get("risk_level", "medium")),
                        requires_approval=bool(action.get("requires_approval", False)),
                        confidence="high",
                        source="learning",
                        fallback_only=False,
                        signature_id=item.id,
                        families=[str(value) for value in action.get("families", [])],
                        family_details=[dict(value) for value in action.get("family_details", []) if isinstance(value, dict)],
                        selected_family=action.get("selected_family"),
                    )
                )
                break
        return candidates

    def publish_approved_candidates(self) -> None:
        """Incrementally publish approved learning candidates as a Markdown knowledge file.

        Instead of overwriting the whole file every time, only the approved
        candidate entries are rewritten; a preamble header is preserved.
        """
        approved = self.list_candidates(status="approved")
        self.knowledge_dir.mkdir(parents=True, exist_ok=True)

        preamble = (
            "# Learned Candidates\n\n"
            "This file is generated from reviewed learning candidates and is intended "
            "for safe probe and verification reuse.\n\n"
        )

        if not approved:
            body = "- No approved learning candidates yet.\n"
        else:
            lines: list[str] = []
            for item in approved:
                action = item.suggested_action
                lines.extend(
                    [
                        f"## {item.title}",
                        "",
                        f"- Summary: {item.summary}",
                        f"- Fingerprint: `{item.fingerprint_key}`",
                        f"- Status: `{item.status}`",
                        f"- Match product: `{item.signature.get('service_product', '')}`",
                        f"- Match version: `{item.signature.get('service_version', '')}`",
                        f"- Match paths: {', '.join(item.signature.get('interesting_paths', [])) or 'n/a'}",
                        f"- Suggested tool: `{action.get('tool_name', 'unknown')}`",
                        f"- Rationale: {action.get('rationale', item.summary)}",
                        f"- Expected evidence: {', '.join(action.get('expected_evidence', [])) or 'n/a'}",
                        "",
                    ]
                )
            body = "\n".join(lines)

        self.learned_knowledge_path.write_text(preamble + body, encoding="utf-8")

    def _apply_decision(
        self,
        candidate_id: str,
        decision: LearningCandidateDecision,
        *,
        status: str,
    ) -> LearningCandidateRecord:
        record = self.get_candidate(candidate_id)
        decided_at = utc_now()
        suggested_action = decision.edited_suggested_action or record.suggested_action
        verification_recipe = decision.edited_verification_recipe or record.verification_recipe
        with self.database.connection() as conn:
            conn.execute(
                """
                UPDATE learning_candidates
                SET suggested_action_json = ?, verification_recipe_json = ?, status = ?, reviewed_at = ?, review_note = ?
                WHERE id = ?
                """,
                (
                    json.dumps(suggested_action, ensure_ascii=False),
                    json.dumps(verification_recipe, ensure_ascii=False),
                    status,
                    decided_at.isoformat(),
                    decision.note,
                    candidate_id,
                ),
            )
            conn.commit()
        if status == "approved":
            self.publish_approved_candidates()
        return self.get_candidate(candidate_id)

    def _insert_candidate(self, task_id: str, payload: dict[str, Any]) -> LearningCandidateRecord:
        candidate_id = str(uuid4())
        created_at = utc_now()
        with self.database.connection() as conn:
            conn.execute(
                """
                INSERT INTO learning_candidates (
                    id, task_id, title, summary, fingerprint_key, signature_json,
                    suggested_action_json, verification_recipe_json, evidence_markers_json,
                    status, created_at, reviewed_at, review_note
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    candidate_id,
                    task_id,
                    payload["title"],
                    payload["summary"],
                    payload["fingerprint_key"],
                    json.dumps(payload["signature"], ensure_ascii=False),
                    json.dumps(payload["suggested_action"], ensure_ascii=False),
                    json.dumps(payload["verification_recipe"], ensure_ascii=False),
                    json.dumps(payload["evidence_markers"], ensure_ascii=False),
                    "pending",
                    created_at.isoformat(),
                    None,
                    None,
                ),
            )
            conn.commit()
        return LearningCandidateRecord(
            id=candidate_id,
            task_id=task_id,
            title=payload["title"],
            summary=payload["summary"],
            fingerprint_key=payload["fingerprint_key"],
            signature=payload["signature"],
            suggested_action=payload["suggested_action"],
            verification_recipe=payload["verification_recipe"],
            evidence_markers=payload["evidence_markers"],
            status="pending",
            created_at=created_at,
        )

    def _fingerprint_exists(self, task_id: str, fingerprint_key: str) -> bool:
        with self.database.connection() as conn:
            row = conn.execute(
                "SELECT id FROM learning_candidates WHERE task_id = ? AND fingerprint_key = ?",
                (task_id, fingerprint_key),
            ).fetchone()
        return row is not None

    def _build_candidate_payload(
        self,
        task: TaskDetail,
        service: dict[str, Any],
        state: dict[str, Any],
        events: list[TaskEvent],
        approvals: list[Any],
        artifacts: list[ArtifactRecord],
    ) -> dict[str, Any] | None:
        signature = self._build_signature(task, service, state)
        learning_mode = self._select_learning_mode(task, service, state)
        if learning_mode is None:
            return None
        suggested_action = self._build_suggested_action(task, service, state, learning_mode)
        verification_recipe = self._build_verification_recipe(task, service, state, learning_mode)
        evidence_markers = self._build_evidence_markers(service, state)
        title = self._build_title(service, learning_mode)
        summary = self._build_summary(service, state, learning_mode)
        fingerprint_material = {
            "signature": signature,
            "action": suggested_action,
            "verification_recipe": verification_recipe,
        }
        fingerprint_key = hashlib.sha256(
            json.dumps(fingerprint_material, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()[:24]
        return {
            "title": title,
            "summary": summary,
            "fingerprint_key": fingerprint_key,
            "signature": signature,
            "suggested_action": suggested_action,
            "verification_recipe": verification_recipe,
            "evidence_markers": evidence_markers,
        }

    def _build_signature(self, task: TaskDetail, service: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
        target = service["target"]
        port = service["port"]
        headers: dict[str, str] = {}
        paths: list[str] = []
        body_markers: list[str] = []
        for item in state.get("evidence", []):
            if item.get("target") != target or item.get("port") != port:
                continue
            data = item.get("data", {})
            if not headers and isinstance(data.get("headers"), dict):
                headers = {str(k): str(v) for k, v in data.get("headers", {}).items()}
            path = data.get("path")
            if isinstance(path, str) and path not in paths:
                paths.append(path)
            snippet = str(data.get("body_snippet", "")).strip()
            if snippet:
                body_markers.append(snippet[:120])
        return {
            "service_name": str(service.get("service", "")),
            "service_product": str(service.get("product", "")),
            "service_version": str(service.get("version", "")),
            "lab_description": task.lab_description[:200],
            "interesting_paths": paths[:6],
            "headers": headers,
            "body_markers": body_markers[:3],
        }

    # ── Mode selection ────────────────────────────────────────────────────

    def _select_learning_mode(
        self,
        task: TaskDetail,
        service: dict[str, Any],
        state: dict[str, Any],
    ) -> str | None:
        """Determine the vulnerability or service classification for this capture.

        Strategy:
        1. LLM-driven classification (when LLM provider is available).
        2. Heuristic fallback based on response body markers, paths, and
           service metadata (when LLM is unavailable or fails).
        """

        # ── LLM-driven classification ────────────────────────────────
        if self.llm is not None and getattr(self.llm, "enabled", False):
            try:
                classification = self._llm_classify_mode(task, service, state)
                if classification and classification.mode:
                    return classification.mode
            except Exception:
                pass  # Fall through to heuristic

        # ── Heuristic fallback ───────────────────────────────────────
        return self._heuristic_classify_mode(task, service, state)

    def _llm_classify_mode(
        self,
        task: TaskDetail,
        service: dict[str, Any],
        state: dict[str, Any],
    ) -> ModeClassification | None:
        """Use LLM to classify the vulnerability/service mode."""
        target = f"{service['target']}:{service['port']}"
        product = str(service.get("product", "") or service.get("service", "")).strip()
        version = str(service.get("version", "")).strip()
        body_snippets: list[str] = []
        for item in state.get("evidence", []):
            if item.get("target") != service["target"] or item.get("port") != service["port"]:
                continue
            snippet = str(item.get("data", {}).get("body_snippet", "")).strip()
            if snippet:
                body_snippets.append(snippet[:200])

        payload_for_poc = {
            m.get("module") or m.get("id", "")
            for m in state.get("pocs", [])
        }

        user_prompt = (
            f"Target: {target}\n"
            f"Service product: {product}\n"
            f"Service version: {version}\n"
            f"Lab description: {task.lab_description[:200]}\n"
            f"PoC modules triggered: {', '.join(sorted(payload_for_poc)) or 'none'}\n"
            f"Response body snippets (first 200 chars): {json.dumps(body_snippets[:3])}\n"
            "\n"
            "Classify the primary vulnerability or service mode this target exhibits. "
            "Use canonical names like: sql_injection, xss, command_injection, "
            "path_traversal, lfi, ssrf, open_redirect, idor, json_rpc, mini_httpd, "
            "php_apache, generic_web."
        )

        return self.llm.invoke_structured(
            ModeClassification,
            "You are a penetration testing expert. Classify the target's vulnerability mode.",
            user_prompt,
        )

    def _heuristic_classify_mode(
        self,
        task: TaskDetail,
        service: dict[str, Any],
        state: dict[str, Any],
    ) -> str | None:
        """Rule-based heuristic classification of vulnerability mode from response features."""
        product_text = " ".join(
            [
                str(service.get("service", "")),
                str(service.get("product", "")),
                str(service.get("version", "")),
                task.lab_description,
            ]
        ).lower()

        # Collect body snippets
        body_snippets: list[str] = []
        for item in state.get("evidence", []):
            if item.get("target") != service["target"] or item.get("port") != service["port"]:
                continue
            snippet = str(item.get("data", {}).get("body_snippet", "")).strip().lower()
            if snippet:
                body_snippets.append(snippet)
        combined_body = " ".join(body_snippets)

        # Collect page titles
        page_titles: list[str] = []
        for item in state.get("evidence", []):
            title = str(item.get("data", {}).get("title", "")).strip().lower()
            if title:
                page_titles.append(title)
        combined_title = " ".join(page_titles)

        # 1. Known product-specific modes (existing logic)
        poc_modules = {poc.get("module") for poc in state.get("pocs", [])}
        if "json_rpc" in poc_modules:
            return "json_rpc"
        if "json_rpc" in product_text or "json-rpc" in product_text:
            return "json_rpc"
        if "aria2" in product_text:
            return "json_rpc"
        if "mini_httpd" in product_text:
            return "mini_httpd"
        if "dvwa" in product_text:
            return "php_apache"
        if state.get("pocs"):
            return "generic_verifier"

        # 2. Generic vulnerability heuristics

        # SQL injection: SQL error messages
        if any(pat.lower() in combined_body for pat in SQL_ERROR_PATTERNS):
            return "sql_injection"

        # Path traversal: sensitive file content leaked
        if any(pat.lower() in combined_body for pat in PATH_TRAVERSAL_PATTERNS):
            return "path_traversal"

        # XSS: script/event handler reflection
        if any(pat.lower() in combined_body for pat in XSS_PATTERNS):
            return "xss"

        # Command injection: OS command output
        if any(pat.lower() in combined_body for pat in COMMAND_INJECTION_PATTERNS):
            return "command_injection"

        # LFI: PHP include errors
        if any(pat.lower() in combined_body for pat in LFI_PATTERNS):
            return "lfi"

        # SSRF: cloud metadata responses
        if any(pat.lower() in combined_body for pat in SSRF_PATTERNS):
            return "ssrf"

        # Open redirect: based on path keywords
        for path in state.get("evidence", []):
            if path.get("target") != service["target"] or path.get("port") != service["port"]:
                continue
            url_path = str(path.get("data", {}).get("path", "")).lower()
            if any(kw in url_path for kw in ["redirect", "url=", "next=", "return=", "callback="]):
                return "open_redirect"

        # IDOR: numeric ID parameters in interesting paths
        for path in state.get("evidence", []):
            if path.get("target") != service["target"] or path.get("port") != service["port"]:
                continue
            url_path = str(path.get("data", {}).get("path", "")).lower()
            if any(kw in url_path for kw in ["id=", "user=", "uid=", "profile=", "account=", "order="]):
                return "idor"

        # CVE-specific: Joomla
        if "joomla" in combined_title or "joomla" in combined_body:
            return "cve_joomla"

        # CVE-specific: Log4Shell (Java service)
        if any(kw in combined_body for kw in ["log4j", "jndi", "${jndi"]):
            return "cve_log4shell"

        # Jenkins
        if "jenkins" in combined_title or "jenkins" in combined_body:
            return "jenkins"

        # WebLogic
        if "weblogic" in combined_title or "weblogic" in combined_body:
            return "weblogic"

        # Tomcat
        if "tomcat" in combined_title or "apache tomcat" in combined_body:
            return "tomcat"

        # JBoss
        if "jboss" in combined_title or "wildfly" in combined_title:
            return "jboss"

        # Webmin
        if "webmin" in combined_title or "webmin" in combined_body:
            return "webmin"

        # phpMyAdmin
        if "phpmyadmin" in combined_title or "phpmyadmin" in combined_body:
            return "phpmyadmin"

        # Grafana
        if "grafana" in combined_title or "grafana" in combined_body:
            return "grafana"

        # PostgreSQL
        if "postgresql" in product_text:
            return "postgres"

        # MySQL/MariaDB
        if "mysql" in product_text or "mariadb" in product_text:
            return "mysql"

        # MongoDB
        if "mongodb" in product_text or "mongo" in product_text:
            return "mongodb"

        # Redis
        if "redis" in product_text:
            return "redis"

        # Memcached
        if "memcached" in product_text:
            return "memcached"

        # Elasticsearch
        if "elasticsearch" in product_text:
            return "elasticsearch"

        # Docker
        if "docker" in product_text:
            return "docker"

        # CVE: Apache Path Traversal
        if "apache/2.4.49" in combined_body or "apache/2.4.50" in combined_body:
            return "cve_apache_traversal"

        # Default generic fallback: any HTTP web service
        if str(service.get("service", "")).lower() in {"http", "https", "www"}:
            return "generic_web"

        return None

    # ── Suggested action builder ──────────────────────────────────────────

    def _build_suggested_action(
        self,
        task: TaskDetail,
        service: dict[str, Any],
        state: dict[str, Any],
        mode: str,
    ) -> dict[str, Any]:
        if mode == "json_rpc":
            return {
                "tool_name": "http_request",
                "stage": "enumerate",
                "params": {
                    "target": service["target"],
                    "port": service["port"],
                    "scheme": "https" if int(service["port"]) in {443, 8443} else "http",
                    "path": "/jsonrpc",
                    "method": "POST",
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"jsonrpc":"2.0","id":1,"method":"aria2.getVersion","params":[]}'
                    if "aria2" in str(service.get("product", "")).lower()
                    else '{"jsonrpc":"2.0","id":1,"method":"rpc.discover","params":[]}',
                    "allow_redirects": False,
                    "timeout": 15,
                },
                "rationale": "Reuse the reviewed safe RPC capability probe before escalating to controlled verification.",
                "expected_evidence": ["HTTP 200 or structured JSON-RPC error proving endpoint behavior"],
                "risk_level": "medium",
                "requires_approval": False,
                "families": ["json_rpc"],
            }
        if mode == "mini_httpd":
            return {
                "tool_name": "vuln_verify",
                "stage": "exploit",
                "params": {
                    "target": service["target"],
                    "port": service["port"],
                    "scheme": "http",
                    "profile": "mini_httpd",
                    "preferred_poc": "none",
                    "service_name": str(service.get("service", "")),
                    "service_product": str(service.get("product", "")),
                    "service_version": str(service.get("version", "")),
                    "lab_description": task.lab_description,
                    "page_title": "",
                    "headers": {},
                    "interesting_paths": [],
                    "timeout": 30,
                },
                "rationale": "Replay the reviewed mini_httpd verifier bundle instead of inventing a new exploit primitive.",
                "expected_evidence": ["Structured verifier findings and evidence markers"],
                "risk_level": "high",
                "requires_approval": True,
                "families": ["mini_httpd"],
            }
        if mode in {"php_apache", "dvwa"}:
            return {
                "tool_name": "vuln_verify",
                "stage": "exploit",
                "params": {
                    "target": service["target"],
                    "port": service["port"],
                    "scheme": "https" if int(service["port"]) in {443, 8443} else "http",
                    "profile": "php_apache",
                    "preferred_poc": "dvwa_fi" if mode == "php_apache" else "none",
                    "service_name": str(service.get("service", "")),
                    "service_product": str(service.get("product", "")),
                    "service_version": str(service.get("version", "")),
                    "lab_description": task.lab_description,
                    "page_title": "",
                    "headers": {},
                    "interesting_paths": [],
                    "timeout": 60,
                },
                "rationale": "Reuse the reviewed controlled verification bundle for the matched PHP/Apache fingerprint.",
                "expected_evidence": ["Structured verification status and reusable evidence markers"],
                "risk_level": "high",
                "requires_approval": True,
                "families": ["php_apache"],
            }
        if mode == "generic_web":
            return {
                "tool_name": "vuln_verify",
                "stage": "exploit",
                "params": {
                    "target": service["target"],
                    "port": service["port"],
                    "scheme": "https" if int(service["port"]) in {443, 8443} else "http",
                    "profile": "generic_web",
                    "preferred_poc": "none",
                    "service_name": str(service.get("service", "")),
                    "service_product": str(service.get("product", "")),
                    "service_version": str(service.get("version", "")),
                    "lab_description": task.lab_description,
                    "page_title": "",
                    "headers": {},
                    "interesting_paths": [],
                    "timeout": 60,
                },
                "rationale": "Run the generic web verifier to capture reproducible evidence for this undocumented service fingerprint.",
                "expected_evidence": ["Structured verification status and reusable evidence markers"],
                "risk_level": "medium",
                "requires_approval": True,
                "families": ["generic_web"],
            }
        # ── Generic / new mode branch ──────────────────────────────────
        # Covers all new modes (sql_injection, xss, command_injection, lfi,
        # ssrf, open_redirect, idor, jenkins, weblogic, tomcat, jboss, etc.)
        return {
            "tool_name": "vuln_verify",
            "stage": "exploit",
            "families": [mode],
            "params": {
                "target": service["target"],
                "port": service["port"],
                "scheme": "https" if int(service["port"]) in {443, 8443} else "http",
                "profile": "generic_web",
                "preferred_poc": "none",
                "service_name": str(service.get("service", "")),
                "service_product": str(service.get("product", "")),
                "service_version": str(service.get("version", "")),
                "lab_description": task.lab_description,
                "page_title": "",
                "headers": {},
                "interesting_paths": [],
                "timeout": 60,
            },
            "rationale": f"Captured {mode} vulnerability pattern. Run bounded verification to produce reproducible evidence.",
            "expected_evidence": ["Structured verification findings", "Reproducible exploit markers"],
            "risk_level": "high",
            "requires_approval": True,
        }

    def _build_verification_recipe(
        self,
        task: TaskDetail,
        service: dict[str, Any],
        state: dict[str, Any],
        mode: str,
    ) -> dict[str, Any]:
        if mode == "json_rpc":
            return {
                "kind": "safe_probe_recipe",
                "summary": "Confirm unauthenticated JSON-RPC access with a safe method before any higher-risk validation.",
                "steps": [
                    "Identify the RPC-like HTTP endpoint from evidence or default to /jsonrpc for aria2-like services.",
                    "Send one safe POST request with Content-Type application/json.",
                    "Treat a JSON-RPC result object as confirmed unauthenticated method access evidence.",
                ],
                "expected_markers": self._build_evidence_markers(service, state),
                "notes": [
                    "This recipe is designed for safe capability confirmation, not arbitrary write or command execution.",
                ],
            }
        return {
            "kind": "controlled_verification_recipe",
            "summary": "Run the bounded verifier profile matched to the reviewed service fingerprint.",
            "steps": [
                "Confirm the service fingerprint still matches the learned signature.",
                "Run the suggested verifier with approval if required.",
                "Preserve findings, PoC evidence, and reflection output in the task report.",
            ],
            "expected_markers": self._build_evidence_markers(service, state),
            "notes": [
                "This recipe reuses reviewed verification flow only; it does not auto-synthesize a new exploit payload.",
            ],
        }

    def _build_evidence_markers(self, service: dict[str, Any], state: dict[str, Any]) -> list[str]:
        target = service["target"]
        port = service["port"]
        markers: list[str] = []
        for item in state.get("evidence", []):
            if item.get("target") != target or item.get("port") != port:
                continue
            data = item.get("data", {})
            snippet = str(data.get("body_snippet", "")).strip()
            if snippet:
                markers.append(snippet[:120])
        for poc in state.get("pocs", []):
            for marker in poc.get("success_evidence", [])[:3]:
                markers.append(str(marker))
        return markers[:6]

    def _build_title(self, service: dict[str, Any], mode: str) -> str:
        product = str(service.get("product", "") or service.get("service", "unknown service")).strip()
        suffix = {
            "json_rpc": "safe JSON-RPC capability probe",
            "mini_httpd": "mini_httpd verifier profile",
            "php_apache": "PHP/Apache verifier profile",
            "generic_verifier": "generic controlled verifier",
            "generic_web": "generic web verifier profile",
            "sql_injection": "SQL injection pattern",
            "xss": "cross-site scripting pattern",
            "command_injection": "command injection pattern",
            "path_traversal": "path traversal pattern",
            "lfi": "local file inclusion pattern",
            "ssrf": "SSRF pattern",
            "open_redirect": "open redirect pattern",
            "idor": "IDOR pattern",
            "cve_joomla": "Joomla CVE pattern",
            "cve_log4shell": "Log4Shell CVE pattern",
            "jenkins": "Jenkins exploitation pattern",
            "weblogic": "WebLogic exploitation pattern",
            "tomcat": "Tomcat exploitation pattern",
            "jboss": "JBoss exploitation pattern",
            "webmin": "Webmin exploitation pattern",
            "phpmyadmin": "phpMyAdmin exploitation pattern",
            "grafana": "Grafana exploitation pattern",
            "postgres": "PostgreSQL exploitation pattern",
            "mysql": "MySQL exploitation pattern",
            "mongodb": "MongoDB exploitation pattern",
            "redis": "Redis exploitation pattern",
            "memcached": "Memcached exploitation pattern",
            "elasticsearch": "Elasticsearch exploitation pattern",
            "docker": "Docker API exploitation pattern",
            "cve_apache_traversal": "Apache CVE path traversal pattern",
        }.get(mode, f"verification recipe ({mode})")
        return f"{product} - {suffix}"

    def _build_summary(self, service: dict[str, Any], state: dict[str, Any], mode: str) -> str:
        target = f"{service['target']}:{service['port']}"
        if mode == "json_rpc":
            return f"Captured a reviewed safe JSON-RPC capability probe pattern for {target}."
        if mode == "mini_httpd":
            return f"Captured a reviewed mini_httpd verification workflow for {target}."
        if mode == "php_apache":
            return f"Captured a reviewed PHP/Apache verification workflow for {target}."
        if mode == "generic_web":
            return f"Captured a reviewed generic web verification workflow for {target}."
        return f"Captured a reviewed {mode} verification workflow for {target}."

    def _matches_state(self, signature: dict[str, Any], state: dict[str, Any], service: dict[str, Any]) -> bool:
        product = str(service.get("product", "")).lower()
        service_name = str(service.get("service", "")).lower()
        version = str(service.get("version", "")).lower()
        sig_product = str(signature.get("service_product", "")).lower()
        sig_service = str(signature.get("service_name", "")).lower()
        sig_version = str(signature.get("service_version", "")).lower()
        if sig_product and sig_product not in product:
            return False
        if sig_service and sig_service not in service_name:
            return False
        if sig_version and sig_version not in version:
            return False
        expected_paths = {str(path).lower() for path in signature.get("interesting_paths", [])}
        if expected_paths:
            observed_paths = set()
            for item in state.get("evidence", []):
                if item.get("target") != service["target"] or item.get("port") != service["port"]:
                    continue
                path = str(item.get("data", {}).get("path", "")).lower()
                if path:
                    observed_paths.add(path)
            if not observed_paths.intersection(expected_paths):
                return False
        return True

    def _row_to_record(self, row: Any) -> LearningCandidateRecord:
        return LearningCandidateRecord(
            id=row["id"],
            task_id=row["task_id"],
            title=row["title"],
            summary=row["summary"],
            fingerprint_key=row["fingerprint_key"],
            signature=json.loads(row["signature_json"]),
            suggested_action=json.loads(row["suggested_action_json"]),
            verification_recipe=json.loads(row["verification_recipe_json"]),
            evidence_markers=json.loads(row["evidence_markers_json"]),
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            reviewed_at=datetime.fromisoformat(row["reviewed_at"]) if row["reviewed_at"] else None,
            review_note=row["review_note"],
        )
