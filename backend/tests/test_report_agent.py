from __future__ import annotations

from datetime import UTC, datetime

from app.agents.report_agent import ReportAgent
from app.agents.result_parser import ResultParser
from app.schemas.task import ArtifactRecord, TaskDetail, TaskEvent
from app.schemas.tool import ToolExecutionResult
from app.services.artifact_store import ArtifactStore


def _now() -> datetime:
    return datetime.now(UTC)


def test_result_parser_records_poc_details_from_vuln_verify() -> None:
    parser = ResultParser()
    state = {
        "evidence": [],
        "findings": [],
        "pocs": [],
    }

    parser.apply(
        state,
        ToolExecutionResult(
            tool_name="vuln_verify",
            success=True,
            summary="confirmed",
            structured_data={
                "url": "http://127.0.0.1:4280/vulnerabilities/fi/?page=../../hackable/flags/fi.php",
                "profile": "php_apache",
                "verification_status": "confirmed",
                "issues": [],
                "findings": [
                    {
                        "title": "DVWA File Inclusion low-level PoC reproduced",
                        "severity": "high",
                        "confidence": "confirmed",
                        "evidence_summary": "Controlled include returned the expected markers.",
                    }
                ],
                "evidence": [
                    {
                        "kind": "dvwa_fi_poc",
                        "target": "127.0.0.1",
                        "port": 4280,
                        "summary": "PoC reproduced",
                        "data": {"matched_markers": ["Bond. James Bond"]},
                    }
                ],
                "pocs": [
                    {
                        "id": "dvwa-fi-low",
                        "title": "DVWA File Inclusion low-level PoC",
                        "status": "confirmed",
                        "method": "GET",
                        "url": "http://127.0.0.1:4280/vulnerabilities/fi/?page=../../hackable/flags/fi.php",
                        "params": {"page": "../../hackable/flags/fi.php"},
                        "success_evidence": ["Bond. James Bond"],
                    }
                ],
            },
        ),
    )

    assert state["pocs"][0]["id"] == "dvwa-fi-low"
    assert state["pocs"][0]["success_evidence"] == ["Bond. James Bond"]
    assert any(item["kind"] == "dvwa_fi_poc" for item in state["evidence"])


def test_report_agent_renders_poc_section(tmp_path) -> None:
    now = _now()
    agent = ReportAgent(ArtifactStore(tmp_path))
    task = TaskDetail(
        id="dvwa-task",
        name="DVWA File Inclusion Report",
        scope=["127.0.0.1"],
        authorization="authorized local dvwa lab",
        lab_description="DVWA local lab",
        objective="Run a single approved PoC and capture request/response evidence.",
        ports="4280",
        current_stage="generate_report",
        status="completed",
        created_at=now,
        updated_at=now,
        started_at=now,
        finished_at=now,
        report_path=None,
        stop_reason=None,
        state={
            "hosts": [{"address": "127.0.0.1", "status": "up"}],
            "services": [
                {
                    "target": "127.0.0.1",
                    "port": 4280,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "Apache httpd",
                    "version": "2.4",
                }
            ],
            "findings": [
                {
                    "title": "DVWA File Inclusion low-level PoC reproduced",
                    "severity": "high",
                    "confidence": "confirmed",
                    "evidence_summary": "A controlled include returned the expected DVWA flag content.",
                }
            ],
            "hypotheses": [],
            "evidence": [],
            "pocs": [
                {
                    "id": "dvwa-fi-low",
                    "title": "DVWA File Inclusion low-level PoC",
                    "module": "file_inclusion",
                    "status": "confirmed",
                    "method": "GET",
                    "url": "http://127.0.0.1:4280/vulnerabilities/fi/?page=../../hackable/flags/fi.php",
                    "params": {"page": "../../hackable/flags/fi.php"},
                    "request_excerpt": "GET /vulnerabilities/fi/?page=..%2F..%2Fhackable%2Fflags%2Ffi.php HTTP/1.1",
                    "response_excerpt": "1.) Bond. James Bond",
                    "success_evidence": ["Bond. James Bond", "The pool on the roof must have a leak."],
                    "notes": ["Authentication was not required."],
                    "evidence_files": ["/tmp/request.txt", "/tmp/response.html"],
                }
            ],
            "reflections": [
                {
                    "summary": "The first exploit attempt was malformed; prefer the refined raw request next.",
                    "source": "corpus_reflection",
                    "failure_class": "parse_failure",
                    "selected_family": "absolute_path",
                    "rejected_families": ["empty_header"],
                    "family_switch_reason": "The parse failure suggests the empty_header shape is too brittle, so the next attempt emphasizes absolute_path handling with a cleaner request.",
                    "hypotheses": [
                        {
                            "title": "Exploit syntax may be wrong",
                            "rationale": "The target reported a parse failure.",
                        }
                    ],
                    "next_candidates": [
                        {
                            "tool_name": "raw_http",
                            "title": "Refined raw HTTP empty Host header exploit",
                            "rationale": "Retry with a standards-compliant request shape.",
                            "family_details": [
                                {"id": "empty_header", "title": "Empty Header", "description": "Use an explicitly empty header."},
                                {"id": "absolute_path", "title": "Absolute Path", "description": "Request an absolute file path."},
                            ],
                        }
                    ],
                }
            ],
            "actions": [{"tool_name": "vuln_verify", "stage": "vuln_verify", "success": True}],
            "path_graph": {"nodes": [], "edges": []},
        },
    )
    events = [
        TaskEvent(
            id=1,
            task_id=task.id,
            event_type="tool_completed",
            stage="vuln_verify",
            message="Tool vuln_verify completed successfully.",
            payload={},
            created_at=now,
        )
    ]

    markdown_content, html_content, report_path = agent.generate(task, events, [], [])

    assert "## PoC 明细" in markdown_content
    assert "../../hackable/flags/fi.php" in markdown_content
    assert "Bond. James Bond" in markdown_content
    assert "```http" in markdown_content
    assert "PoC 1: DVWA File Inclusion low-level PoC" in markdown_content
    assert "## 反思与下一跳" in markdown_content
    assert "Refined raw HTTP empty Host header exploit" in markdown_content
    assert "Empty Header" in markdown_content
    assert "parse_failure" in markdown_content
    assert "empty_header" in markdown_content
    assert "absolute_path" in markdown_content
    assert report_path.endswith("report.md")
    assert "<h2>PoC 明细</h2>" in html_content


def test_report_agent_synthesizes_poc_when_confirmed_finding_has_no_recorded_poc(tmp_path) -> None:
    now = _now()
    agent = ReportAgent(ArtifactStore(tmp_path))
    task = TaskDetail(
        id="jsonrpc-task",
        name="JSON-RPC Report",
        scope=["127.0.0.1"],
        authorization="authorized local lab",
        lab_description="aria2 json-rpc service on port 6800",
        objective="Confirm unauthorized JSON-RPC access.",
        ports="6800",
        current_stage="generate_report",
        status="completed",
        created_at=now,
        updated_at=now,
        started_at=now,
        finished_at=now,
        report_path=None,
        stop_reason=None,
        state={
            "hosts": [{"address": "127.0.0.1", "status": "up"}],
            "services": [
                {
                    "target": "127.0.0.1",
                    "port": 6800,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "aria2 downloader JSON-RPC",
                    "version": "1.18.8",
                }
            ],
            "findings": [
                {
                    "title": "Unauthenticated JSON-RPC method call succeeded on /jsonrpc",
                    "severity": "high",
                    "confidence": "confirmed",
                    "evidence_summary": "Safe method aria2.getVersion returned a JSON-RPC result without authentication.",
                }
            ],
            "hypotheses": [],
            "evidence": [
                {
                    "kind": "http_request",
                    "target": "127.0.0.1",
                    "port": 6800,
                    "summary": "POST /jsonrpc -> 200",
                    "data": {
                        "url": "http://127.0.0.1:6800/jsonrpc",
                        "path": "/jsonrpc",
                        "status_code": 200,
                        "headers": {"Content-Type": "application/json-rpc"},
                        "body_snippet": '{"id":1,"jsonrpc":"2.0","result":{"version":"1.18.8"}}',
                        "method": "POST",
                        "request_headers": {"Content-Type": "application/json"},
                        "request_body": '{"jsonrpc":"2.0","id":1,"method":"aria2.getVersion","params":[]}',
                    },
                }
            ],
            "pocs": [],
            "reflections": [],
            "actions": [
                {
                    "tool_name": "http_request",
                    "stage": "observe",
                    "success": True,
                    "summary": "POST /jsonrpc returned HTTP 200.",
                    "params": {
                        "target": "127.0.0.1",
                        "port": 6800,
                        "scheme": "http",
                        "path": "/jsonrpc",
                        "method": "POST",
                        "headers": {"Content-Type": "application/json"},
                        "body": '{"jsonrpc":"2.0","id":1,"method":"aria2.getVersion","params":[]}',
                    },
                }
            ],
            "path_graph": {"nodes": [], "edges": []},
        },
    )
    artifacts = [
        ArtifactRecord(
            id="artifact-1",
            task_id=task.id,
            artifact_type="http_request",
            title="http_request output",
            path="/tmp/http_request.json",
            summary="POST /jsonrpc returned HTTP 200.",
            created_at=now,
        )
    ]

    markdown_content, html_content, report_path = agent.generate(task, [], [], artifacts)

    assert "Auto-generated PoC draft" in markdown_content
    assert "aria2.getVersion" in markdown_content
    assert "/jsonrpc" in markdown_content
    assert "Unauthenticated JSON-RPC method call succeeded" in markdown_content
    assert "```http" in markdown_content
    assert "/tmp/http_request.json" in markdown_content
    assert report_path.endswith("report.md")
    assert "<h2>PoC 明细</h2>" in html_content
