from __future__ import annotations

from pathlib import Path

from app.agents.graph import PentestGraphRunner
from app.agents.planner import PlannerService
from app.agents.report_agent import ReportAgent
from app.agents.result_parser import ResultParser
from app.core.scope_guard import ScopeGuard
from app.db.session import Database
from app.schemas.approval import ApprovalDecision
from app.schemas.task import TaskCreate
from app.schemas.tool import ToolExecutionResult
from app.services.approval_service import ApprovalService
from app.services.artifact_store import ArtifactStore
from app.services.exploit_knowledge_mapper import ExploitKnowledgeMapper
from app.services.knowledge_retriever import KnowledgeRetriever
from app.services.task_service import TaskService
from app.tools.base import ToolExecutionError


class DummyDeepSeekClient:
    enabled = False


class DummyKnowledgeCaptureService:
    def suggest(self, state):
        return []


class FakeToolExecutor:
    def __init__(self, artifact_root: Path) -> None:
        self.artifact_root = artifact_root
        self.artifact_root.mkdir(parents=True, exist_ok=True)

    def execute(self, *, task_id: str, scope: list[str], stage: str, tool_name: str, params: dict) -> ToolExecutionResult:
        artifact_path = self.artifact_root / f"{tool_name}.json"
        artifact_path.write_text("{}", encoding="utf-8")
        if tool_name == "asset_discovery":
            return ToolExecutionResult(
                tool_name=tool_name,
                success=True,
                summary="1 host discovered",
                structured_data={"hosts": [{"address": "127.0.0.1", "status": "up", "source": "fake"}]},
                artifact_paths=[str(artifact_path)],
            )
        if tool_name == "service_fingerprint":
            return ToolExecutionResult(
                tool_name=tool_name,
                success=True,
                summary="1 service identified",
                structured_data={
                    "services": [
                        {
                            "target": "127.0.0.1",
                            "port": 8088,
                            "protocol": "tcp",
                            "service": "http",
                            "product": "mini_httpd",
                            "version": "1.29",
                        }
                    ]
                },
                artifact_paths=[str(artifact_path)],
            )
        if tool_name == "http_get":
            return ToolExecutionResult(
                tool_name=tool_name,
                success=True,
                summary="HTTP GET completed",
                structured_data={
                    "url": "http://127.0.0.1:8088/",
                    "path": "/",
                    "status_code": 404,
                    "title": "404 Not Found",
                    "headers": {"server": "mini_httpd"},
                    "body_snippet": "404 Not Found",
                },
                artifact_paths=[str(artifact_path)],
            )
        if tool_name == "http_request":
            return ToolExecutionResult(
                tool_name=tool_name,
                success=True,
                summary="HTTP request completed",
                structured_data={
                    "url": "http://127.0.0.1:6800/jsonrpc",
                    "path": "/jsonrpc",
                    "status_code": 200,
                    "title": "",
                    "headers": {"content-type": "application/json-rpc"},
                    "body_snippet": '{"id":1,"jsonrpc":"2.0","result":{"version":"1.18.8"}}',
                    "method": "POST",
                    "request_headers": {"Content-Type": "application/json"},
                    "request_body": '{"jsonrpc":"2.0","id":1,"method":"aria2.getVersion","params":[]}',
                },
                artifact_paths=[str(artifact_path)],
            )
        if tool_name == "web_probe":
            return ToolExecutionResult(
                tool_name=tool_name,
                success=True,
                summary="HTTP probe completed",
                structured_data={
                    "responses": [
                        {
                            "url": "http://127.0.0.1:80/",
                            "path": "/",
                            "status_code": 200,
                            "title": "Demo",
                            "headers": {"server": "demo"},
                            "content_length": 100,
                        }
                    ]
                },
                artifact_paths=[str(artifact_path)],
            )
        if tool_name == "dir_enum":
            return ToolExecutionResult(
                tool_name=tool_name,
                success=True,
                summary="Directory enumeration completed",
                structured_data={
                    "paths": [
                        {
                            "path": "/phpinfo.php",
                            "url": "http://127.0.0.1:80/phpinfo.php",
                            "status_code": 200,
                            "content_length": 50,
                        }
                    ]
                },
                artifact_paths=[str(artifact_path)],
            )
        if tool_name == "ffuf_enum":
            return ToolExecutionResult(
                tool_name=tool_name,
                success=True,
                summary="ffuf enumeration completed",
                structured_data={
                    "paths": [
                        {
                            "path": "/admin",
                            "url": "http://127.0.0.1:80/admin",
                            "status_code": 403,
                            "content_length": 12,
                            "words": 2,
                            "lines": 1,
                            "content_type": "text/html",
                            "redirect_location": "",
                        }
                    ]
                },
                artifact_paths=[str(artifact_path)],
            )
        if tool_name == "http_snapshot":
            return ToolExecutionResult(
                tool_name=tool_name,
                success=True,
                summary="HTTP snapshot completed",
                structured_data={
                    "snapshots": [
                        {
                            "url": "http://127.0.0.1:80/",
                            "path": "/",
                            "status_code": 200,
                            "headers": {"server": "demo"},
                            "content_length": 100,
                            "body_snippet": "Demo landing page",
                        }
                    ]
                },
                artifact_paths=[str(artifact_path)],
            )
        if tool_name == "header_mutation":
            return ToolExecutionResult(
                tool_name=tool_name,
                success=True,
                summary="Mutated-header exploit returned HTTP 200.",
                structured_data={
                    "status_code": 200,
                    "headers": {"server": "mini_httpd"},
                    "body_preview": "root:x:0:0:root:/root:/bin/bash",
                    "raw_request": "GET /etc/passwd HTTP/1.1\r\nHost: \r\n\r\n",
                    "raw_response": "HTTP/1.1 200 OK\r\n\r\nroot:x:0:0:root:/root:/bin/bash",
                    "path": "/etc/passwd",
                    "method": "GET",
                },
                artifact_paths=[str(artifact_path)],
            )
        if tool_name == "template_runner":
            return ToolExecutionResult(
                tool_name=tool_name,
                success=True,
                summary="Nikto template collected 1 observation.",
                structured_data={
                    "template": "nikto_scan",
                    "target": "http://127.0.0.1:8088",
                    "issues": ["mini_httpd/1.29 appears outdated"],
                    "raw": "nikto raw output",
                },
                artifact_paths=[str(artifact_path)],
            )
        if tool_name == "vuln_verify":
            return ToolExecutionResult(
                tool_name=tool_name,
                success=True,
                summary="Nikto verification completed",
                structured_data={
                    "url": "http://127.0.0.1:80",
                    "issues": [{"detail": "Directory indexing appears enabled"}],
                },
                artifact_paths=[str(artifact_path)],
            )
        raise AssertionError(f"Unexpected tool: {tool_name}")


class FailingVerifyToolExecutor(FakeToolExecutor):
    def execute(self, *, task_id: str, scope: list[str], stage: str, tool_name: str, params: dict) -> ToolExecutionResult:
        if tool_name == "header_mutation":
            raise ToolExecutionError("Exploit primitive failed against the demo target.")
        return super().execute(task_id=task_id, scope=scope, stage=stage, tool_name=tool_name, params=params)


def build_graph_runner(
    tmp_path: Path,
    *,
    tool_executor: FakeToolExecutor | None = None,
) -> tuple[TaskService, ApprovalService, PentestGraphRunner]:
    database = Database(tmp_path / "test.db")
    database.init()
    task_service = TaskService(database)
    approval_service = ApprovalService(task_service)
    artifact_store = ArtifactStore(tmp_path / "artifacts")
    planner = PlannerService(
        deepseek_client=DummyDeepSeekClient(),
        exploit_mapper=ExploitKnowledgeMapper(),
        knowledge_retriever=KnowledgeRetriever(tmp_path / "knowledge"),
        knowledge_capture_service=DummyKnowledgeCaptureService(),
    )
    graph_runner = PentestGraphRunner(
        task_service=task_service,
        approval_service=approval_service,
        scope_guard=ScopeGuard(),
        tool_executor=tool_executor or FakeToolExecutor(tmp_path / "tool_outputs"),
        planner=planner,
        result_parser=ResultParser(),
        report_agent=ReportAgent(artifact_store),
    )
    return task_service, approval_service, graph_runner


def test_graph_pauses_for_high_risk_approval(tmp_path: Path) -> None:
    task_service, approval_service, graph_runner = build_graph_runner(tmp_path)
    task = task_service.create_task(
        TaskCreate(
            name="Demo Task",
            scope=["127.0.0.1"],
            authorization="Lab approved",
            objective="Inspect the local demo service",
        ),
        ["127.0.0.1"],
    )

    graph_runner.run(task.id)

    updated = task_service.get_task(task.id)
    approvals = approval_service.list_approvals(task.id)
    assert updated.status == "waiting_approval"
    assert len(approvals) == 1
    assert approvals[0].tool_name == "header_mutation"


def test_graph_resumes_after_approval_and_generates_report(tmp_path: Path) -> None:
    task_service, approval_service, graph_runner = build_graph_runner(tmp_path)
    task = task_service.create_task(
        TaskCreate(
            name="Demo Task",
            scope=["127.0.0.1"],
            authorization="Lab approved",
            objective="Inspect the local demo service",
        ),
        ["127.0.0.1"],
    )

    graph_runner.run(task.id)
    approval = approval_service.list_approvals(task.id)[0]
    approval_service.approve(approval.id, ApprovalDecision(note="Proceed"))
    graph_runner.run(task.id)

    updated = task_service.get_task(task.id)
    assert updated.status == "completed"
    assert updated.report_path
    assert Path(updated.report_path).exists()


def test_graph_marks_failed_verification_as_unreproduced(tmp_path: Path) -> None:
    task_service, approval_service, graph_runner = build_graph_runner(
        tmp_path,
        tool_executor=FailingVerifyToolExecutor(tmp_path / "tool_outputs"),
    )
    task = task_service.create_task(
        TaskCreate(
            name="Demo Task",
            scope=["127.0.0.1"],
            authorization="Lab approved",
            objective="Inspect the local demo service",
        ),
        ["127.0.0.1"],
    )

    graph_runner.run(task.id)
    approval = approval_service.list_approvals(task.id)[0]
    approval_service.approve(approval.id, ApprovalDecision(note="Proceed"))
    graph_runner.run(task.id)

    updated = task_service.get_task(task.id)
    assert updated.status == "failed"
    assert updated.stop_reason == "Exploit action failed before reproduction."
    assert updated.report_path
    report_content = Path(updated.report_path).read_text(encoding="utf-8")
    assert "验证失败/未复现" in report_content
    assert "Exploit primitive failed against the demo target." in report_content


def test_planner_treats_local_dev_ports_as_web_services(tmp_path: Path) -> None:
    planner = PlannerService(
        deepseek_client=DummyDeepSeekClient(),
        exploit_mapper=ExploitKnowledgeMapper(),
        knowledge_retriever=KnowledgeRetriever(tmp_path / "knowledge"),
        knowledge_capture_service=DummyKnowledgeCaptureService(),
    )

    verifier_planner = PlannerService(
        deepseek_client=DummyDeepSeekClient(),
        exploit_mapper=ExploitKnowledgeMapper(),
        knowledge_retriever=KnowledgeRetriever(tmp_path / "knowledge"),
        knowledge_capture_service=DummyKnowledgeCaptureService(),
    )

    plan = verifier_planner.plan(
        {
            "scope": ["127.0.0.1"],
            "hosts": [{"address": "127.0.0.1", "status": "up"}],
            "services": [
                {
                    "target": "127.0.0.1",
                    "port": 4173,
                    "protocol": "tcp",
                    "service": "mma-discovery",
                    "product": "",
                    "version": "",
                }
            ],
            "evidence": [],
            "actions": [
                {"tool_name": "asset_discovery", "params": {"targets": ["127.0.0.1"]}},
                {"tool_name": "service_fingerprint", "params": {"target": "127.0.0.1", "port_spec": "4173"}},
            ],
            "current_stage": "service_fingerprint",
            "objective": "Inspect local dev server",
        }
    )

    assert plan.stage == "observe"
    assert plan.tool_name == "http_get"


def test_planner_allows_mini_httpd_verification_even_with_404_only_evidence(tmp_path: Path) -> None:
    planner = PlannerService(
        deepseek_client=DummyDeepSeekClient(),
        exploit_mapper=ExploitKnowledgeMapper(),
        knowledge_retriever=KnowledgeRetriever(tmp_path / "knowledge"),
        knowledge_capture_service=DummyKnowledgeCaptureService(),
    )

    plan = planner.plan(
        {
            "scope": ["127.0.0.1"],
            "lab_description": "Official Vulhub mini_httpd CVE-2018-18778 container on port 8088",
            "hosts": [{"address": "127.0.0.1", "status": "up"}],
            "services": [
                {
                    "target": "127.0.0.1",
                    "port": 8088,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "mini_httpd",
                    "version": "1.29",
                }
            ],
            "evidence": [
                {
                    "kind": "web_probe",
                    "target": "127.0.0.1",
                    "port": 8088,
                    "summary": "/ -> 404 404 Not Found",
                    "data": {"status_code": 404, "title": "404 Not Found"},
                }
            ],
            "actions": [
                {"tool_name": "asset_discovery", "params": {"targets": ["127.0.0.1"]}},
                {"tool_name": "service_fingerprint", "params": {"target": "127.0.0.1", "port_spec": "8088"}},
                {"tool_name": "web_probe", "params": {"target": "127.0.0.1", "port": 8088}},
                {"tool_name": "dir_enum", "params": {"target": "127.0.0.1", "port": 8088}},
                {"tool_name": "ffuf_enum", "params": {"target": "127.0.0.1", "port": 8088}},
                {"tool_name": "http_snapshot", "params": {"target": "127.0.0.1", "port": 8088}},
            ],
            "current_stage": "http_snapshot",
            "objective": "Reproduce the local mini_httpd vulnerability",
        }
    )

    assert plan.stage == "exploit"
    assert plan.tool_name == "header_mutation"
    assert plan.params["headers"]["Host"] == ""


def test_planner_prioritizes_reflection_candidates_over_corpus_candidates(tmp_path: Path) -> None:
    planner = PlannerService(
        deepseek_client=DummyDeepSeekClient(),
        exploit_mapper=ExploitKnowledgeMapper(),
        knowledge_retriever=KnowledgeRetriever(tmp_path / "knowledge"),
        knowledge_capture_service=DummyKnowledgeCaptureService(),
    )

    plan = planner.plan(
        {
            "scope": ["127.0.0.1"],
            "hosts": [{"address": "127.0.0.1", "status": "up"}],
            "services": [
                {
                    "target": "127.0.0.1",
                    "port": 8088,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "mini_httpd",
                    "version": "1.29",
                }
            ],
            "evidence": [],
            "actions": [],
            "last_reflection": {
                "summary": "Try a refined raw HTTP candidate first.",
                "next_candidates": [
                    {
                        "stage": "exploit",
                        "tool_name": "raw_http",
                        "params": {
                            "target": "127.0.0.1",
                            "port": 8088,
                            "request": "GET /etc/passwd HTTP/1.1\\r\\nHost: \\r\\n\\r\\n",
                            "timeout": 10,
                        },
                        "rationale": "Reflection-derived refined candidate.",
                        "expected_evidence": ["root:x:0:0:"],
                        "risk_level": "high",
                        "requires_approval": True,
                        "source": "corpus_reflection",
                    }
                ],
            },
            "current_stage": "reflect",
            "objective": "Reproduce the local mini_httpd vulnerability",
        }
    )

    assert plan.tool_name == "raw_http"
    assert plan.source == "corpus_reflection"


def test_planner_normalizes_reflection_http_post_candidates(tmp_path: Path) -> None:
    planner = PlannerService(
        deepseek_client=DummyDeepSeekClient(),
        exploit_mapper=ExploitKnowledgeMapper(),
        knowledge_retriever=KnowledgeRetriever(tmp_path / "knowledge"),
        knowledge_capture_service=DummyKnowledgeCaptureService(),
    )

    plan = planner.plan(
        {
            "scope": ["127.0.0.1"],
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
            "evidence": [],
            "actions": [],
            "last_reflection": {
                "summary": "Try a safe JSON-RPC POST first.",
                "next_candidates": [
                    {
                        "stage": "enumerate",
                        "tool_name": "http_post",
                        "params": {
                            "target": "127.0.0.1",
                            "port": 6800,
                            "scheme": "http",
                            "path": "/jsonrpc",
                            "headers": {"Content-Type": "application/json"},
                            "body": '{"jsonrpc":"2.0","id":1,"method":"aria2.getVersion","params":[]}',
                            "allow_redirects": False,
                            "timeout": 15,
                        },
                        "rationale": "Reflection-derived safe RPC probe.",
                        "expected_evidence": ["JSON-RPC result"],
                        "source": "reflection",
                    }
                ],
            },
            "current_stage": "reflect",
            "objective": "Confirm unauthorized JSON-RPC access on a local lab target",
        }
    )

    assert plan.tool_name == "http_request"
    assert plan.params["method"] == "POST"
    assert plan.params["path"] == "/jsonrpc"


def test_planner_chooses_generic_verifier_for_rpc_like_targets(tmp_path: Path) -> None:
    planner = PlannerService(
        deepseek_client=DummyDeepSeekClient(),
        exploit_mapper=ExploitKnowledgeMapper(),
        knowledge_retriever=KnowledgeRetriever(tmp_path / "knowledge"),
        knowledge_capture_service=DummyKnowledgeCaptureService(),
    )


def test_planner_prioritizes_approved_learning_candidates(tmp_path: Path) -> None:
    class LearningStub:
        def suggest(self, state):
            from app.services.exploit_knowledge_mapper import ExploitCandidate

            return [
                ExploitCandidate(
                    id="learned-json-rpc",
                    title="Reviewed JSON-RPC safe probe",
                    tool_name="http_request",
                    stage="enumerate",
                    params={
                        "target": "127.0.0.1",
                        "port": 6800,
                        "scheme": "http",
                        "path": "/jsonrpc",
                        "method": "POST",
                        "headers": {"Content-Type": "application/json"},
                        "body": '{"jsonrpc":"2.0","id":1,"method":"aria2.getVersion","params":[]}',
                        "allow_redirects": False,
                        "timeout": 15,
                    },
                    rationale="Reuse reviewed experience first.",
                    expected_evidence=["JSON-RPC result"],
                    risk_level="medium",
                    requires_approval=False,
                    confidence="high",
                    source="learning",
                )
            ]

    planner = PlannerService(
        deepseek_client=DummyDeepSeekClient(),
        exploit_mapper=ExploitKnowledgeMapper(),
        knowledge_retriever=KnowledgeRetriever(tmp_path / "knowledge"),
        knowledge_capture_service=LearningStub(),
    )

    plan = planner.plan(
        {
            "scope": ["127.0.0.1"],
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
            "evidence": [],
            "actions": [],
            "current_stage": "observe",
            "objective": "Reuse reviewed experience before generic corpus candidates",
        }
    )

    assert plan.tool_name == "http_request"
    assert plan.source == "learning"

    verifier_planner = PlannerService(
        deepseek_client=DummyDeepSeekClient(),
        exploit_mapper=ExploitKnowledgeMapper(),
        knowledge_retriever=KnowledgeRetriever(tmp_path / "knowledge"),
        knowledge_capture_service=DummyKnowledgeCaptureService(),
    )

    plan = verifier_planner.plan(
        {
            "scope": ["127.0.0.1"],
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
            "evidence": [
                {
                    "kind": "http_request",
                    "target": "127.0.0.1",
                    "port": 6800,
                    "data": {
                        "path": "/jsonrpc",
                        "status_code": 200,
                        "headers": {"content-type": "application/json-rpc"},
                        "body_snippet": '{"id":1,"jsonrpc":"2.0","result":{"version":"1.18.8"}}',
                    },
                }
            ],
            "actions": [
                {
                    "tool_name": "http_request",
                    "params": {
                        "target": "127.0.0.1",
                        "port": 6800,
                        "path": "/jsonrpc",
                        "method": "POST",
                    },
                }
            ],
            "current_stage": "observe",
            "objective": "Confirm whether the local RPC surface allows unauthorized capability probes",
        }
    )

    assert plan.tool_name == "vuln_verify"
    assert plan.params["profile"] == "json_rpc"
