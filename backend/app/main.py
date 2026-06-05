from __future__ import annotations

from dataclasses import dataclass

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.agents.graph import PentestGraphRunner
from app.agents.planner import PlannerService
from app.agents.report_agent import ReportAgent
from app.agents.result_parser import ResultParser
from app.api import approvals, learning_candidates, reports, tasks, websocket
from app.core.config import Settings, get_settings
from app.core.llm_provider import LLMConfig, LLMProvider
from app.core.logging import configure_logging
from app.core.scope_guard import ScopeGuard
from app.db.session import Database
from app.services.approval_service import ApprovalService
from app.services.artifact_store import ArtifactStore
from app.services.deepseek_client import DeepSeekProvider
from app.services.demo_template_service import DemoTemplateService
from app.services.exploit_knowledge_mapper import ExploitKnowledgeMapper
from app.services.knowledge_capture_service import KnowledgeCaptureService
from app.services.knowledge_retriever import KnowledgeRetriever
from app.services.task_runtime import TaskRuntime
from app.services.task_service import TaskService
from app.services.tool_executor import ToolExecutor


def _build_llm_provider(settings: Settings) -> LLMProvider:
    """Construct the appropriate LLMProvider from application settings."""
    api_key = settings.resolved_llm_api_key or ""

    if settings.llm_provider == "deepseek":
        config = LLMConfig(
            provider="deepseek",
            model=settings.deepseek_model,
            api_key=api_key,
            base_url=settings.deepseek_base_url,
            temperature=settings.llm_temperature,
            timeout=settings.llm_timeout,
            max_tokens=settings.llm_max_tokens,
        )
        return DeepSeekProvider(config)

    # Generic fallback – uses OpenAI-compatible endpoint for any provider
    config = LLMConfig(
        provider=settings.llm_provider,  # type: ignore[arg-type]
        model=settings.deepseek_model,
        api_key=api_key,
        base_url=settings.deepseek_base_url,
        temperature=settings.llm_temperature,
        timeout=settings.llm_timeout,
        max_tokens=settings.llm_max_tokens,
    )
    return DeepSeekProvider(config)


@dataclass(slots=True)
class Container:
    settings: Settings
    database: Database
    scope_guard: ScopeGuard
    artifact_store: ArtifactStore
    task_service: TaskService
    approval_service: ApprovalService
    demo_template_service: DemoTemplateService
    exploit_mapper: ExploitKnowledgeMapper
    knowledge_retriever: KnowledgeRetriever
    knowledge_capture_service: KnowledgeCaptureService
    llm_provider: LLMProvider
    planner: PlannerService
    result_parser: ResultParser
    report_agent: ReportAgent
    tool_executor: ToolExecutor
    graph_runner: PentestGraphRunner
    task_runtime: TaskRuntime


def create_container() -> Container:
    settings = get_settings()
    configure_logging(settings.debug)
    database = Database(database_url=settings.database_path)
    database.init()
    scope_guard = ScopeGuard(allow_public_targets=settings.allow_public_targets)
    artifact_store = ArtifactStore(settings.artifact_path)
    task_service = TaskService(database)
    approval_service = ApprovalService(task_service)
    demo_template_service = DemoTemplateService()
    exploit_mapper = ExploitKnowledgeMapper()
    knowledge_retriever = KnowledgeRetriever(settings.artifact_path.parent / "data" / "knowledge")
    knowledge_capture_service = KnowledgeCaptureService(database)
    llm_provider = _build_llm_provider(settings)
    planner = PlannerService(
        deepseek_client=llm_provider,
        exploit_mapper=exploit_mapper,
        knowledge_retriever=knowledge_retriever,
        knowledge_capture_service=knowledge_capture_service,
    )
    result_parser = ResultParser()
    report_agent = ReportAgent(artifact_store)
    tool_executor = ToolExecutor(
        settings=settings,
        scope_guard=scope_guard,
        artifact_store=artifact_store,
    )
    graph_runner = PentestGraphRunner(
        task_service=task_service,
        approval_service=approval_service,
        scope_guard=scope_guard,
        tool_executor=tool_executor,
        planner=planner,
        result_parser=result_parser,
        report_agent=report_agent,
        knowledge_capture_service=knowledge_capture_service,
    )
    task_runtime = TaskRuntime(graph_runner)
    return Container(
        settings=settings,
        database=database,
        scope_guard=scope_guard,
        artifact_store=artifact_store,
        task_service=task_service,
        approval_service=approval_service,
        demo_template_service=demo_template_service,
        exploit_mapper=exploit_mapper,
        knowledge_retriever=knowledge_retriever,
        knowledge_capture_service=knowledge_capture_service,
        llm_provider=llm_provider,
        planner=planner,
        result_parser=result_parser,
        report_agent=report_agent,
        tool_executor=tool_executor,
        graph_runner=graph_runner,
        task_runtime=task_runtime,
    )


def create_app() -> FastAPI:
    container = create_container()
    app = FastAPI(title=container.settings.app_name)
    app.state.container = container

    app.add_middleware(
        CORSMiddleware,
        allow_origins=container.settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(tasks.router, prefix=container.settings.api_prefix)
    app.include_router(approvals.router, prefix=container.settings.api_prefix)
    app.include_router(learning_candidates.router, prefix=container.settings.api_prefix)
    app.include_router(reports.router, prefix=container.settings.api_prefix)
    app.include_router(websocket.router)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
