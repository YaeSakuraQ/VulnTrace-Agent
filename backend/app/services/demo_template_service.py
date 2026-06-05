from __future__ import annotations

from app.schemas.task import TaskTemplate


class DemoTemplateService:
    def __init__(self) -> None:
        self._templates = [
            TaskTemplate.model_validate(
                {
                    "id": "dvwa",
                    "title": "DVWA 演示模板",
                    "lab_type": "web",
                    "summary": "适合本地 Docker 或单靶机 Web 演示，突出低风险探测、审批式验证，以及带请求/证据留存的单条 PoC 复现。",
                    "defaults": {
                        "name": "DVWA 教学靶场演示任务",
                        "scope": ["127.0.0.1"],
                        "authorization": "仅针对本地部署的 DVWA 课程靶场执行受控测试，禁止扩展到未授权主机。",
                        "lab_description": "DVWA 是故意脆弱的 PHP Web 应用，常以 Docker 端口映射或 Host Only 虚拟机方式部署。",
                        "objective": "识别 DVWA Web 服务、收集页面和路径证据，并在人工审批后执行单条受控漏洞 PoC，输出请求、参数和成功证据。",
                        "ports": "80,443,8080",
                        "max_steps": 6,
                    },
                    "recommended_scope_examples": ["127.0.0.1", "192.168.56.10"],
                    "recommended_port_presets": ["80", "8080", "80,443,8080"],
                    "setup_notes": [
                        "如果 DVWA 通过 Docker 暴露在宿主机上，优先使用 127.0.0.1 和映射端口。",
                        "如果 DVWA 运行在独立虚拟机中，建议替换为 Host Only 网段 IP，如 192.168.56.x。",
                        "首次演示可以把端口限制在 80 或 8080，减少无关扫描结果。",
                    ],
                    "checklist": [
                        "确认 DVWA 登录页可访问。",
                        "观察 robots.txt、/login、/setup、/vulnerabilities/fi/ 等低风险路径响应。",
                        "审批后再执行单条受控 Web PoC，并保留请求、参数和响应证据。",
                    ],
                    "demo_flow": [
                        "先使用 localhost 或靶机 IP 快速填充范围，确认端口为 80 或 8080。",
                        "点击按模板创建并运行，展示资产发现、Web 探测和目录证据收集阶段。",
                        "当审批卡片出现后，说明为什么高风险 PoC 必须人工批准，并核对目标与参数。",
                        "批准后展示受控 exploit 的请求、成功标记和证据文件。",
                        "最后用报告页串起发现、PoC、审批记录和结论。",
                    ],
                    "risk_focus": "聚焦 Web 面的证据驱动验证，高风险动作仅限单条受控 PoC，并在报告中明确写出请求、参数和成功依据。",
                }
            ),
            TaskTemplate.model_validate(
                {
                    "id": "vulhub",
                    "title": "Vulhub 演示模板",
                    "lab_type": "container-web",
                    "summary": "适合本地 Docker 漏洞场景，通常服务映射到 localhost，便于快速演示完整闭环。",
                    "defaults": {
                        "name": "Vulhub 场景演示任务",
                        "scope": ["127.0.0.1"],
                        "authorization": "仅针对本地 Vulhub 场景暴露的端口执行受控测试，禁止访问 Docker 之外的目标。",
                        "lab_description": "Vulhub 通常以 Docker Compose 方式启动单漏洞场景，服务多映射到本机端口。",
                        "objective": "识别 Vulhub 场景的 Web 服务和关键路径，在人工审批后执行有限漏洞验证并生成报告。",
                        "ports": "80,443,7001,8000,8080,8081,8088,9200",
                        "max_steps": 7,
                    },
                    "recommended_scope_examples": ["127.0.0.1", "192.168.56.30"],
                    "recommended_port_presets": [
                        "8080",
                        "8000,8080,8081",
                        "80,443,7001,8000,8080,8081,8088,9200",
                    ],
                    "setup_notes": [
                        "先查看 `docker ps` 或 compose 文件，确认实际映射端口后再微调模板。",
                        "如果只演示单一 Vulhub 场景，建议把端口进一步收窄为真实映射端口。",
                        "不同 Vulhub 场景差异较大，目标说明里最好写明具体漏洞主题。",
                    ],
                    "checklist": [
                        "先根据映射端口确认 HTTP 入口。",
                        "保留首页、特征路径和目录枚举证据，便于汇报时说明推理链路。",
                        "审批后再进行 Nikto 验证，避免把所有容器端口都当成目标。",
                    ],
                    "demo_flow": [
                        "先核对 Docker 映射端口，再点击推荐端口预设快速覆盖表单。",
                        "一键创建并运行后，展示针对本地容器服务的低风险探测。",
                        "审批阶段说明系统不会直接执行未授权的高风险 Web 验证。",
                        "最后用报告说明容器场景下如何保留证据和控制边界。",
                    ],
                    "risk_focus": "适合演示 Docker 本地漏洞场景，但需要手动确认端口映射，避免误判服务入口。",
                }
            ),
        ]
        self._by_id = {template.id: template for template in self._templates}

    def list_templates(self) -> list[TaskTemplate]:
        return self._templates

    def get_template(self, template_id: str) -> TaskTemplate:
        return self._by_id[template_id]
