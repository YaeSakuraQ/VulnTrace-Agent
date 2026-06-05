# VulnTrace Agent

基于技术文档实现的本地靶场安全智能体原型，面向 Kali Linux 环境，提供任务管理、范围控制、工具封装、LangGraph 状态编排、人工审批、证据落盘和报告生成能力。

## 技术栈

- 后端：FastAPI、LangGraph、LangChain、SQLite
- 前端：Vue 3、Vite、Axios
- 工具：`nmap`、`nikto`、HTTP 探测

## 目录

- `backend/`：后端代码、测试与依赖
- `frontend/`：前端控制台
- `data/knowledge/`：本地知识库
- `artifacts/`：工具输出与报告
- `docs/`：设计与使用文档
- `scripts/`：启动脚本

## 快速启动

```bash
cp .env.example .env
./scripts/run_backend.sh
```

另开一个终端：

```bash
./scripts/run_frontend.sh
```

前端默认地址：`http://127.0.0.1:5173`

后端默认地址：`http://127.0.0.1:8000`

## 当前实现范围

- 任务创建、查询、暂停、停止、继续
- 内置 DVWA、Metasploitable、Vulhub 演示任务模板
- 选中模板后可一键创建并自动开始运行
- 白名单范围校验和默认拒绝公网
- 结构化 Kali 工具封装
- LangGraph 阶段推进与审批暂停
- 审计日志、证据记录、Markdown/HTML 报告
- 前端任务总览、审批面板、路径图和报告预览

## 测试

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
PYTHONPATH=backend pytest backend/tests
```
