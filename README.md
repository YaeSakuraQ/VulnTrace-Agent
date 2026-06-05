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

## 本地靶机启动

本项目默认面向“本地或课程授权靶场”运行。推荐先把靶机启动好，再用 VulnTrace Agent 创建任务，验证系统能否完成资产发现、服务识别、审批式验证和报告输出。

### 1. 启动前准备

先确认 Docker 环境可用：

```bash
docker version
docker compose version
```

### 2. 启动 DVWA

DVWA 适合演示本项目当前最完整的一条 Web 验证链路。

```bash
cd labs/DVWA
docker compose up -d
```

- 默认访问地址：`http://127.0.0.1:4280`
- 首次初始化：打开 `http://127.0.0.1:4280/setup.php`，点击 `Create / Reset Database`
- 默认账号：`admin / password`
- 建议在 DVWA 中将安全级别切换为 `low`
- 停止并清理：

```bash
cd labs/DVWA
docker compose down -v
```

### 3. 启动 Vulhub 场景

仓库中已经包含 `labs/vulhub/` 子模块，可直接在任意场景目录里启动对应靶机：

```bash
cd labs/vulhub/<产品族>/<场景目录>
docker compose up -d
```

例如，启动 `mini_httpd/CVE-2018-18778`：

```bash
cd labs/vulhub/mini_httpd/CVE-2018-18778
docker compose up -d
docker compose ps
```

- 停止并清理：

```bash
docker compose down -v
```

- 由于不同 Vulhub 场景暴露端口不同，启动后请执行 `docker compose ps` 查看本机映射端口。
- 每个 Vulhub 场景目录通常都带有 `README.md` 或 `README.zh-cn.md`，可用于确认访问入口和复现要点。
- 仓库里当前可直接启动的 Vulhub 场景共 `328` 个，完整列表见 [docs/local_lab_targets.md](docs/local_lab_targets.md)。

### 4. 用本项目测试靶机

靶机启动后，可按下面方式用本项目验证能力：

1. 启动后端与前端。
2. 在首页选择 `DVWA` 或 `Vulhub` 模板。
3. 将目标范围填为本机：`127.0.0.1`，端口改为靶机映射出来的实际端口。
4. 创建任务并观察资产发现、服务识别、Web 探测、审批和报告生成。

建议优先使用下列场景做课程展示：

- `labs/DVWA`
- `labs/vulhub/mini_httpd/CVE-2018-18778`
- 其他带明显 Web 入口、且官方 README 已写清访问路径的 Vulhub 场景

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
