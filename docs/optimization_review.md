# VulnTrace Agent — 通用化优化 Review 报告

> **审查日期**: 2026-06-05  
> **审查范围**: 全部项目代码（backend + frontend + docs + data + scripts）  
> **目标**: 改造为针对**未知靶机**的 LLM 核心通用渗透 Agent，安全策略放松、通用化、自动知识库更新

---

## 0. 当前架构概况

```
前端 (Vue 3 + Naive UI)
  ↕ REST + WebSocket
后端 API (FastAPI)
  ↕ 依赖注入 Container
Agent 编排层 (LangGraph + Planner + ReportAgent)
  ↕
服务层 (ToolExecutor / KnowledgeCapture / DeepSeekClient / ...)
  ↕
工具层 (14 个封装工具: nmap, nikto, ffuf, curl, raw http, ...)
  ↕
数据层 (SQLite + 文件系统 artifacts)
```

**核心痛点**: 系统高度耦合于特定已知靶场（DVWA、mini_httpd、aria2 JSON-RPC），对未知目标几乎无渗透能力。

---

## 1. 🔴 架构层面（最高优先级）

### 1.1 LLM 提供商硬编码为 DeepSeek
**位置**: [config.py:24-25](backend/app/core/config.py), [deepseek_client.py](backend/app/services/deepseek_client.py)

**现状**: 系统仅支持 DeepSeek API，无法切换到 OpenAI、Claude、本地模型等。`deepseek_client.py` 中 LLM 提示词全部为中文，`ChatOpenAI` 硬编码。

**优化建议**:
- 抽象 `LLMProvider` 协议/接口，支持多种模型后端（OpenAI / Anthropic / 本地 Ollama）
- 中文 prompt 改为中英双语或通过配置指定语言
- 添加 `temperature`、`timeout`、`max_tokens` 可配置参数
- 增加 LLM 调用重试/fallback 机制

### 1.2 数据库硬绑 SQLite
**位置**: [config.py:26,49-51](backend/app/core/config.py), [db/session.py](backend/app/db/session.py)

**现状**: `database_path` 属性对非 `sqlite:///` URL 直接抛出 `ValueError`。无迁移系统，无连接池，未启用 `PRAGMA foreign_keys = ON`。

**优化建议**:
- 引入 SQLAlchemy + Alembic 替换裸 SQL
- 支持 PostgreSQL 作为可选后端
- 启用外键约束强制
- 添加连接池

### 1.3 无抽象/无接口
**现状**: 所有服务之间直接依赖具体实现类（`TaskService` 依赖 `Database`，`ApprovalService` 内部访问 `task_service.database`）。无法进行单元测试 mock。

**优化建议**:
- 定义 `Protocol` 或 ABC 接口（`TaskRepository`、`LLMClient`、`KnowledgeBase`）
- 通过依赖注入容器解耦

### 1.4 项目路径硬编码
**位置**: [config.py:8](backend/app/core/config.py) — `PROJECT_ROOT = Path(__file__).resolve().parents[3]`

**现状**: 假设文件在 `backend/app/core/config.py`，实际深度可能变化。前端 [ui.js:133](frontend/src/utils/ui.js) 也硬编码 `/root/Desktop/Agent Project/`。

**优化建议**: 使用环境变量 `PROJECT_ROOT` 或运行时自动检测

---

## 2. 🔴 智能体编排层（Agent Core）

### 2.1 Planner 严重依赖硬编码启发式规则，LLM 失败无感知
**位置**: [planner.py:104](backend/app/agents/planner.py), [planner.py:191-558](backend/app/agents/planner.py)

**现状**: 
- LLM 调用失败时 `except Exception: pass` 静默吞掉错误，回退到 370 行启发式规则
- 启发式规则极度锚定 DVWA/mini_httpd/aria2 三个已知靶场
- 对未知服务（无匹配模式）只能进入 `generic_web` 变体（仅 nikto 扫描）

**优化建议**:
- LLM 调用失败必须记录日志 + 发送告警
- 启发式规则应更通用：基于端口/协议泛化（HTTP→web scan, SMB→smbclient, SSH→ssh-audit...）
- 增加通用漏洞类型探测（SQLi、XSS、Command Injection 基于响应特征的通用检测）
- 将 370 行单一函数拆分为策略模式（`ScanStrategy`、`ExploitStrategy`、`VerifyStrategy`）

### 2.2 Graph 审批流程绕过 Scope 重校验
**位置**: [graph.py:491-492](backend/app/agents/graph.py) — `_after_bootstrap` 中直接跳到 `execute_action`

**现状**: 当任务从审批恢复时，跳过 scope_validation。如果 scope 在暂停期间变化，会绕过安全检查。

**优化建议**: 恢复时至少做轻量级 scope 重校验

### 2.3 `_FallbackGraph` 无循环限制
**位置**: [graph.py:537-590](backend/app/agents/graph.py)

**现状**: `while True` 循环，无 step_counter、无超时。如果状态机未达终止状态会无限运行。

**优化建议**: 
- 添加全局 `max_steps` 限制到 fallback 图
- 添加 wall-clock timeout
- 添加连续失败计数器

### 2.4 单次 confirmed finding 即停止
**位置**: [graph.py:384-389](backend/app/agents/graph.py)

**现状**: 任一 confirmed finding 触发停止，无法继续深入测试其他服务。

**优化建议**: 
- 改为可配置策略（`stop_on_first_finding: bool`）
- 或按服务分组继续：一个服务确认后继续测试其他服务

### 2.5 历史上下文截断过激
**位置**: [prompts.py:35-36](backend/app/agents/prompts.py) — 仅保留最近 6 evidence / 8 actions / 6 findings

**现状**: 长任务丢失早期上下文，可能重复工作或前后矛盾。

**优化建议**: 
- 增加上下文窗口（利用 LLM 的 1M token 能力）
- 添加智能摘要机制而不是硬截断

---

## 3. 🔴 工具层（Tools）

### 3.1 vuln_verify 是最大瓶颈 — 只支持 3 个已知靶场
**位置**: [vuln_verify.py](backend/app/tools/vuln_verify.py) (1045 行)

**现状**: 整个验证引擎仅覆盖:
- DVWA File Inclusion（PHP Apache 特定）
- mini_httpd CVE-2018-18778（空 Host header 文件读取）
- aria2 JSON-RPC 信息泄露

**对于未知目标**: 只能跑 `generic_web` profile（仅 nikto），无任何主动验证能力。

**优化建议**:
- 增加通用 PoC 引擎（模板化 HTTP 请求 + 响应匹配器）
- 支持从 YAML/JSON 加载 PoC 模板（类似 nuclei templates）
- 增加通用漏洞探测类型：SQLi 时间盲注、XSS 反射检测、命令注入回显检测、路径穿越通用检测
- `_select_profile` 不要再靠硬编码产品名匹配，而是由 LLM 根据上下文动态决策

### 3.2 dir_enum 字典仅 12 个路径
**位置**: [dir_enum.py:12-25](backend/app/tools/dir_enum.py)

**现状**: 硬编码 `COMMON_PATHS = ["/admin", "/login", ...]`，只 12 条。对于未知 Web 应用基本无效。

**优化建议**: 
- 支持外部字典文件（如 `common.txt`、`raft-small-words.txt`）
- 支持从知识库动态加载按服务类型分类的路径列表

### 3.3 ffuf_enum 默认词表仅 10 个词
**位置**: [ffuf_enum.py:10-21](backend/app/tools/ffuf_enum.py)

**现状**: `DEFAULT_WORDS` 仅 10 个通用路径。

**优化建议**: 
- 增加默认字典大小（至少 100-200 条常见路径）
- 单线程 (`-t 1`) 对未知目标太慢，允许用户可配并发

### 3.4 raw_http / header_mutation 的 timeout 参数被忽略
**位置**: [raw_http.py:12](backend/app/tools/raw_http.py), [header_mutation.py:18](backend/app/tools/header_mutation.py)

**现状**: 两者调用 `_send_raw_http_request`，该函数硬编码 socket timeout=5。用户设置的 `timeout=120` 无效。

**优化建议**: 将 `params.timeout` 传入底层 socket 函数

### 3.5 工具缺乏 IPv6 支持
**位置**: 所有构造 URL 的工具

**现状**: `f"{scheme}://{target}:{port}{path}"` 对 IPv6 地址（如 `::1`）不合法，应是 `http://[::1]:8080/path`。

**优化建议**: 增加 IPv6 地址检测和 `[...]` 括号包装

### 3.6 report_tool 是空实现
**位置**: [report_tool.py](backend/app/tools/report_tool.py) (13 行)

**现状**: 接受任何参数，忽略所有输入，返回空 `structured_data: {}`。报告生成实际在 `report_agent.py` 中完成。

**优化建议**: 移除或重构为报告状态查询工具

### 3.7 缺少关键渗透工具
**缺失的工具能力**:
- SSH 爆破/弱口令检测
- SMB 枚举
- SQL 注入测试（sqlmap / 手动探测）
- 默认凭据检查
- 服务 Banner 欺骗检测
- 子域名枚举（如 gobuster DNS 模式）
- Docker API 未授权检测
- Redis/MongoDB 未授权访问

---

## 4. 🟡 安全策略层

### 4.1 风险策略完全静态
**位置**: [risk_policy.py](backend/app/core/risk_policy.py)

**现状**: 14 个工具的 risk_level / approval_required 硬编码在 dict 中，无法运行时调整。

**优化建议**:
- 支持按任务/用户/环境覆盖 risk level 配置
- 支持"宽松模式" — 自动审批 medium 及以下风险
- 支持"学习模式" — 记录审批决策，自动学习用户偏好

### 4.2 ALLOW_PUBLIC_TARGETS 全局开关
**位置**: [config.py:30](backend/app/core/config.py) — `allow_public_targets: bool = False`

**现状**: 单一全局开关。开则全开，关则全关。无按目标粒度控制。

**优化建议**: 
- 支持目标白名单显式授权（用户标注 "此公网 IP 已授权"）
- 支持 CIDR 范围授权

### 4.3 Scope Guard 阻塞同步调用
**位置**: [scope_guard.py:65](backend/app/core/scope_guard.py) — `socket.getaddrinfo()`

**现状**: 同步 DNS 解析阻塞 asyncio 事件循环。

**优化建议**: 使用 `asyncio.getaddrinfo()` 替代

### 4.4 ToolExecutor registry 中所有工具 `allowed_stages=("*",)`
**位置**: [tool_executor.py:56-183](backend/app/services/tool_executor.py)

**现状**: 阶段门控功能设置了但从未真正启用。任何工具可以在任何阶段调用。

**优化建议**: 启用阶段门控（如 `vuln_verify` 只能在 `exploit` 阶段），增加渗透测试的纪律性

---

## 5. 🟡 知识库与学习系统

### 5.1 exploit_signatures.json 仅 2 条签名
**位置**: [data/knowledge/exploit_signatures.json](data/knowledge/exploit_signatures.json)

**现状**: 
- 5 个 exploit 家族（empty_header, duplicate_header, absolute_path, path_traversal, vhost_confusion）
- 仅 2 条实际签名：`mini_httpd_cve_2018_18778` 和 `dvwa_file_inclusion`
- 无通用漏洞签名（SQLi、XSS、LFI/RFI、SSRF、命令注入）

**优化建议**:
- 扩展为至少覆盖 OWASP Top 10 的基础签名
- 支持从外部模板文件动态加载（JSON 目录或 YAML 模板）
- 每个签名包含 `detection`（如何识别）和 `exploitation`（如何利用）两个阶段

### 5.2 KnowledgeCaptureService 学习模式硬编码
**位置**: [knowledge_capture_service.py:309-328](backend/app/services/knowledge_capture_service.py) — `_select_learning_mode`

**现状**: 仅支持 4 种硬编码学习模式：`json_rpc`, `mini_httpd`, `php_apache`, `generic_verifier`。添加新模式需改代码。

**优化建议**:
- LLM 驱动的模式识别（让 LLM 自己决定"这是什么类型的漏洞，应该如何验证"）
- 学习候选应包含更灵活的结构（不限于固定参数模板）

### 5.3 KnowledgeRetriever 极度简陋
**位置**: [knowledge_retriever.py:11-23](backend/app/services/knowledge_retriever.py)

**现状**: 
- 纯关键词匹配（`.count(term)` 计分）
- 仅搜索 `.md` 文件
- snippet 始终返回文件前 280 字符
- 无 TF-IDF、无语义搜索、无 embedding

**优化建议**:
- 集成向量数据库（如 ChromaDB / FAISS）做 semantic search
- 对工具输出做 embedding 后入库
- 支持根据当前上下文（服务类型、版本）精准检索相关攻击知识

### 5.4 知识库文件纯文本，无机器可读结构
**位置**: [data/knowledge/](data/knowledge/)

**现状**: `kali_tools.md`, `web_vuln_checklist.md`, `lab_rules.md` 均为人类可读 Markdown，无法被程序高效利用。

**优化建议**:
- 将工具使用说明转为结构化 JSON/YAML（tool_name, params, risk, examples）
- 将漏洞检查清单转为可执行规则引擎
- 增加 CVE ↔ service fingerprint 映射数据库

---

## 6. 🟡 LLM 交互层

### 6.1 提示词全部为中文，LLM 响应解析脆弱
**位置**: [prompts.py:6-16](backend/app/agents/prompts.py), [deepseek_client.py:40-52](backend/app/services/deepseek_client.py)

**现状**: System prompt 和 JSON 提取指令均为中文。`_extract_json` 用简单正则（先找 ```json 代码块，再找外层 `{...}`），边界情况有 bug。

**优化建议**:
- 系统提示词支持双语（中文 + English fallback）
- 使用 SDK 原生的 structured output（如 OpenAI `response_format`、Anthropic `tool_use`）
- 不要依赖 LLM 输出中手动嵌入 JSON Schema

### 6.2 LLM 决策无审计 trail
**位置**: [planner.py:106-120](backend/app/agents/planner.py)

**现状**: LLM 原始响应（可能含危险计划）在使用后丢弃，仅保留解析后的结构化决策。如果安全绕过发生，无法追溯 LLM 到底说了什么。

**优化建议**: 保存每次 LLM 调用的完整 prompt + response 到审计日志

### 6.3 提示词注入风险
**现状**: `lab_description`、`objective`、工具输出等用户可控字段直接注入 LLM prompt（[prompts.py:29-42](backend/app/agents/prompts.py)）。如果攻击者构造恶意输入，可能操控 LLM 行为。

**优化建议**: 
- 对注入 LLM prompt 的用户数据进行 sanitization
- 使用 "user/assistant" 消息分离而不是字符串拼接
- 在 system prompt 中加固角色边界（"你只能执行授权范围内操作"）

---

## 7. 🟢 前端层

### 7.1 任务配置无细粒度控制
**位置**: [TaskForm.vue](frontend/src/components/TaskForm.vue)

**现状**: 前端只能配置 scope IP、ports、name、最大步骤数、授权文本、目标描述。无法指定：
- 允许/禁用哪些工具
- 风险容忍度
- 扫描强度档位（轻/中/重）
- 超时策略

**优化建议**: 
- 增加 "高级配置" 面板，暴露工具选择、强度、策略选项
- "通用模式" toggle — 未知目标 vs 已知靶场模式

### 7.2 审批界面编辑纯 JSON textarea
**位置**: [ApprovalPanel.vue](frontend/src/components/ApprovalPanel.vue)

**现状**: 用户必须在 textarea 中手动编辑 JSON 来修改参数。语法错误即 `window.alert`，参数无校验。

**优化建议**: 基于 JSON Schema 动态渲染表单控件（下拉框、开关、输入框）

### 7.3 PathGraph 无实际可视化
**位置**: [PathGraph.vue](frontend/src/components/PathGraph.vue)

**现状**: 名为 "PathGraph" 但实际是无向文本列表。无 D3/ECharts/Cytoscape 图渲染。

**优化建议**: 集成 D3.js 或 vis-network 实现真实的攻击路径可视化图

### 7.4 ReportView XSS 风险
**位置**: [ReportView.vue:46](frontend/src/components/ReportView.vue)

**现状**: `v-html` 直接渲染 `marked.parse()` 结果，无 HTML sanitization（如 DOMPurify）。如工具输出含恶意 HTML，可能执行脚本。

**优化建议**: 使用 DOMPurify 对 marked 输出进行 sanitize

### 7.5 硬编码绝对路径
**位置**: [ui.js:133](frontend/src/utils/ui.js), [ReportView.vue:259](frontend/src/components/ReportView.vue)

**现状**: 多处在代码中硬编码 `/root/Desktop/Agent Project/` 绝对路径，不可移植。

**优化建议**: 使用环境变量或 API 返回的相对路径

---

## 8. 🟢 数据与持久化

### 8.1 无数据库索引
**位置**: [models.py](backend/app/db/models.py)

**现状**: events / approvals / artifacts / learning_candidates 表的 `task_id` 列无索引，全表扫描。

**优化建议**: 对 `task_id` 列添加索引

### 8.2 无软删除/级联删除
**位置**: [models.py](backend/app/db/models.py)

**现状**: 删除 task 会遗留孤立记录。无 `ON DELETE CASCADE`。

**优化建议**: 添加 CASCADE 或至少应用层级联清理

### 8.3 Task State 无 Schema 验证
**位置**: [task_service.py:26-56](backend/app/services/task_service.py)

**现状**: `state` 字段是裸 `dict`，无 Pydantic 验证。各消费者对 state 结构有隐含假设但无编译期检查。

**优化建议**: 为 state 定义严格的 Pydantic model 并在读写时验证

---

## 9. 🟢 测试与质量

### 9.1 测试覆盖不全
**现状**: 有 10 个测试文件，但：
- `test_vuln_verify.py` 是新文件（尚未追踪）
- 无集成测试（CI pipeline）
- 无 `planner.py` 直接单元测试
- 无 `knowledge_capture_service.py` 边界测试

**优化建议**: 
- 增加未知目标的集成测试（启动 mock 服务，验证 Agent 的完整流程）
- 为 planner 添加 mock LLM 的单元测试

### 9.2 无全局超时/取消机制
**现状**: `TaskRuntime` 无 `cancel()` 方法，运行中的图无法从外部终止（除了线程级强制 kill）。

**优化建议**: 在 LangGraph 循环中检查 `asyncio.Event` 取消标志

---

## 10. 🔵 针对 "未知靶机完整渗透" 的专项优化

### 10.1 增加服务自适应发现
当前 `service_fingerprint` 只扫描 nmap 默认 1000 端口。对于非标准端口服务（如 4280 的 PHP 服务），当前系统会漏掉。

**建议**: 
- 增加全端口扫描选项（1-65535）
- 对已知特定服务类型增加非标准端口检测（如 27017→MongoDB, 6379→Redis）

### 10.2 增加协议级探测能力
当前工具只覆盖 HTTP/TCP（raw socket）。对于 SMB、SSH、FTP、SNMP 等协议无任何探测能力。

**建议**: 
- 增加 SMB 共享枚举工具
- 增加 SSH 弱口令/版本检测
- 增加 FTP 匿名登录检测
- 增加 SNMP community string 探测

### 10.3 LLM 驱动的动态工具选择
当前 Planner 的启发式规则限制了工具选择。对于未知目标，应该：
- 先让 LLM 看到 nmap 的完整服务输出（包括 unknown services）
- LLM 根据服务 Banner 内容推理"这可能是什么"
- LLM 动态选择或组合工具参数
- 结果反馈给 LLM 进一步分析

### 10.4 知识库自动扩增
当前 KnowledgeCaptureService 学习后在 `learned_candidates.md` 中写 Markdown。但学习内容仅限于固定模板。

**建议**: 
- 每次完成对未知目标的成功 exploit，自动提取为可复用的签名模板
- LLM 分析 "成功的原因是什么" → 生成新的 exploit_signature JSON
- 自动存储到知识库并在后续任务中检索匹配

---

## 总结：优先级排序

| 优先级 | 类别 | 核心改动 |
|--------|------|---------|
| **P0** | LLM 抽象 | 支持多模型后端，可配置 provider |
| **P0** | vuln_verify 通用化 | 脱离 DVWA/mini_httpd 绑定，增加通用 PoC 引擎 |
| **P0** | Planner 通用化 | LLM 错误不静默，启发式规则泛化到通用端口/协议 |
| **P1** | 知识库 | exploit_signatures 扩展到 OWASP Top 10 + 自动学习能力 |
| **P1** | 新工具 | SSH、SMB、SQLi、默认凭据、Docker API、Redis 未授权 |
| **P1** | 安全策略 | 可配置风险容忍度、"宽松模式" |
| **P2** | Graph 增强 | 不单 confirmed finding 停止、循环限制、取消机制 |
| **P2** | 数据库 | ORM + 迁移 + 索引 |
| **P3** | 前端 | 高级配置面板、审批改进、真实 PathGraph、XSS 修复 |
| **P3** | 测试 | CI/CD、集成测试、Mock LLM 测试 |
