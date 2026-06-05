# VulnTrace Agent 课程汇报 PPT 大纲

适用场景：网络攻防技术基础课程大作业汇报  
建议页数：12 ~ 14 页  
建议时长：12 ~ 18 分钟  
汇报风格：突出"安全智能体设计思路 + 技术原理 + 靶场闭环验证"，弱化工程源码细节

---

## 备选题目（供选择）

| 编号 | 题目 |
|------|------|
| A | **VulnTrace Agent：基于 LangGraph 的受控安全智能体** |
| B | **VulnTrace Agent：面向靶场环境的 LLM 驱动安全验证系统** |
| C | **VulnTrace Agent：大模型辅助的渗透测试智能体设计与实现** |
| D | **从探测到报告：一个基于 LangGraph 的自主安全智能体** |
| E | **VulnTrace Agent：混合决策驱动的安全测试智能体原型** |

> 推荐：**A** 或 **C**。A 突出核心技术栈（LangGraph），C 突出"LLM 辅助决策"定位。

---

## 第 1 页：封面

- **标题**：VulnTrace Agent：基于 LangGraph 的受控安全智能体
- **副标题**：网络攻防技术基础课程大作业汇报
- 建议展示内容：
  - 项目名称 + 选题编号
  - 小组成员姓名
  - 指导教师
  - 汇报日期
- 一句话定位：
  > 本项目不是通用攻击平台，而是一个面向授权靶场环境的、LLM 辅助决策的受控安全智能体原型。
- 可配图：系统首页截图（深色主题工作台 + 任务列表）

---

## 第 2 页：选题背景与问题定义

- **标题**：选题背景：安全工具的自动化困境

### 传统渗透测试的三个痛点

| 痛点 | 表现 |
|------|------|
| 流程碎片化 | Nmap → Nikto → SQLMap → 手工写报告，工具各自独立，缺乏串联 |
| 边界模糊 | 初学者容易把"自动化扫描"误解为"无约束攻击"，缺少范围控制意识 |
| 证据链缺失 | 能发现漏洞，但难以形成"从探测到验证再到证据"的完整闭环 |

### 本项目的核心追问

> 能否构建一个系统，让 LLM 负责"思考该做什么"，让预定义工具负责"执行该怎么做"，让审批与审计机制负责"确保不该做的不做"？

### 技术趋势背景

- 2023 年以来，LLM Agent 在代码生成、数据分析等领域表现出色
- 安全领域出现 AutoGPT 式自主代理，但普遍缺乏安全边界
- LangChain / LangGraph 提供了可控的状态机编排能力
- 本项目探索：**将 LLM Agent 引入安全测试，同时保持受控、可审计、可解释**

---

## 第 3 页：靶机与攻防环境

- **标题**：实验环境：本地靶场 + Docker 容器化

### 运行环境

```
Kali Linux（攻击机）          Docker 靶场（受害者）
┌─────────────────┐          ┌──────────────────────┐
│ VulnTrace Agent  │  HTTP    │ DVWA       :4280     │
│ (FastAPI + Vue)  │◄───────►│ mini_httpd  :8088    │
│ LLM (DeepSeek)   │  各种协议 │ Struts2     :8080    │
│ 31 个封装工具     │          │ Confluence  :8090    │
└─────────────────┘          │ WebLogic    :7001    │
                              │ ... 328+ Vulhub 场景  │
                              └──────────────────────┘
```

### 主要靶场对象

| 靶场 | 用途 | 典型漏洞 |
|------|------|---------|
| **DVWA** | Web 漏洞基础教学 | File Inclusion, SQLi, XSS |
| **Vulhub** | 容器化漏洞复现（328+ 场景） | mini_httpd 文件读取、Struts2 OGNL RCE、Confluence OGNL 注入、WebLogic RCE 等 |
| **Aria2** | 非 HTTP 服务验证 | JSON-RPC 未授权访问 |

### 系统定位

- ✅ 面向本地或课程授权范围内目标
- ❌ 默认拒绝公网地址
- ❌ 不允许模型直接构造 Shell 命令

---

## 第 4 页：技术栈全景

- **标题**：技术选型：全栈架构一览

### 三层技术栈

| 层 | 技术 | 角色 |
|----|------|------|
| **智能体层** | LangGraph + LangChain | 状态机编排、LLM 工具调用 |
| | DeepSeek V4 (OpenAI 兼容 API) | 主要推理模型（可切换 OpenAI/Anthropic/Ollama） |
| | Pydantic | 结构化决策输出、Schema 校验 |
| **后端层** | FastAPI + Uvicorn | HTTP API + WebSocket 实时推送 |
| | SQLAlchemy + SQLite | 任务状态持久化、外键约束、CASCADE |
| | Docker | 靶场容器化部署 |
| **前端层** | Vue 3 + Vite | 响应式 SPA |
| | Naive UI | 暗色主题组件库 |
| | Axios + WebSocket | API 通信 + 实时事件流 |
| | marked + DOMPurify | Markdown 报告渲染 + XSS 防护 |

### 关键设计决策

- **混合决策**：LLM 负责规划，规则系统兜底 → 稳定性 + 灵活性
- **工具白名单**：31 个预定义工具，模型只能选择不能构造 → 安全边界
- **宽松风险策略**：strict / moderate / relaxed 三档可切换 → 教学灵活性

---

## 第 5 页：智能体技术原理 — 任务编排

- **标题**：核心原理：LangGraph 状态机驱动的任务编排

### 状态机节点（13 节点）

```
  [validate_scope] → [choose_action] → [risk_check]
        ↓                  ↑               ↓
    (范围不合法)              │         (需审批?)
        ↓                  │               ↓
      [finish]             │      [human_approval] → (用户审批)
                           │               ↓
                    [reflect_result] ← [execute_tool]
                           │
                    [parse_result] → [update_path_graph]
                           │
                    [decide_continue]
                      ↓           ↘
                 [choose_action]   [generate_report] → [finish]
```

### 关键设计

- **循环推进**：每轮 observe → hypothesize → choose action → execute → reflect
- **LLM + 规则混合决策**：LLM 优先输出结构化 JSON 计划；LLM 不可用时回退到规则引擎
- **反思机制**：每轮执行后分析结果，动态调整下一轮策略
- **攻击路径图**：自动构建 Host → Service → Finding 的有向图

---

## 第 6 页：智能体技术原理 — 混合决策机制

- **标题**：混合决策：LLM 规划 + 规则兜底 + 知识库增强

### 三层决策架构

```
用户输入
  │
  ▼
┌─────────────────────────────────────┐
│  Layer 1: LLM 规划器                 │
│  - 理解任务上下文 + 历史证据         │
│  - 输出结构化 PlanDecision (JSON)    │
│  - 自动选择工具、参数、理由           │
│  失败? ──────────────────────┐       │
└──────────────────────────────┼───────┘
                               ▼
┌─────────────────────────────────────┐
│  Layer 2: 启发式规则引擎             │
│  - 5 个阶段策略: asset, service,     │
│    web_recon, exploit, finalize      │
│  - PORT_SERVICE_MAP 端口→服务映射     │
│  - 兜底保证最低可用性                │
└─────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────┐
│  Layer 3: Exploit 知识库增强         │
│  - 119 条 exploit 签名 (43 家族)     │
│  - Exploit-DB searchsploit 动态搜索  │
│  - 学习候选自动扩增                  │
└─────────────────────────────────────┘
```

### 举例

| 场景 | LLM 决策 | 规则兜底 | 知识库增强 |
|------|---------|---------|-----------|
| 遇到 Confluence:8090 | 选择 OGNL `${1+1}` 注入探测 | 端口 8090→web_probe | CVE-2022-26134 签名匹配 |
| 遇到 mini_httpd:8088 | 空 Host 头读取 /etc/passwd | 端口 80→http_snapshot | CVE-2018-18778 签名匹配 |
| 遇到未知服务:6379 | searchsploit 搜索 "redis" | 端口 6379→redis_check | EDB 搜索结果→候选签名 |

---

## 第 7 页：智能体技术原理 — 安全控制体系

- **标题**：安全控制：五层防御体系

### 控制层级

| 层级 | 机制 | 实现 |
|------|------|------|
| **范围控制** | IP 白名单 + CIDR 校验 | ScopeGuard：默认拒绝公网，支持显式授权 |
| **工具控制** | 31 个预注册工具白名单 | ToolExecutor registry：模型只能选择，不能构造 |
| **参数控制** | Pydantic Schema 强校验 | 每个工具 5-15 个约束字段（min/max, pattern, enum） |
| **审批控制** | 高风险动作人工审批 | 可配置容忍度（strict/moderate/relaxed） |
| **审计控制** | 每步记录事件日志 | Events + Artifacts → 证据链 → 报告 |

### 风险容忍度三级策略

| 模式 | Low | Medium | High | 适用场景 |
|------|-----|--------|------|---------|
| **Strict** | 自动 | 需审批 | 需审批 | 生产环境演练 |
| **Moderate** | 自动 | 自动 | 需审批 | 教学演示（默认） |
| **Relaxed** | 自动 | 自动 | 自动 | 隔离靶场快速验证 |

---

## 第 8 页：系统架构与模块设计

- **标题**：系统架构：六层分离的智能体平台

```
┌──────────────────────────────────────────────────┐
│ 前端呈现层 (Vue 3 + Naive UI)                     │
│ TaskForm│AgentConsole│ApprovalPanel│PathGraph│    │
│ ReportView│EventTimeline│LearningPanel│ApiBalance│
├──────────────────────────────────────────────────┤
│ API 网关层 (FastAPI)                               │
│ REST: tasks│approvals│reports│learning-candidates │
│ WebSocket: /ws/tasks/{id} (实时事件推送)           │
├──────────────────────────────────────────────────┤
│ 智能体编排层 (LangGraph)                           │
│ GraphRunner│PlannerService│ReportAgent│           │
│ ResultParser│RiskPolicy│PromptBuilder             │
├──────────────────────────────────────────────────┤
│ 工具执行层 (ToolExecutor + 31 tools)              │
│ nmap│nikto│ffuf│gobuster│hydra│sqlmap│searchsploit│
│ whatweb│wpscan│enum4linux│commix│linpeas│impacket│
├──────────────────────────────────────────────────┤
│ 知识库层                                          │
│ 119 Exploit Signatures│learned_candidates│        │
│ KnowledgeRetriever (TF-IDF)│Auto-Expansion        │
├──────────────────────────────────────────────────┤
│ 数据持久层 (SQLAlchemy + SQLite)                  │
│ tasks│events│approvals│artifacts│learning_candidates│
└──────────────────────────────────────────────────┘
```

### 模块职责

| 模块 | 核心职责 |
|------|---------|
| **PlannerService** | LLM 规划 + 规则兜底 + 端口映射 |
| **ToolExecutor** | 工具注册、阶段门控、参数 Schema 校验 |
| **ResultParser** | 工具输出 → 结构化证据、Finding、PoC 记录 |
| **ReportAgent** | Findings + PoC + Evidence → Markdown/HTML 报告 |
| **KnowledgeAutoExpansion** | searchsploit 结果 → 去重 → 候选签名 → 发布 |

---

## 第 9 页：实现过程与关键迭代

- **标题**：实现路径：从原型到通用化平台的演进

### 五个迭代阶段

| 阶段 | 内容 | 关键产出 |
|------|------|---------|
| **I: 基础框架** | LangGraph 状态机 + FastAPI + Vue3 骨架 | 任务生命周期管理、前后端联通 |
| **II: 安全控制** | ScopeGuard + RiskPolicy + 审批流 | 范围校验、风险分级、人工审批卡点 |
| **III: 知识注入** | Exploit 签名库 + 知识检索 + 学习候选 | 2→119 条签名（43 家族），TF-IDF 检索 |
| **IV: 通用化** | LLM Provider 抽象 + vuln_verify 通用化 | 支持多模型、unknown-target exploit 探测 |
| **V: 工具扩展** | 14→31 工具 + searchsploit 闭环 | SSH/FTP/SMB/Redis/MongoDB/SQLi/hydra/sqlmap/impacket... |

### 演进思路

> 不是一次性写完，而是在"能跑通 → 能受控 → 能解释 → 能出报告 → 能通用"的方向上逐步完善

---

## 第 10 页：小组分工与实际贡献

- **标题**：小组分工与成员贡献

> 使用说明：请在正式汇报前将 `[组员X]` 替换为真实姓名，并按实际贡献调整描述。

| 成员 | 职责模块 | 实际产出 |
|------|---------|---------|
| **[组员A]** | 智能体编排 + 混合决策 | LangGraph 状态机设计、LLM 规划器、规则引擎、反思机制 |
| **[组员B]** | 工具生态 + 安全控制 | 31 个工具封装与注册、ScopeGuard 范围控制、RiskPolicy 审批体系 |
| **[组员C]** | 知识库 + 漏洞验证 | 119 条 exploit 签名库、searchsploit 自动扩展、vuln_verify 通用化 |
| **[组员D]** | 前端 + 汇报材料 | 控制台界面、审批交互、攻击路径可视化、API 用量面板、报告渲染 |

> 如果组员人数较少，可将 A+B 合并（编排 + 工具），C+D 合并（知识库 + 前端）。

---

## 第 11 页：攻防性能表现与验证效果

- **标题**：验证效果：四条主线的闭环验证

### 验证指标

| 维度 | 指标 | 数据 |
|------|------|------|
| 功能完整性 | API 端点数 | 22 个（覆盖率 100%） |
| 功能完整性 | 封装工具数 | 31 个 |
| 知识覆盖 | Exploit 签名 | 119 条（43 家族） |
| 知识覆盖 | 覆盖攻击链 | 入口→认证绕过→提权(Linux/Win)→横向移动→容器逃逸 |
| 测试质量 | 测试用例数 | 82 个（78 pass / 95%） |
| 构建质量 | 前端构建 | 6 模块 / 3.97s / 0 errors |

### 真实靶场验证

| 靶场 | 漏洞 | 结果 | PoC 证据 |
|------|------|------|---------|
| **mini_httpd CVE-2018-18778** | 空 Host 头任意文件读取 | ✅ 成功 | HTTP 200 + `/etc/passwd` 内容（`root:x:0:0:`） |
| **Struts2 S2-048** | OGNL 注入 RCE | ✅ 识别 | 正确选择 `/saveGangster.action` + OGNL header 注入 |
| **Confluence CVE-2022-26134** | OGNL 注入 RCE | ✅ 识别 | 5 个 exploit 候选签名匹配，选择 `${1+1}` 算术探测 |
| **DVWA** | File Inclusion | ✅ 成功 | 完整 PoC 报告链路（请求→参数→响应→证据文件） |

### 安全控制验证

- ✅ 未授权公网 IP → 被 ScopeGuard 拒绝
- ✅ 高风险动作（header_mutation/raw_http）→ 正确进入审批状态
- ✅ 审批通过后 → 工具执行并产生证据链
- ✅ 工具失败 → 反思机制调整策略，不做虚假确认

---

## 第 12 页：存在不足与改进方向

- **标题**：不足分析与后续改进

### 当前不足

| 不足 | 表现 |
|------|------|
| 场景覆盖偏 Web | 对纯内网 AD 域渗透、无线安全、IoT 固件等方向支持有限 |
| LLM 依赖性 | LLM API 不可用时退化为规则引擎（可用但智能度下降） |
| 内存型 Agent | 多轮任务间缺乏长期记忆与经验复用 |
| 真实验证待加强 | 部分 payload（如 S2-048）需手工调试才能触发 |

### 改进方向

| 方向 | 具体措施 |
|------|---------|
| **能力扩展** | 增加 AD 域渗透工具链、无线安全模块、IoT 固件分析 |
| **智能提升** | 增强多轮记忆机制、RAG 检索增强、self-play 经验学习 |
| **安全治理** | 细粒度权限控制、操作回滚能力、合规审计报告 |
| **工程完善** | CI/CD 集成测试、Docker Compose 一键部署、Playwright E2E 测试 |

---

## 第 13 页：实践总结与结论

- **标题**：实践总结

### 项目成果

> 本项目完成了一个**面向授权靶场的、LLM 辅助决策的受控安全智能体原型**。

### 验证的核心能力

| 能力 | 说明 |
|------|------|
| 🎯 **自动推进** | 从任务创建到报告输出，全流程自主完成 |
| 🛡️ **受控执行** | 五层安全控制，高风险动作审批 + 审计 |
| 📊 **证据沉淀** | 每步事件记录、结构化证据文件、完整报告 |
| 🔄 **动态调整** | LLM 反思 + 规则兜底，失败后自动换策略 |
| 📚 **知识进化** | searchsploit 自动搜索 → 去重 → 发布到签名库 |

### 核心价值

> **不是替代安全人员，而是把零散工具、分散证据和手工流程整合成一个受控的智能工作流。**

### 一句话收束

> *"我们做的是一个能在授权范围内自主思考、受控执行、留下完整证据链的安全智能体。"*

---

## 第 14 页（可选）：致谢 / Q&A

- **标题**：感谢聆听 · 欢迎提问
- 可配图：项目闭环总图 + 团队合影

---

## 可选附录：建议准备的截图素材

| 页面 | 建议截图 |
|------|---------|
| 任务列表 | 深色主题工作台 + 任务卡片 + API 用量面板 |
| 执行概览 | AgentConsole — Task Snapshot + Tool History + Hosts/Services 行布局 |
| 攻击路径 | PathGraph SVG 节点-边可视化 |
| 审批交互 | ApprovalPanel — 动态参数表单 + JSON 编辑器 |
| PoC 展示 | ReportView 摘要/证据 Tab — PoC 链路 + request/response 摘录 |
| 学习面板 | LearningCandidatePanel — Publish + Expand 按钮 |
| 真实验证 | mini_httpd /etc/passwd 读取结果 |
| 测试结果 | pytest 78 passed / 82 collected |

---

## 汇报时的表达建议

| 做 ✅ | 不做 ❌ |
|------|--------|
| 讲"模块做什么，为什么这样设计" | 逐行念源码或文件名 |
| 强调"LLM 辅助 + 规则兜底"的双保险 | 只说"AI 自动攻击" |
| 展示"从探测到报告"的完整闭环 | 展示孤立的工具输出 |
| 突出安全控制体系的五层设计 | 忽略审批和审计机制 |
| 表达"工程严谨性 + 学术探索性" | 过度强调攻击能力 |
