# 使用说明

## 1. 准备环境

1. 复制 `.env.example` 为 `.env` 并填写 `DEEPSEEK_API_KEY`（可选，不填则走规则规划兜底）。
2. 确认 Kali Linux 中可用 `nmap`、`nikto`、`ffuf`、`curl`、`python3`、`node`、`npm`。

## 2. 启动后端

```bash
./scripts/run_backend.sh
```

## 3. 启动前端

```bash
./scripts/run_frontend.sh
```

## 4. 演示流程

1. 在首页直接点击 DVWA、Metasploitable 或 Vulhub 模板卡片，自动带出推荐参数。
2. 如需微调，直接点击模板下方的推荐 IP/范围或推荐端口预设，快速覆盖表单。
3. 如需快速演示，直接点击“按模板创建并运行”。
4. 也可以先微调任务说明，再手动点击“创建任务”。
5. 观察智能体自动完成低风险阶段。
6. 当界面出现审批卡片时，批准或修改后批准。
7. 等待报告生成并在报告区查看结果。
