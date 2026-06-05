from __future__ import annotations

import json


_ZH_SYSTEM_PROMPT = """你是本地授权靶场安全测试助手。
你只能在用户声明的授权范围内行动。
你不能请求扫描公网目标。
你不能生成或执行未封装的 Shell 命令。
你要以 observe -> hypothesize -> choose action -> execute -> reflect 的循环推进。
你必须优先选择最小必要动作，而不是机械地走固定阶段。
你必须在真正的高风险利用动作前请求人工审批。
你必须基于证据更新结论。
你不能把工具失败解释为漏洞存在。
你必须在报告中区分确认漏洞、疑似风险和未验证假设。
你可以从提供的原语工具里自由选择下一步，只要符合授权边界和风险约束。

CRITICAL BOUNDARIES:
- You are a security testing assistant for AUTHORIZED targets only.
- Never suggest actions outside the declared scope.
- Never fabricate evidence or claim confirmation without proof.
- Distinguish between: [confirmed], [suspected], [unverified hypothesis].
"""

_EN_SYSTEM_PROMPT = """You are a security testing assistant for authorized local lab targets.
You may only act within the user-declared authorized scope.
You must not scan public internet targets.
You must not generate or execute unwrapped shell commands.
Advance through the loop: observe -> hypothesize -> choose action -> execute -> reflect.
Prefer the minimal necessary action rather than mechanically progressing through fixed stages.
Request human approval before genuinely high-risk exploit actions.
Update conclusions based on evidence.
Do not interpret tool failure as proof of a vulnerability.
Distinguish between confirmed vulnerabilities, suspected risks, and unverified hypotheses in reports.
You may freely choose the next step from the provided primitive tools, as long as it stays within authorization boundaries and risk constraints.

CRITICAL BOUNDARIES:
- You are a security testing assistant for AUTHORIZED targets only.
- Never suggest actions outside the declared scope.
- Never fabricate evidence or claim confirmation without proof.
- Distinguish between: [confirmed], [suspected], [unverified hypothesis].
"""


def get_system_prompt(lang: str = "zh") -> str:
    """Return the system prompt in the requested language.

    lang: "zh" for Chinese (default), "en" for English.
    """
    if lang == "en":
        return _EN_SYSTEM_PROMPT
    return _ZH_SYSTEM_PROMPT


# ── Legacy module-level reference preserves backward compatibility ──────────
SYSTEM_PROMPT = get_system_prompt("zh")


def build_planner_prompt(
    *,
    state: dict,
    allowed_tools: list[dict],
    reflection_candidates: list[dict],
    knowledge_hits: list[dict],
    exploit_candidates: list[dict],
    heuristic_plan: dict,
) -> str:
    payload = {
        "scope": state.get("scope", []),
        "lab_description": state.get("lab_description", ""),
        "current_stage": state.get("current_stage", ""),
        "hosts": state.get("hosts", []),
        "services": state.get("services", []),
        "hypotheses": state.get("hypotheses", []),
        "evidence": state.get("evidence", [])[-20:],
        "recent_actions": state.get("actions", [])[-20:],
        "allowed_tools": allowed_tools,
        "reflection_candidates": reflection_candidates,
        "knowledge_hits": knowledge_hits,
        "exploit_candidates": exploit_candidates,
        "heuristic_plan": heuristic_plan,
        "constraints": [
            "访问范围外目标",
            "任意命令执行",
            "破坏性操作",
            "未审批利用验证",
        ],
        "instruction": [
            "优先决定最有信息增益的下一步动作。",
            "候选优先级必须遵循：reflection_candidates > exploit_candidates > generic tools。",
            "如果 reflection_candidates 非空，优先从中选择，不要忽略它们。",
            "如果 exploit_candidates 非空，优先在这些候选方案中选择，而不是自行发明 payload。",
            "如果存在明确漏洞特征，可直接选择 exploit 原语，不必机械经过全部枚举阶段。",
            "只有当动作本身具备利用或破坏风险时，才把 requires_approval 设为 true。",
            "stage 可使用 observe、enumerate、exploit、reflect、report 等抽象阶段名。",
        ],
    }
    return (
        "请基于以下状态给出下一步动作计划，输出必须符合给定 JSON Schema。\n"
        + json.dumps(payload, ensure_ascii=False, indent=2)
    )


def build_reflection_prompt(*, state: dict, knowledge_hits: list[dict], exploit_candidates: list[dict]) -> str:
    payload = {
        "scope": state.get("scope", []),
        "current_stage": state.get("current_stage", ""),
        "last_decision": state.get("last_decision"),
        "services": state.get("services", []),
        "recent_actions": state.get("actions", [])[-20:],
        "last_result": state.get("last_result"),
        "evidence": state.get("evidence", [])[-20:],
        "findings": state.get("findings", [])[-20:],
        "hypotheses": state.get("hypotheses", [])[-20:],
        "knowledge_hits": knowledge_hits,
        "exploit_candidates": exploit_candidates,
        "instruction": [
            "总结最新动作给安全判断带来的变化。",
            "只保留有证据支撑的结论。",
            "如果应当新增或更新假设，请明确给出。",
            "如果 exploit_candidates 非空，请选出最合理的 0-3 个作为 next_candidates。",
            "显式输出 failure_class。",
            "显式输出 selected_family、rejected_families、family_switch_reason。",
            "如果你改变了 exploit family，要明确说明为什么当前 failure_class 导致你切换 family。",
        ],
    }
    return (
        "请根据最新执行结果做一次简短反思，输出必须符合给定 JSON Schema。\n"
        + json.dumps(payload, ensure_ascii=False, indent=2)
    )
