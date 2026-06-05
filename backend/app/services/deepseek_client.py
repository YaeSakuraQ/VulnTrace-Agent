from __future__ import annotations

import json
import re
from typing import Any

from langchain_openai import ChatOpenAI

from app.core.config import Settings


JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)


class DeepSeekClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._llm: ChatOpenAI | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.settings.deepseek_api_key)

    def invoke_structured(self, schema: type, system_prompt: str, user_prompt: str) -> Any:
        if not self.enabled:
            raise RuntimeError("DeepSeek API is not configured.")

        if self._llm is None:
            self._llm = ChatOpenAI(
                api_key=self.settings.deepseek_api_key,
                model=self.settings.deepseek_model,
                base_url=self.settings.deepseek_base_url,
                temperature=0.2,
                timeout=60,
            )

        response = self._llm.invoke(
            [
                (
                    "system",
                    (
                        f"{system_prompt}\n"
                        "你必须只输出一个 JSON 对象，不要输出解释、Markdown、代码块标题或额外文本。"
                    ),
                ),
                (
                    "human",
                    (
                        f"{user_prompt}\n\n"
                        "下面是目标 JSON Schema，请严格匹配字段和枚举值：\n"
                        f"{json.dumps(schema.model_json_schema(), ensure_ascii=False, indent=2)}"
                    ),
                ),
            ]
        )
        content = response.content if isinstance(response.content, str) else str(response.content)
        parsed = self._extract_json(content)
        return schema.model_validate(parsed)

    def _extract_json(self, content: str) -> dict[str, Any]:
        stripped = content.strip()
        block_match = JSON_BLOCK_RE.search(stripped)
        if block_match:
            stripped = block_match.group(1).strip()
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError(f"DeepSeek did not return a JSON object: {content[:400]}")
        return json.loads(stripped[start : end + 1])
