from __future__ import annotations

import json
import logging
import re
from typing import Any, TypeVar

from langchain_openai import ChatOpenAI

from app.core.config import Settings
from app.core.llm_provider import LLMConfig, LLMProvider

logger = logging.getLogger(__name__)

JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)

_ModelT = TypeVar("_ModelT")


class DeepSeekProvider(LLMProvider):
    """LLM provider that calls the DeepSeek API (OpenAI-compatible) via LangChain."""

    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        self._llm: ChatOpenAI | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.config.api_key)

    def invoke_structured(
        self, schema: type[_ModelT], system_prompt: str, user_prompt: str
    ) -> _ModelT:
        if not self.enabled:
            raise RuntimeError("DeepSeek API is not configured.")

        if self._llm is None:
            self._llm = ChatOpenAI(
                api_key=self.config.api_key,
                model=self.config.model,
                base_url=self.config.base_url,
                temperature=self.config.temperature,
                timeout=self.config.timeout,
                max_tokens=self.config.max_tokens,
            )

        schema_json = json.dumps(
            schema.model_json_schema(), ensure_ascii=False, indent=2
        )

        full_system = (
            f"{system_prompt}\n"
            "You must output only a JSON object. "
            "Do not include explanations, markdown headings, code fences, or extra text."
        )
        full_user = (
            f"{user_prompt}\n\n"
            "Below is the target JSON Schema. Match fields and enum values strictly:\n"
            f"{schema_json}"
        )

        logger.debug("LLM system prompt (first 800 chars): %s", full_system[:800])
        logger.debug("LLM user prompt (first 800 chars): %s", full_user[:800])

        response = self._llm.invoke(
            [("system", full_system), ("human", full_user)]
        )
        content = (
            response.content
            if isinstance(response.content, str)
            else str(response.content)
        )

        logger.debug("LLM raw response (first 1200 chars): %s", content[:1200])

        parsed = self._extract_json(content)
        return schema.model_validate(parsed)

    def _extract_json(self, content: str) -> dict[str, Any]:
        stripped = content.strip()

        block_match = JSON_BLOCK_RE.search(stripped)
        if block_match:
            extracted = block_match.group(1).strip()
            logger.debug(
                "_extract_json: matched fenced block, length=%d", len(extracted)
            )
            stripped = extracted

        start = stripped.find("{")
        end = stripped.rfind("}")

        if start == -1 or end == -1 or end <= start:
            logger.error(
                "_extract_json: no JSON object found in content (first 500 chars): %s",
                content[:500],
            )
            raise ValueError(
                f"DeepSeek did not return a JSON object: {content[:400]}"
            )

        json_str = stripped[start : end + 1]
        logger.debug(
            "_extract_json: extracted JSON substring length=%d, starts=%s...",
            len(json_str),
            json_str[:120],
        )

        try:
            return json.loads(json_str)
        except json.JSONDecodeError as exc:
            logger.error(
                "_extract_json: JSON decode failed at line %d col %d: %s",
                exc.lineno,
                exc.colno,
                exc.msg,
            )
            logger.debug(
                "_extract_json: failing substring (first 500 chars): %s",
                json_str[:500],
            )
            raise ValueError(
                f"DeepSeek returned malformed JSON: {content[:400]}"
            ) from exc


class DeepSeekClient(LLMProvider):
    """Backward-compatible wrapper that constructs an LLMConfig from Settings.

    Delegates all actual work to :class:`DeepSeekProvider`.
    """

    def __init__(self, settings: Settings) -> None:
        config = LLMConfig(
            provider="deepseek",
            model=settings.deepseek_model,
            api_key=settings.deepseek_api_key or settings.llm_api_key or "",
            base_url=settings.deepseek_base_url,
            temperature=settings.llm_temperature,
            timeout=settings.llm_timeout,
            max_tokens=settings.llm_max_tokens,
        )
        self._provider = DeepSeekProvider(config)

    @property
    def enabled(self) -> bool:
        return self._provider.enabled

    def invoke_structured(
        self, schema: type[_ModelT], system_prompt: str, user_prompt: str
    ) -> _ModelT:
        return self._provider.invoke_structured(schema, system_prompt, user_prompt)
