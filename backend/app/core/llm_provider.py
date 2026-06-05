from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Literal

from pydantic import BaseModel


class LLMConfig(BaseModel):
    provider: Literal["deepseek", "openai", "anthropic", "ollama"]
    model: str
    api_key: str
    base_url: str | None = None
    temperature: float = 0.2
    timeout: int = 120
    max_tokens: int = 8192


class LLMProvider(ABC):
    """Abstract base for LLM providers used by the planner and other agents."""

    @property
    @abstractmethod
    def enabled(self) -> bool: ...

    @abstractmethod
    def invoke_structured(
        self, schema: type, system_prompt: str, user_prompt: str
    ) -> Any: ...
