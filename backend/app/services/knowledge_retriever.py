from __future__ import annotations

import re
from pathlib import Path


class KnowledgeRetriever:
    def __init__(self, knowledge_dir: Path) -> None:
        self.knowledge_dir = knowledge_dir

    def search(self, query: str, top_k: int = 3) -> list[dict[str, str]]:
        if not self.knowledge_dir.exists():
            return []

        terms = [term for term in re.split(r"[\s,;:/]+", query.lower()) if len(term) >= 3]
        scored: list[tuple[int, Path, str]] = []
        for path in sorted(self.knowledge_dir.glob("*.md")):
            content = path.read_text(encoding="utf-8")
            lowered = content.lower()
            score = sum(lowered.count(term) for term in terms)
            if score <= 0:
                continue
            snippet = content[:280].strip().replace("\n", " ")
            scored.append((score, path, snippet))

        scored.sort(key=lambda item: item[0], reverse=True)
        return [
            {
                "title": path.stem,
                "path": str(path),
                "snippet": snippet,
            }
            for _, path, snippet in scored[:top_k]
        ]
