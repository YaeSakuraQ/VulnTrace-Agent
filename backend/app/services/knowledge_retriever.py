from __future__ import annotations

import json
import math
import re
from pathlib import Path

# Words that carry negligible semantic weight for vulnerability/exploit search
STOP_WORDS: set[str] = {
    "the", "and", "for", "are", "but", "not", "you", "all", "can", "had",
    "her", "was", "one", "our", "out", "has", "have", "from", "they",
    "this", "that", "with", "will", "each", "been", "them", "some",
    "what", "when", "were", "said", "does", "their", "also", "into",
    "more", "than", "very", "just", "over", "its", "should", "could",
    "would", "about", "which", "other", "after", "being", "only",
    "these", "those", "then", "there", "such", "like",
}


class KnowledgeRetriever:
    def __init__(self, knowledge_dir: Path) -> None:
        self.knowledge_dir = knowledge_dir

    def search(self, query: str, top_k: int = 3) -> list[dict[str, str]]:
        """Search knowledge files using TF-IDF-style scoring.

        - Reads both .md and .json files.
        - Ignores stop words.
        - Penalises common words (inverse-document-frequency).
        - Snippet is extracted around the best-matching keyword line.
        """
        if not self.knowledge_dir.exists():
            return []

        terms = self._tokenize(query)
        if not terms:
            return []

        paths = sorted(self.knowledge_dir.glob("*.md")) + sorted(self.knowledge_dir.glob("*.json"))
        if not paths:
            return []

        # --- read all docs and build a simple TF-IDF index ---
        docs: list[tuple[Path, str, list[str]]] = []  # (path, raw_text, tokenised)
        for path in paths:
            if not path.is_file():
                continue
            raw = path.read_text(encoding="utf-8")
            tokens = self._tokenize(raw)
            docs.append((path, raw, tokens))

        # document frequency (how many docs contain each term)
        df: dict[str, int] = {}
        for _, _, tokens in docs:
            seen_in_doc: set[str] = set()
            for token in tokens:
                if token not in seen_in_doc:
                    df[token] = df.get(token, 0) + 1
                    seen_in_doc.add(token)

        num_docs = len(docs)

        # score each doc against the query
        scored: list[tuple[float, Path, str]] = []
        for path, raw, tokens in docs:
            score = self._tf_idf_score(terms, tokens, df, num_docs)
            if score <= 0.0:
                continue
            snippet = self._extract_snippet(raw, terms)
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

    def search_by_port(self, port: int) -> list[dict[str, str]]:
        """Return knowledge items relevant to a specific TCP/UDP port."""
        if not self.knowledge_dir.exists():
            return []
        results: list[dict[str, str]] = []
        port_str = str(port)
        for path in sorted(self.knowledge_dir.rglob("*.md")):
            if not path.is_file():
                continue
            raw = path.read_text(encoding="utf-8")
            lowered = raw.lower()
            if port_str in lowered:
                snippet = self._extract_snippet(raw, [port_str])
                results.append(
                    {
                        "title": path.stem,
                        "path": str(path),
                        "snippet": snippet,
                    }
                )
        # Also try to match from JSON signatures
        for path in sorted(self.knowledge_dir.rglob("*.json")):
            if not path.is_file():
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                for sig in payload.get("signatures", []):
                    matcher = sig.get("matcher", {}) or sig.get("match", {})
                    ports = matcher.get("port_in", [])
                    if port in ports:
                        title = sig.get("id", "unknown")
                        rationale = ""
                        for c in sig.get("candidates", []):
                            rationale = str(c.get("rationale", ""))[:280]
                            break
                        results.append(
                            {
                                "title": str(title),
                                "path": str(path),
                                "snippet": rationale or f"Port {port} matched in exploit signatures",
                            }
                        )
            except (json.JSONDecodeError, KeyError):
                pass
        return results

    def search_by_service(self, service_name: str) -> list[dict[str, str]]:
        """Return knowledge items relevant to a specific service name."""
        if not self.knowledge_dir.exists():
            return []
        results: list[dict[str, str]] = []
        svc_lower = service_name.lower()
        for path in sorted(self.knowledge_dir.rglob("*.md")):
            if not path.is_file():
                continue
            raw = path.read_text(encoding="utf-8")
            lowered = raw.lower()
            if svc_lower in lowered:
                snippet = self._extract_snippet(raw, [svc_lower])
                results.append(
                    {
                        "title": path.stem,
                        "path": str(path),
                        "snippet": snippet,
                    }
                )
        # Also try from JSON signatures
        for path in sorted(self.knowledge_dir.rglob("*.json")):
            if not path.is_file():
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                for sig in payload.get("signatures", []):
                    matcher = sig.get("matcher", {}) or sig.get("match", {})
                    products = matcher.get("service_products", []) or matcher.get("service_products_contains", [])
                    names = matcher.get("service_names", [])
                    combined = [str(x).lower() for x in products + names]
                    if svc_lower in " ".join(combined):
                        title = sig.get("id", "unknown")
                        rationale = ""
                        for c in sig.get("candidates", []):
                            rationale = str(c.get("rationale", ""))[:280]
                            break
                        results.append(
                            {
                                "title": str(title),
                                "path": str(path),
                                "snippet": rationale or f"Service '{service_name}' matched in exploit signatures",
                            }
                        )
            except (json.JSONDecodeError, KeyError):
                pass
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """Split on non-alphanumeric, lowercase, drop stop words and short tokens."""
        raw = re.split(r'[\s,;:/()\[\]\{\}"`!@#$%^&*+=|\\<>?]+', text.lower())
        return [
            t
            for t in raw
            if len(t) >= 3 and t not in STOP_WORDS and not t.isdigit()
        ]

    @staticmethod
    def _tf_idf_score(
        query_terms: list[str],
        doc_tokens: list[str],
        df: dict[str, int],
        num_docs: int,
    ) -> float:
        if not doc_tokens:
            return 0.0
        score = 0.0
        doc_len = len(doc_tokens)
        for term in query_terms:
            # term frequency in this doc
            tf = doc_tokens.count(term) / max(doc_len, 1)
            # inverse document frequency (smooth)
            doc_freq = df.get(term, 0)
            idf = math.log((num_docs + 1) / (doc_freq + 1)) + 1.0
            score += tf * idf
        return score

    @staticmethod
    def _extract_snippet(raw: str, keywords: list[str]) -> str:
        """Return up to 3 lines: the line where a keyword first appears plus one line before and after."""
        lines = raw.splitlines()
        if not keywords or not lines:
            return "\n".join(lines[:3]).strip().replace("\t", " ")

        lower_lines = [line.lower() for line in lines]
        for keyword in keywords:
            kw_lower = keyword.lower()
            for idx, lowered in enumerate(lower_lines):
                if kw_lower in lowered:
                    start = max(0, idx - 1)
                    end = min(len(lines), idx + 2)
                    snippet_lines = lines[start:end]
                    return "\n".join(line.strip().replace("\t", " ") for line in snippet_lines)

        # fallback: first 3 lines
        return "\n".join(line.strip().replace("\t", " ") for line in lines[:3])
