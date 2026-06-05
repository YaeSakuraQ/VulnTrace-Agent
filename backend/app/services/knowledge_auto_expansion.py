"""Auto-expand the exploit knowledge base from searchsploit / Exploit-DB results.

Flow:
  1. Planner hits an unknown service with no matching exploit signature.
  2. The planner triggers searchsploit_lookup tool to query Exploit-DB.
  3. This service takes the searchsploit result, deduplicates with existing
     signatures, and proposes new candidate signatures for review.
  4. On user approval, the signature is appended to exploit_signatures.json
     so it becomes immediately available for future tasks.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.core.config import PROJECT_ROOT

logger = logging.getLogger(__name__)

# ── Pydantic schemas ─────────────────────────────────────────────────────────

class ProposedSignature(BaseModel):
    """A candidate exploit signature ready for review / insertion."""
    id: str = Field(description="Unique kebab-case signature id")
    family: str = Field(description="Exploit family name")
    matcher: dict[str, Any] = Field(description="Matcher dict with service_products_contains, port_in, etc.")
    min_score: int = Field(default=1, description="Minimum match score")
    candidates: list[dict[str, Any]] = Field(description="Candidate actions list")
    source_edb_id: str = Field(default="", description="Source Exploit-DB ID if applicable")
    source_query: str = Field(default="", description="The service query that triggered the search")
    rationale: str = Field(default="", description="Why this signature was proposed")


class KnowledgeAutoExpansion:
    """Service that bridges searchsploit results into the exploit signature database."""

    DEFAULT_CORPUS_PATH = PROJECT_ROOT / "data" / "knowledge" / "exploit_signatures.json"

    def __init__(
        self,
        *,
        corpus_path: Path | None = None,
        llm_provider: Any = None,  # Optional LLM for intelligent filtering
    ) -> None:
        self.corpus_path = corpus_path or self.DEFAULT_CORPUS_PATH
        self.llm = llm_provider

    # ── Public API ───────────────────────────────────────────────────────────

    def searchsploit_to_proposals(
        self,
        service: dict[str, Any],
        searchsploit_results: list[dict[str, Any]],
        *,
        max_proposals: int = 5,
    ) -> list[ProposedSignature]:
        """Convert raw searchsploit results into proposed exploit signatures.

        Args:
            service: The service dict (target, port, service, product, version).
            searchsploit_results: Results from the searchsploit_lookup tool.
            max_proposals: Maximum number of proposals to return.

        Returns:
            A deduped list of ProposedSignature objects.
        """
        if not searchsploit_results:
            return []

        # Deduplicate against existing signatures
        existing_ids = self._load_existing_ids()

        proposals: list[ProposedSignature] = []
        for result in searchsploit_results:
            if len(proposals) >= max_proposals:
                break

            proposed_id = self._derive_signature_id(result, service)
            if proposed_id in existing_ids:
                logger.debug("Skipping duplicate signature: %s", proposed_id)
                continue

            proposals.append(self._result_to_signature(result, service, proposed_id))

        return proposals

    def approve_and_publish(self, proposal: ProposedSignature | dict[str, Any]) -> bool:
        """Append an approved signature to the knowledge base.

        Returns True on success.
        """
        if isinstance(proposal, dict):
            proposal = ProposedSignature.model_validate(proposal)

        sig_dict = proposal.model_dump(exclude_none=True)
        # Clean up for JSON: remove internal-only fields
        sig_dict.pop("source_edb_id", None)
        sig_dict.pop("source_query", None)
        sig_dict.pop("rationale", None)

        try:
            appended = self._append_signature(sig_dict)
            if appended:
                logger.info(
                    "Published new signature '%s' (family=%s) from EDB:%s",
                    proposal.id, proposal.family, proposal.source_edb_id,
                )
            return appended
        except Exception as exc:
            logger.error("Failed to publish signature %s: %s", proposal.id, exc)
            return False

    def search_and_propose(
        self,
        service: dict[str, Any],
        searchsploit_results: list[dict[str, Any]],
        *,
        auto_publish_low_risk: bool = False,
    ) -> dict[str, Any]:
        """Orchestrate: search → dedup → propose → optionally auto-publish.

        Returns a status dict with counts and IDs.
        """
        proposals = self.searchsploit_to_proposals(service, searchsploit_results)

        published: list[str] = []
        review_needed: list[str] = []

        for proposal in proposals:
            # High-risk exploits always need review
            is_high_risk = any(
                c.get("risk_level") in {"high", "critical"}
                for c in proposal.candidates
            )

            if auto_publish_low_risk and not is_high_risk:
                if self.approve_and_publish(proposal):
                    published.append(proposal.id)
            else:
                review_needed.append(proposal.id)

        return {
            "total_found": len(searchsploit_results),
            "proposed": len(proposals),
            "published": published,
            "review_needed": review_needed,
        }

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _load_existing_ids(self) -> set[str]:
        """Load the set of IDs already present in the corpus."""
        if not self.corpus_path.is_file():
            return set()
        try:
            data = json.loads(self.corpus_path.read_text(encoding="utf-8"))
            return {s["id"] for s in data.get("signatures", []) if isinstance(s, dict)}
        except (json.JSONDecodeError, OSError):
            return set()

    def _derive_signature_id(self, result: dict[str, Any], service: dict[str, Any]) -> str:
        """Create a stable, unique signature ID from a searchsploit result."""
        product = str(service.get("product", "") or service.get("service", "unknown"))
        product_slug = "".join(c if c.isalnum() else "_" for c in product.lower())[:30]

        edb_id = str(result.get("edb_id", "")).strip()
        if edb_id:
            return f"edb_{edb_id}_{product_slug}"

        title = result.get("title", "").strip()
        title_hash = hashlib.md5(title.encode()).hexdigest()[:8] if title else "unknown"
        return f"auto_{product_slug}_{title_hash}"

    def _result_to_signature(
        self,
        result: dict[str, Any],
        service: dict[str, Any],
        proposed_id: str,
    ) -> ProposedSignature:
        """Build a ProposedSignature from a single searchsploit result + service context."""
        product = str(service.get("product", "")).strip()
        service_name = str(service.get("service", "")).strip()
        port = int(service.get("port", 0))
        target = str(service.get("target", ""))
        scheme = "https" if port in {443, 8443} else "http"

        title = result.get("title", "").strip()
        edb_id = result.get("edb_id", "").strip()
        exploit_type = result.get("type", "").strip().lower()

        # ── Determine exploit family ──────────────────────────────────────
        family = self._guess_family(title, exploit_type, service)

        # ── Build matcher ─────────────────────────────────────────────────
        matcher: dict[str, Any] = {}

        if product:
            matcher["service_products_contains"] = [product.lower()]
        if service_name and service_name != product:
            matcher.setdefault("service_products_contains", []).append(service_name.lower())

        if port:
            matcher["port_in"] = [port]

        # ── Determine tool and params ─────────────────────────────────────
        tool_name, params_template = self._select_tool_for_exploit(
            exploit_type, target, port, scheme
        )

        # ── Determine risk and approval ───────────────────────────────────
        risk_level = "high" if any(
            kw in title.lower()
            for kw in ["rce", "execution", "overflow", "privilege", "bypass", "injection"]
        ) else "medium"

        return ProposedSignature(
            id=proposed_id,
            family=family,
            matcher=matcher,
            min_score=1,
            candidates=[
                {
                    "tool_name": tool_name,
                    "stage": "exploit",
                    "params_template": params_template,
                    "requires_approval": risk_level in {"high", "critical"},
                    "risk_level": risk_level,
                    "confidence": "medium",
                    "rationale": f"Auto-proposed from searchsploit result: {title}",
                    "expected_evidence": f"Exploit verification evidence for {title}",
                }
            ],
            source_edb_id=edb_id,
            source_query=f"{product} {service_name}",
            rationale=f"Auto-generated from Exploit-DB entry {edb_id}: {title}",
        )

    def _guess_family(
        self,
        title: str,
        exploit_type: str,
        service: dict[str, Any],
    ) -> str:
        """Heuristically map an exploit to a family."""
        title_lower = title.lower()
        type_lower = exploit_type.lower()

        # Check title/type keywords
        family_keywords = [
            ("privilege_escalation", ["privilege escalation", "local", "privesc", "lpe", "elevation"]),
            ("sqli", ["sql injection", "sqli", "sql"]),
            ("xss", ["xss", "cross site scripting", "cross-site"]),
            ("command_injection", ["command injection", "rce", "remote code execution", "code execution"]),
            ("path_traversal", ["path traversal", "directory traversal", "lfi", "file inclusion"]),
            ("ssrf", ["ssrf", "server side request forgery"]),
            ("deserialization", ["deserializ", "unserializ"]),
            ("ssti", ["ssti", "template injection", "server side template"]),
            ("xxe", ["xxe", "xml external entity"]),
            ("auth_bypass", ["auth bypass", "authentication bypass", "unauth"]),
            ("service_exploit", ["buffer overflow", "dos", "denial of service", "overflow"]),
            ("container_escape", ["container", "docker", "escape", "sandbox"]),
            ("cve", ["cve-"]),
        ]

        for family, keywords in family_keywords:
            if any(kw in title_lower or kw in type_lower for kw in keywords):
                return family

        # Fallback: use service type
        service_name = str(service.get("service", "")).lower()
        if service_name in {"smb", "microsoft-ds", "netbios-ssn"}:
            return "service_exploit"
        if service_name in {"ssh"}:
            return "weak_crypto"
        if service_name in {"ftp"}:
            return "unauth_access"
        if service_name in {"mysql", "postgresql", "mssql", "oracle", "redis", "mongodb"}:
            return "service_exploit"
        if service_name in {"http", "https", "www", "http-proxy"}:
            return "cve"

        return "service_exploit"

    @staticmethod
    def _select_tool_for_exploit(
        exploit_type: str,
        target: str,
        port: int,
        scheme: str,
    ) -> tuple[str, dict[str, Any]]:
        """Pick the best tool and default params for a given exploit type."""
        base_params: dict[str, Any] = {"target": target, "port": port}

        type_lower = exploit_type.lower()

        if "web" in type_lower or "php" in type_lower or "http" in type_lower:
            return "vuln_verify", {
                **base_params,
                "scheme": scheme,
                "profile": "generic_web",
                "service_name": "http",
                "service_product": "",
                "timeout": 60,
            }

        if "sql" in type_lower:
            return "sqli_probe", {
                **base_params,
                "scheme": scheme,
                "path": "/",
                "param": "id",
                "timeout": 30,
            }

        if "remote" in type_lower or "rce" in type_lower:
            return "vuln_verify", {
                **base_params,
                "scheme": scheme,
                "profile": "generic_exploit",
                "service_name": "http",
                "service_product": "",
                "timeout": 120,
            }

        if "local" in type_lower:
            return "linpeas_runner", {
                "target": target,
                "timeout": 60,
            }

        if "dos" in type_lower or "overflow" in type_lower:
            return "tcp_send", {
                **base_params,
                "payload": "",
                "encoding": "latin1",
                "timeout": 15,
            }

        # Default
        return "vuln_verify", {
            **base_params,
            "scheme": scheme,
            "profile": "generic_web",
            "service_name": "http",
            "service_product": "",
            "timeout": 60,
        }

    def _append_signature(self, sig: dict[str, Any]) -> bool:
        """Append a single signature to the exploit_signatures.json corpus.

        Creates the file if missing.  Returns True on success.
        """
        try:
            if self.corpus_path.is_file():
                data = json.loads(self.corpus_path.read_text(encoding="utf-8"))
            else:
                data = {"families": {}, "signatures": []}

            # Auto-register the family if new
            family = sig.get("family", "unknown")
            if family and family not in data.setdefault("families", {}):
                data["families"][family] = {
                    "id": family,
                    "title": family.replace("_", " ").title(),
                    "description": f"Auto-registered family for {sig['id']}",
                }

            data.setdefault("signatures", []).append(sig)

            # Atomic write
            temp_path = self.corpus_path.with_suffix(".tmp")
            temp_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            temp_path.replace(self.corpus_path)

            return True
        except Exception as exc:
            logger.error("Failed to write signature: %s", exc)
            return False


def build_proposal_from_searchsploit(
    result: dict[str, Any],
    service: dict[str, Any],
) -> ProposedSignature:
    """Convenience function for external callers (e.g. knowledge_capture_service)."""
    expander = KnowledgeAutoExpansion()
    proposed_id = expander._derive_signature_id(result, service)
    return expander._result_to_signature(result, service, proposed_id)
