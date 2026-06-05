from __future__ import annotations

import json
import os

from app.schemas.tool import SearchsploitLookupInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError, run_command

# Fallback: small local cache of common exploit-db entries
# In a production deployment this would be populated from the searchsploit JSON db.
_LOCAL_CACHE: list[dict] = []

# Path to the searchsploit JSON database file (default Kali location)
_SEARCHSPLOIT_DB_PATH = "/usr/share/exploitdb/files_exploits.json"


def _check_searchsploit_available() -> bool:
    try:
        stdout, _, rc = run_command(
            ["searchsploit", "--version"],
            timeout=10,
            max_output_chars=2048,
        )
        return rc == 0 and bool(stdout.strip())
    except ToolExecutionError:
        return False


def _run_searchsploit(query: str, timeout: int, max_output_chars: int) -> list[dict]:
    """Run searchsploit --json and parse the results."""
    args = [
        "searchsploit",
        "--json",
        query,
    ]
    stdout, stderr, rc = run_command(args, timeout=timeout, max_output_chars=max_output_chars)

    if rc != 0 and not stdout.strip():
        raise ToolExecutionError(stderr or f"searchsploit returned non-zero exit for query: {query}")

    # The --json flag outputs a JSON object with a "RESULTS_EXPLOIT" key
    results: list[dict] = []
    try:
        data = json.loads(stdout)
        raw_results = data.get("RESULTS_EXPLOIT", [])
        if isinstance(raw_results, list):
            for entry in raw_results:
                if not isinstance(entry, dict):
                    continue
                results.append({
                    "title": entry.get("Title", entry.get("title", "")).strip(),
                    "edb_id": str(entry.get("EDB-ID", entry.get("edb_id", ""))).strip(),
                    "path": entry.get("Path", entry.get("path", "")).strip(),
                    "type": entry.get("Type", entry.get("type", "")).strip(),
                })
    except (json.JSONDecodeError, KeyError):
        # Fallback: parse the plain text output if JSON parsing fails
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("{") or line.startswith("}"):
                continue
            results.append({
                "title": line[:120],
                "edb_id": "",
                "path": "",
                "type": "",
            })

    return results


def _fallback_local_search(query: str) -> list[dict]:
    """Search fallback local cache or a local exploit-db JSON file.

    If searchsploit is not available, we try to load and search the local JSON
    database file shipped with exploitdb packages.
    """
    query_lower = query.lower()
    results: list[dict] = []

    # Try the database JSON file first
    db_paths = [
        _SEARCHSPLOIT_DB_PATH,
        "/usr/share/exploitdb/exploits/files_exploits.json",
        "/opt/exploitdb/files_exploits.json",
    ]

    for db_path in db_paths:
        if not os.path.isfile(db_path):
            continue
        try:
            with open(db_path, "r", encoding="utf-8", errors="replace") as fh:
                db_data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            continue

        # Iterate through the JSON (can be list or dict)
        entries: list[dict] = []
        if isinstance(db_data, list):
            entries = db_data
        elif isinstance(db_data, dict):
            entries = list(db_data.values())

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            title = str(entry.get("title", entry.get("description", ""))).lower()
            if any(term in title for term in query_lower.split()):
                results.append({
                    "title": str(entry.get("title", entry.get("description", "")).strip()),
                    "edb_id": str(entry.get("id", entry.get("edb_id", ""))).strip(),
                    "path": str(entry.get("file", entry.get("path", ""))).strip(),
                    "type": str(entry.get("type", entry.get("platform", ""))).strip(),
                })
            if len(results) >= 50:
                break
        if results:
            break

    return results


def execute(params: SearchsploitLookupInput, context: ToolContext) -> ToolExecutionResult:
    query = params.query.strip()
    if not query:
        raise ToolExecutionError("searchsploit query must not be empty.")

    results: list[dict] = []

    if _check_searchsploit_available():
        try:
            results = _run_searchsploit(query, timeout=60, max_output_chars=context.max_output_chars)
        except ToolExecutionError:
            results = _fallback_local_search(query)
    else:
        results = _fallback_local_search(query)

    if not results:
        results = _fallback_local_search(query)

    structured: dict = {
        "query": query,
        "results": results,
    }

    if results:
        examples = [r["title"][:80] for r in results[:5]]
        summary = (
            f"searchsploit found {len(results)} exploit(s) for '{query}'. "
            f"Top: {'; '.join(examples)}"
        )
    else:
        summary = (
            f"searchsploit found no results for '{query}'. "
            f"searchsploit binary available={_check_searchsploit_available()}."
        )

    artifact_path = context.artifact_dir / "searchsploit_lookup.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")

    return ToolExecutionResult(
        tool_name="searchsploit_lookup",
        success=True,
        summary=summary,
        raw_output=json.dumps(structured, indent=2)[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
