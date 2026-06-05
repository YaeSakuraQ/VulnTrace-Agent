from __future__ import annotations

import json
import re

import requests
import urllib.parse

from app.schemas.tool import SqliProbeInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError


# Payloads to inject
PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR "1"="1',
    "1' OR '1'='1",
]

# Common SQL error patterns to detect in responses
SQL_ERROR_PATTERNS = [
    (re.compile(r"SQL syntax.*MySQL", re.IGNORECASE), "MySQL syntax error"),
    (re.compile(r"Warning.*mysql_.*", re.IGNORECASE), "MySQL warning"),
    (re.compile(r"valid MySQL result", re.IGNORECASE), "MySQL result error"),
    (re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE), "PostgreSQL error"),
    (re.compile(r"Driver.*SQL\w*.*Server", re.IGNORECASE), "SQL Server driver"),
    (re.compile(r"Microsoft OLE DB.*SQL Server", re.IGNORECASE), "MSSQL OLE DB"),
    (re.compile(r"ODBC.*Driver", re.IGNORECASE), "ODBC driver error"),
    (re.compile(r"SQLite.*error", re.IGNORECASE), "SQLite error"),
    (re.compile(r"Oracle.*error", re.IGNORECASE), "Oracle error"),
    (re.compile(r"ORA-\d{5}", re.IGNORECASE), "Oracle ORA code"),
    (re.compile(r"DB2 SQL error", re.IGNORECASE), "DB2 error"),
    (re.compile(r"SQL\s*syntax", re.IGNORECASE), "Generic SQL syntax"),
    (re.compile(r"unclosed quotation mark", re.IGNORECASE), "Unclosed quote"),
    (re.compile(r"quoted string not properly terminated", re.IGNORECASE), "Unterminated string"),
    (re.compile(r"syntax error", re.IGNORECASE), "Syntax error"),
    (re.compile(r"unexpected end of SQL", re.IGNORECASE), "Unexpected SQL end"),
    (re.compile(r"sql error", re.IGNORECASE), "SQL error"),
]


def _inject_param(url: str, param: str, payload: str, timeout: int) -> dict:
    """Inject a payload into the specified parameter and analyze the response."""
    parsed = list(urllib.parse.urlparse(url))
    query = urllib.parse.parse_qs(parsed[4])
    # Replace the target parameter with the payload
    query[param] = [payload]
    parsed[4] = urllib.parse.urlencode(query, doseq=True)
    injected_url = urllib.parse.urlunparse(parsed)

    result = {
        "payload": payload,
        "error_matched": False,
        "matched_pattern": "",
    }

    try:
        resp = requests.get(
            injected_url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
        )
        body = resp.text
    except requests.RequestException as exc:
        result["error_matched"] = False
        result["matched_pattern"] = f"request failed: {exc}"
        return result

    for pattern, label in SQL_ERROR_PATTERNS:
        if pattern.search(body):
            result["error_matched"] = True
            result["matched_pattern"] = label
            break

    return result


def execute(params: SqliProbeInput, context: ToolContext) -> ToolExecutionResult:
    base_url = f"{params.scheme}://{params.target}:{params.port}{params.path}"
    injections: list[dict] = []

    for payload in PAYLOADS:
        try:
            injection_result = _inject_param(
                base_url, params.param, payload, params.timeout
            )
            injections.append(injection_result)
        except Exception as exc:
            injections.append({
                "payload": payload,
                "error_matched": False,
                "matched_pattern": f"injection failed: {exc}",
            })

    errors_found = [i for i in injections if i["error_matched"]]
    if errors_found:
        patterns = list({i["matched_pattern"] for i in errors_found})
        summary = (
            f"SQL injection probe on {params.param}@{base_url}: "
            f"{len(errors_found)}/{len(PAYLOADS)} payload(s) triggered errors "
            f"({', '.join(patterns[:5])})."
        )
    else:
        summary = (
            f"SQL injection probe on {params.param}@{base_url}: "
            f"no SQL errors detected with {len(PAYLOADS)} payload(s)."
        )

    structured: dict = {
        "url": base_url,
        "param": params.param,
        "injections": injections,
    }

    artifact_path = context.artifact_dir / "sqli_probe.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")

    return ToolExecutionResult(
        tool_name="sqli_probe",
        success=True,
        summary=summary,
        raw_output=json.dumps(structured, indent=2)[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
