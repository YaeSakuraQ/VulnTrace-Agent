from __future__ import annotations

import json
import os
import re

from app.schemas.tool import GobusterEnumInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError, run_command

# Built-in small wordlist (70 common paths)
BUILTIN_DIR_WORDLIST = [
    "admin", "login", "wp-admin", "wp-login.php", "dashboard",
    "uploads", "backup", "config", "api", "test", "dev",
    ".git", ".env", "robots.txt", "sitemap.xml", "phpinfo.php",
    "info.php", "shell.php", "cmd.php", "console", "manager",
    "administrator", "user", "users", "register", "signup",
    "signin", "forgot", "reset", "account", "profile",
    "settings", "setup", "install", "README.md", "CHANGELOG.md",
    "debug", "status", "health", "metrics", "monitor",
    "logs", "log", "tmp", "temp", "cache", "assets",
    "static", "public", "private", "files", "download",
    "upload", "file", "image", "images", "img", "css",
    "js", "javascript", "vendor", "node_modules", "composer.json",
    "package.json", "Dockerfile", "docker-compose.yml", ".htaccess",
    "wp-content", "wp-includes", "wp-json", "xmlrpc.php",
    "cgi-bin", "cgi", "server-status", "server-info",
]

BUILTIN_DNS_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "pop3", "imap",
    "webmail", "admin", "portal", "blog", "shop", "store",
    "api", "dev", "test", "stage", "staging", "prod",
    "app", "apps", "cdn", "static", "assets", "media",
    "files", "docs", "doc", "wiki", "support", "help",
    "intranet", "vpn", "remote", "gateway", "proxy", "ns1",
    "ns2", "dns", "dns1", "dns2", "mx", "mx1", "mx2",
    "autodiscover", "autoconfig", "owa", "lync", "skype",
    "sip", "voip", "jabber", "xmpp", "chat", "irc",
    "git", "svn", "jenkins", "ci", "build", "deploy",
    "monitor", "status", "health", "grafana", "kibana",
    "elastic", "logstash", "prometheus", "alertmanager",
    "db", "db1", "db2", "mysql", "postgres", "mongo",
    "redis", "memcached", "elasticsearch", "ldap", "kerberos",
    "k8s", "kubernetes", "docker", "rancher", "swarm",
]


def _gobuster_dir(url: str, wordlist_path: str, timeout: int, max_output_chars: int) -> tuple[str, str, int]:
    args = [
        "gobuster", "dir",
        "-u", url,
        "-w", wordlist_path,
        "--no-error",
        "--no-status-banners",
        "-t", "3",
        "--timeout", f"{min(timeout, 60)}s",
    ]
    return run_command(args, timeout=timeout + 10, max_output_chars=max_output_chars)


def _gobuster_dns(domain: str, wordlist_path: str, timeout: int, max_output_chars: int) -> tuple[str, str, int]:
    args = [
        "gobuster", "dns",
        "-d", domain,
        "-w", wordlist_path,
        "-t", "3",
        "--timeout", f"{min(timeout, 60)}s",
    ]
    return run_command(args, timeout=timeout + 10, max_output_chars=max_output_chars)


def _resolve_mode_port(params: GobusterEnumInput) -> tuple[str, str]:
    """Resolve the mode and return (url_or_domain, wordlist)."""
    if params.mode == "dns":
        wordlist = BUILTIN_DNS_WORDLIST
        domain = params.target
        return domain, wordlist
    else:
        wordlist = BUILTIN_DIR_WORDLIST
        url = f"{params.scheme}://{params.target}:{params.port}"
        return url, wordlist


# Regex to parse gobuster dir output lines: e.g. "/admin (Status: 200) [Size: 1234]"
DIR_PARSE_RE = re.compile(r"^(/\S*)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]")


def _parse_dir_output(stdout: str) -> list[dict]:
    findings: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        m = DIR_PARSE_RE.search(line)
        if m:
            findings.append({
                "path": m.group(1),
                "status": int(m.group(2)),
                "size": int(m.group(3)),
            })
    return findings


# Regex to parse gobuster dns output: e.g. "Found: www.example.com"
DNS_FOUND_RE = re.compile(r"^Found:\s*(\S+)")


def _parse_dns_output(stdout: str, domain: str) -> list[dict]:
    findings: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        m = DNS_FOUND_RE.search(line)
        if m:
            findings.append({
                "path": m.group(1),
                "status": 0,
                "size": 0,
            })
    return findings


def execute(params: GobusterEnumInput, context: ToolContext) -> ToolExecutionResult:
    target_str, wordlist = _resolve_mode_port(params)

    wordlist_path = context.artifact_dir / "gobuster_words.txt"
    wordlist_path.write_text("\n".join(wordlist) + "\n", encoding="utf-8")

    try:
        if params.mode == "dns":
            stdout, stderr, rc = _gobuster_dns(
                target_str, str(wordlist_path), params.timeout, context.max_output_chars
            )
            findings = _parse_dns_output(stdout, target_str)
        else:
            stdout, stderr, rc = _gobuster_dir(
                target_str, str(wordlist_path), params.timeout, context.max_output_chars
            )
            findings = _parse_dir_output(stdout)

        if rc != 0 and not findings:
            raise ToolExecutionError(stderr or stdout or "gobuster returned non-zero exit code.")
    except ToolExecutionError as exc:
        if "Required tool not found" in str(exc) or "not found" in str(exc):
            # Fallback: describe what would have been scanned
            fallback_msg = (
                f"gobuster binary not available. Built-in wordlist has "
                f"{len(wordlist)} entries for {params.mode} mode. "
                f"Install gobuster to enable directory/DNS enumeration. "
                f"Target: {target_str}"
            )
            raise ToolExecutionError(fallback_msg) from exc
        raise

    structured: dict = {
        "mode": params.mode,
        "url": target_str,
        "findings": findings,
    }

    if findings:
        example = findings[:5]
        paths = ", ".join(f["path"] for f in example)
        summary = (
            f"gobuster {params.mode} on {target_str}: "
            f"{len(findings)} finding(s) out of {len(wordlist)} words. "
            f"First: {paths}"
        )
    else:
        summary = (
            f"gobuster {params.mode} on {target_str}: "
            f"no findings out of {len(wordlist)} words."
        )

    artifact_path = context.artifact_dir / "gobuster_enum.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")

    return ToolExecutionResult(
        tool_name="gobuster_enum",
        success=True,
        summary=summary,
        raw_output=json.dumps(structured, indent=2)[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
