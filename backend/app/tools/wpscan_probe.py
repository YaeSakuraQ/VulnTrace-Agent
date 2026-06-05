from __future__ import annotations

import json
import re

import requests
import urllib3

from app.schemas.tool import ToolExecutionResult, WpscanProbeInput
from app.tools.base import ToolContext, ToolExecutionError, run_command

# Suppress InsecureRequestWarning for probes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common WordPress plugin paths for fallback enumeration
COMMON_PLUGIN_PATHS = [
    "wp-content/plugins/akismet/",
    "wp-content/plugins/contact-form-7/",
    "wp-content/plugins/woocommerce/",
    "wp-content/plugins/wordfence/",
    "wp-content/plugins/wordpress-seo/",
    "wp-content/plugins/jetpack/",
    "wp-content/plugins/elementor/",
    "wp-content/plugins/classic-editor/",
    "wp-content/plugins/hello-dolly/",
    "wp-content/plugins/wp-rocket/",
    "wp-content/plugins/w3-total-cache/",
    "wp-content/plugins/updraftplus/",
    "wp-content/plugins/wordpress-importer/",
    "wp-content/plugins/all-in-one-wp-migration/",
    "wp-content/plugins/wp-super-cache/",
    "wp-content/plugins/duplicator/",
    "wp-content/plugins/wp-file-manager/",
    "wp-content/plugins/revslider/",
    "wp-content/plugins/visual-composer/",
    "wp-content/plugins/litespeed-cache/",
]


def _check_wpscan_available() -> bool:
    try:
        stdout, _, rc = run_command(
            ["wpscan", "--version"],
            timeout=10,
            max_output_chars=2048,
        )
        return rc == 0 and bool(stdout.strip())
    except ToolExecutionError:
        return False


def _run_wpscan(url: str, timeout: int, max_output_chars: int) -> tuple[str, str, int]:
    """Run wpscan with JSON output."""
    args = [
        "wpscan",
        "--url", url,
        "--no-banner",
        "--format", "json",
        "--disable-tls-checks",
        "--random-user-agent",
    ]
    return run_command(args, timeout=timeout, max_output_chars=max_output_chars)


def _parse_wpscan_json(raw_output: str) -> dict:
    """Parse wpscan JSON output into structured data."""
    result = {
        "wordpress_detected": False,
        "version": "",
        "vulnerabilities": [],
        "users": [],
    }

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        return result

    if not isinstance(data, dict):
        return result

    # Version detection
    version_info = data.get("version", {})
    if isinstance(version_info, dict):
        result["wordpress_detected"] = True
        result["version"] = str(version_info.get("number", ""))
        # Vulnerabilities in version
        vulns = version_info.get("vulnerabilities", [])
        if isinstance(vulns, list):
            for v in vulns:
                if isinstance(v, dict):
                    result["vulnerabilities"].append({
                        "id": str(v.get("id", "")),
                        "title": str(v.get("title", "")),
                        "fixed_in": str(v.get("fixed_in", "")),
                    })

    # Plugins
    plugins = data.get("plugins", {})
    if isinstance(plugins, dict):
        for plugin_name, plugin_data in plugins.items():
            if isinstance(plugin_data, dict):
                pvulns = plugin_data.get("vulnerabilities", [])
                if isinstance(pvulns, list):
                    for v in pvulns:
                        if isinstance(v, dict):
                            result["vulnerabilities"].append({
                                "id": str(v.get("id", "")),
                                "title": f"[Plugin: {plugin_name}] {v.get('title', '')}",
                                "fixed_in": str(v.get("fixed_in", "")),
                            })

    # Themes
    themes = data.get("themes", {})
    if isinstance(themes, dict):
        for theme_name, theme_data in themes.items():
            if isinstance(theme_data, dict):
                tvulns = theme_data.get("vulnerabilities", [])
                if isinstance(tvulns, list):
                    for v in tvulns:
                        if isinstance(v, dict):
                            result["vulnerabilities"].append({
                                "id": str(v.get("id", "")),
                                "title": f"[Theme: {theme_name}] {v.get('title', '')}",
                                "fixed_in": str(v.get("fixed_in", "")),
                            })

    # Users
    users_data = data.get("users", {})
    if isinstance(users_data, dict):
        for user_name in users_data.keys():
            result["users"].append(str(user_name))

    # Main theme
    main_theme = data.get("main_theme", {})
    if isinstance(main_theme, dict) and main_theme.get("style_name"):
        result["wordpress_detected"] = True

    # If version is null, might still be WordPress
    if result["wordpress_detected"] or data:
        if not result["wordpress_detected"] and "wordpress" in str(data).lower():
            result["wordpress_detected"] = True

    return result


def _fallback_http_probe(base_url: str, timeout: int) -> dict:
    """Fallback: HTTP-based WordPress detection when wpscan is unavailable."""
    result = {
        "wordpress_detected": False,
        "version": "",
        "vulnerabilities": [],
        "users": [],
    }

    session = requests.Session()
    session.verify = False
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; VulnTrace/1.0)",
    })

    # Remove trailing slash for consistency
    base_url = base_url.rstrip("/")

    # Check 1: /wp-login.php
    try:
        resp = session.get(f"{base_url}/wp-login.php", timeout=timeout, allow_redirects=True)
        if resp.status_code == 200 and ("wp-login" in resp.text.lower() or "wordpress" in resp.text.lower()):
            result["wordpress_detected"] = True
    except requests.RequestException:
        pass

    # Check 2: /wp-admin/ redirect
    if not result["wordpress_detected"]:
        try:
            resp = session.get(f"{base_url}/wp-admin/", timeout=timeout, allow_redirects=False)
            if resp.status_code in (301, 302) and "wp-login" in resp.headers.get("Location", "").lower():
                result["wordpress_detected"] = True
        except requests.RequestException:
            pass

    # Check 3: Homepage meta generator
    if not result["wordpress_detected"]:
        try:
            resp = session.get(base_url, timeout=timeout)
            if "wp-content" in resp.text.lower() or "wordpress" in resp.text.lower():
                result["wordpress_detected"] = True
            # Try to extract version from meta generator
            m = re.search(
                r'<meta\s+name="generator"\s+content="WordPress\s+([^"]+)"',
                resp.text,
                re.IGNORECASE,
            )
            if m:
                result["wordpress_detected"] = True
                result["version"] = m.group(1)
        except requests.RequestException:
            pass

    # Check 4: /readme.html for version
    if result["wordpress_detected"] and not result["version"]:
        try:
            resp = session.get(f"{base_url}/readme.html", timeout=timeout)
            m = re.search(r"Version\s+([\d.]+)", resp.text, re.IGNORECASE)
            if m:
                result["version"] = m.group(1)
        except requests.RequestException:
            pass

    # Check 5: Response headers
    if not result["wordpress_detected"]:
        try:
            resp = session.head(base_url, timeout=timeout, allow_redirects=True)
            for key, value in resp.headers.items():
                if "wordpress" in str(value).lower() or "wp-" in str(value).lower():
                    result["wordpress_detected"] = True
                    break
            # X-Powered-By
            powered = resp.headers.get("X-Powered-By", "")
            if "wordpress" in powered.lower():
                result["wordpress_detected"] = True
        except requests.RequestException:
            pass

    # Check 6: Common plugin paths
    if result["wordpress_detected"]:
        detected_plugins: list[str] = []
        for plugin_path in COMMON_PLUGIN_PATHS[:10]:  # limit to first 10
            try:
                resp = session.head(f"{base_url}/{plugin_path}", timeout=timeout, allow_redirects=True)
                if resp.status_code in (200, 301, 302, 403):
                    plugin_name = plugin_path.split("/")[2]  # wp-content/plugins/{name}/
                    detected_plugins.append(plugin_name)
            except requests.RequestException:
                pass
        if detected_plugins:
            result["vulnerabilities"].append({
                "id": "http_fallback",
                "title": f"Detected plugins via HTTP: {', '.join(detected_plugins)}",
                "fixed_in": "",
            })

    return result


def execute(params: WpscanProbeInput, context: ToolContext) -> ToolExecutionResult:
    base_url = params.target.rstrip("/")

    if _check_wpscan_available():
        try:
            stdout, stderr, rc = _run_wpscan(base_url, params.timeout, context.max_output_chars)
            structured = _parse_wpscan_json(stdout)
        except ToolExecutionError:
            # wpscan failed; fallback to HTTP probe
            structured = _fallback_http_probe(base_url, params.timeout)
    else:
        structured = _fallback_http_probe(base_url, params.timeout)

    if structured["wordpress_detected"]:
        ver_str = f" version {structured['version']}" if structured["version"] else ""
        vuln_str = f" {len(structured['vulnerabilities'])} vuln(s)" if structured["vulnerabilities"] else ""
        user_str = f" {len(structured['users'])} user(s)" if structured["users"] else ""
        summary = (
            f"wpscan on {base_url}: WordPress detected{ver_str}.{vuln_str}{user_str}."
        )
    else:
        summary = f"wpscan on {base_url}: WordPress NOT detected."

    artifact_path = context.artifact_dir / "wpscan_probe.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")

    return ToolExecutionResult(
        tool_name="wpscan_probe",
        success=True,
        summary=summary,
        raw_output=json.dumps(structured, indent=2)[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
