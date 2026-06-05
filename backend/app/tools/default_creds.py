from __future__ import annotations

import json

import requests

from app.schemas.tool import DefaultCredsInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError


# Target paths to probe for login forms
LOGIN_PATHS = [
    "/admin",
    "/login",
    "/phpmyadmin",
    "/wp-admin",
    "/wp-login.php",
    "/manager/html",
]

# Common default credential pairs
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("admin", "admin1234"),
    ("root", "root"),
    ("root", "password"),
    ("root", "toor"),
    ("root", "123456"),
    ("user", "user"),
    ("user", "password"),
    ("guest", "guest"),
    ("test", "test"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("admin", ""),
    ("root", ""),
    ("admin", "pass"),
    ("admin", "pass123"),
    ("admin", "p@ssword"),
]


# Heuristic success indicators in response
SUCCESS_INDICATORS = [
    "welcome",
    "dashboard",
    "logout",
    "sign out",
    "signout",
    "my account",
    "logged in",
    "successfully logged",
    "login successful",
    "session",
    "set-cookie",
]


def _try_login(
    session: requests.Session,
    base_url: str,
    path: str,
    username: str,
    password: str,
    timeout: int,
) -> dict:
    """Attempt login with given credentials on a path and return result."""
    url = f"{base_url}{path}"
    result = {
        "url": url,
        "username": username,
        "password": password,
        "success": False,
        "indicator": "",
    }

    try:
        # Common login POST data patterns
        data_variants = [
            {"username": username, "password": password},
            {"user": username, "pass": password},
            {"log": username, "pwd": password},
            {"login": username, "password": password},
            {"email": username, "password": password},
            {"name": username, "passwd": password},
        ]

        for data in data_variants:
            try:
                resp = session.post(
                    url,
                    data=data,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=False,
                )
            except requests.RequestException:
                continue

            body_lower = resp.text.lower()
            cookies = {k.lower(): v for k, v in resp.cookies.items()}

            # Check success indicators
            for indicator in SUCCESS_INDICATORS:
                if indicator in body_lower and resp.status_code < 400:
                    result["success"] = True
                    result["indicator"] = f"body contains '{indicator}'"
                    return result

            # Check for session cookies being set
            session_cookie_names = {"session", "sessionid", "token", "auth", "login", "sid", "jsessionid", "phpsessid"}
            for name in session_cookie_names:
                if name in cookies or name in {k.lower() for k in dict(resp.headers).get("set-cookie", "").lower()}:
                    result["success"] = True
                    result["indicator"] = f"session cookie set ({name})"
                    return result

            # Check HTTP status redirect (302/303) could indicate successful login
            if resp.status_code in (302, 303) and resp.headers.get("location", "").lower() not in (
                "", "/", f"{path}", f"{path}/", f"{path}?error", "/login", "/admin/login",
            ):
                result["success"] = True
                result["indicator"] = f"redirect to {resp.headers.get('location', '')}"
                return result

    except Exception as exc:
        result["indicator"] = f"error: {exc}"

    return result


def execute(params: DefaultCredsInput, context: ToolContext) -> ToolExecutionResult:
    base_url = f"{params.scheme}://{params.target}:{params.port}"
    attempts: list[dict] = []

    with requests.Session() as session:
        session.verify = False

        # First, probe which paths return a non-error response
        reachable_paths: list[str] = []
        for path in LOGIN_PATHS:
            try:
                resp = session.get(
                    f"{base_url}{path}",
                    timeout=params.timeout,
                    allow_redirects=True,
                    verify=False,
                )
                if resp.status_code < 500:
                    reachable_paths.append(path)
            except requests.RequestException:
                continue

        if not reachable_paths:
            reachable_paths = ["/"]  # fallback to root

        # Try credentials on each reachable path
        for path in reachable_paths[:3]:  # Limit to top 3 paths to bound intensity
            for username, password in DEFAULT_CREDENTIALS[:10]:  # Limit credentials per path
                result = _try_login(
                    session, base_url, path, username, password, params.timeout
                )
                attempts.append(result)
                if result["success"]:
                    break  # Found working creds for this path, move on

    successes = [a for a in attempts if a["success"]]
    if successes:
        summary = (
            f"Default credential probe on {base_url}: "
            f"{len(successes)} successful login(s) out of {len(attempts)} attempts. "
            + "; ".join(
                f"{s['username']}:{s['password']}@{s['url']}"
                for s in successes[:5]
            )
        )
    else:
        summary = (
            f"Default credential probe on {base_url}: "
            f"no successful logins in {len(attempts)} attempts across {len(reachable_paths[:3])} path(s)."
        )

    structured: dict = {"attempts": attempts}

    artifact_path = context.artifact_dir / "default_creds.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")

    return ToolExecutionResult(
        tool_name="default_creds",
        success=True,
        summary=summary,
        raw_output=json.dumps(structured, indent=2)[: context.max_output_chars],
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
