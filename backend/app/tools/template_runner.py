from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from app.schemas.tool import TemplateRunnerInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError, run_command


def execute(params: TemplateRunnerInput, context: ToolContext) -> ToolExecutionResult:
    if params.template == "nikto_scan":
        return _run_nikto_template(params, context)
    if params.template == "nmap_service":
        return _run_nmap_service_template(params, context)
    raise ToolExecutionError(f"Unknown template {params.template}")


def _run_nikto_template(params: TemplateRunnerInput, context: ToolContext) -> ToolExecutionResult:
    url = f"{params.scheme}://{params.target}:{params.port}"
    args = [
        "nikto",
        "-nointeractive",
        "-ask",
        "no",
        "-host",
        url,
        "-maxtime",
        f"{min(params.timeout, 20)}s",
        "-timeout",
        "5",
        "-Tuning",
        "b,e",
    ]
    stdout, stderr, return_code = run_command(args, timeout=params.timeout + 20, max_output_chars=20000)
    if return_code not in {0, 1}:
        raise ToolExecutionError(stderr or stdout or "Nikto template execution failed.")

    issues = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("+ ") and "Nikto v" not in stripped:
            issues.append(stripped[2:])

    structured = {
        "template": params.template,
        "target": url,
        "issues": issues,
        "raw": stdout,
    }
    artifact_path = context.artifact_dir / "template_runner_nikto.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    return ToolExecutionResult(
        tool_name="template_runner",
        success=True,
        summary=f"Nikto template collected {len(issues)} observation(s).",
        raw_output=stdout,
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )


def _run_nmap_service_template(params: TemplateRunnerInput, context: ToolContext) -> ToolExecutionResult:
    args = ["nmap", "-sV", "-Pn", "-n", "-p", str(params.port), "-oX", "-", params.target]
    stdout, stderr, return_code = run_command(args, timeout=params.timeout, max_output_chars=20000)
    if return_code != 0:
        raise ToolExecutionError(stderr or stdout or "nmap service template failed.")

    root = ET.fromstring(stdout)
    services = []
    for host in root.findall("host"):
        for port_el in host.findall("./ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.attrib.get("state") != "open":
                continue
            service_el = port_el.find("service")
            services.append(
                {
                    "port": int(port_el.attrib.get("portid", "0")),
                    "protocol": port_el.attrib.get("protocol", "tcp"),
                    "service": service_el.attrib.get("name", "unknown") if service_el is not None else "unknown",
                    "product": service_el.attrib.get("product", "") if service_el is not None else "",
                    "version": service_el.attrib.get("version", "") if service_el is not None else "",
                }
            )

    structured = {"template": params.template, "target": params.target, "services": services, "raw": stdout}
    artifact_path = context.artifact_dir / "template_runner_nmap.json"
    artifact_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    return ToolExecutionResult(
        tool_name="template_runner",
        success=True,
        summary=f"nmap service template identified {len(services)} service(s).",
        raw_output=stdout,
        structured_data=structured,
        artifact_paths=[str(artifact_path)],
    )
