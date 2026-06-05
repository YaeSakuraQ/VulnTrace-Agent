from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from app.schemas.tool import ServiceFingerprintInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError, run_command


def execute(params: ServiceFingerprintInput, context: ToolContext) -> ToolExecutionResult:
    args = ["nmap", "-sV", "-Pn", "-n", "--version-light", "-oX", "-", params.target]
    if params.port_spec:
        args[1:1] = ["-p", params.port_spec]

    stdout, stderr, return_code = run_command(
        args,
        timeout=params.timeout,
        max_output_chars=context.max_output_chars,
    )
    if return_code != 0:
        raise ToolExecutionError(stderr or stdout or "nmap service fingerprint failed.")

    root = ET.fromstring(stdout)
    services: list[dict[str, str | int]] = []
    for host in root.findall("host"):
        address_el = host.find("address")
        target = address_el.attrib.get("addr", params.target) if address_el is not None else params.target
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.attrib.get("state") != "open":
                continue
            service_el = port_el.find("service")
            name = service_el.attrib.get("name", "unknown") if service_el is not None else "unknown"
            product = service_el.attrib.get("product", "") if service_el is not None else ""
            version = service_el.attrib.get("version", "") if service_el is not None else ""
            services.append(
                {
                    "target": target,
                    "port": int(port_el.attrib.get("portid", "0")),
                    "protocol": port_el.attrib.get("protocol", "tcp"),
                    "service": name,
                    "product": product,
                    "version": version,
                    "source": "nmap",
                }
            )

    artifact_path = context.artifact_dir / "service_fingerprint.json"
    artifact_path.write_text(
        json.dumps({"command": args, "services": services, "xml": stdout}, indent=2),
        encoding="utf-8",
    )

    summary = f"Identified {len(services)} open service(s) on {params.target}."
    return ToolExecutionResult(
        tool_name="service_fingerprint",
        success=True,
        summary=summary,
        raw_output=stdout,
        structured_data={"services": services},
        artifact_paths=[str(artifact_path)],
    )
