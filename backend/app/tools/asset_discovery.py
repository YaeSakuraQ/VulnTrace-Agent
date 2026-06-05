from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from app.schemas.tool import AssetDiscoveryInput, ToolExecutionResult
from app.tools.base import ToolContext, ToolExecutionError, run_command


def execute(params: AssetDiscoveryInput, context: ToolContext) -> ToolExecutionResult:
    args = ["nmap", "-sn", "-n", "-oX", "-"] + params.targets
    stdout, stderr, return_code = run_command(
        args,
        timeout=params.timeout,
        max_output_chars=context.max_output_chars,
    )
    if return_code != 0:
        raise ToolExecutionError(stderr or stdout or "nmap host discovery failed.")

    root = ET.fromstring(stdout)
    hosts: list[dict[str, str]] = []
    for host in root.findall("host"):
        status_el = host.find("status")
        address_el = host.find("address")
        if status_el is None or address_el is None:
            continue
        if status_el.attrib.get("state") != "up":
            continue
        hosts.append(
            {
                "address": address_el.attrib.get("addr", ""),
                "status": "up",
                "source": "nmap",
            }
        )

    artifact_path = context.artifact_dir / "asset_discovery.json"
    artifact_path.write_text(
        json.dumps({"command": args, "hosts": hosts, "xml": stdout}, indent=2),
        encoding="utf-8",
    )

    summary = f"Discovered {len(hosts)} live host(s) inside the approved scope."
    return ToolExecutionResult(
        tool_name="asset_discovery",
        success=True,
        summary=summary,
        raw_output=stdout,
        structured_data={"hosts": hosts},
        artifact_paths=[str(artifact_path)],
    )
