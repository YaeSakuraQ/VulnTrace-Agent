from dataclasses import dataclass


@dataclass(frozen=True)
class RiskPolicy:
    tool_name: str
    risk_level: str
    approval_required: bool
    description: str


POLICIES = {
    "asset_discovery": RiskPolicy(
        tool_name="asset_discovery",
        risk_level="low",
        approval_required=False,
        description="Low-intensity host discovery inside the approved lab scope.",
    ),
    "service_fingerprint": RiskPolicy(
        tool_name="service_fingerprint",
        risk_level="low",
        approval_required=False,
        description="Version detection on discovered ports with bounded scan intensity.",
    ),
    "web_probe": RiskPolicy(
        tool_name="web_probe",
        risk_level="low",
        approval_required=False,
        description="Safe HTTP probing for titles, headers, and common entry points.",
    ),
    "dir_enum": RiskPolicy(
        tool_name="dir_enum",
        risk_level="medium",
        approval_required=False,
        description="Rate-limited directory enumeration with a fixed small path set.",
    ),
    "ffuf_enum": RiskPolicy(
        tool_name="ffuf_enum",
        risk_level="medium",
        approval_required=False,
        description="Bounded ffuf content discovery using a tiny curated wordlist and low request rate.",
    ),
    "http_snapshot": RiskPolicy(
        tool_name="http_snapshot",
        risk_level="low",
        approval_required=False,
        description="Capture short HTTP body snippets and key headers for already discovered paths.",
    ),
    "http_get": RiskPolicy(
        tool_name="http_get",
        risk_level="low",
        approval_required=False,
        description="Structured HTTP request primitive for targeted observation.",
    ),
    "header_mutation": RiskPolicy(
        tool_name="header_mutation",
        risk_level="high",
        approval_required=True,
        description="Structured HTTP exploit primitive with explicit header control.",
    ),
    "raw_http": RiskPolicy(
        tool_name="raw_http",
        risk_level="high",
        approval_required=True,
        description="Raw HTTP request primitive for exploit reproduction and protocol edge cases.",
    ),
    "tcp_send": RiskPolicy(
        tool_name="tcp_send",
        risk_level="high",
        approval_required=True,
        description="Low-level TCP payload primitive for manual protocol interaction.",
    ),
    "template_runner": RiskPolicy(
        tool_name="template_runner",
        risk_level="medium",
        approval_required=False,
        description="Run a bounded scanner template such as Nikto or nmap service checks.",
    ),
    "vuln_verify": RiskPolicy(
        tool_name="vuln_verify",
        risk_level="high",
        approval_required=True,
        description="Controlled verification using Nikto against the local web target.",
    ),
    "report_tool": RiskPolicy(
        tool_name="report_tool",
        risk_level="low",
        approval_required=False,
        description="Local report generation with no network side effects.",
    ),
}


def get_policy(tool_name: str) -> RiskPolicy:
    if tool_name not in POLICIES:
        raise KeyError(f"Unknown tool policy: {tool_name}")
    return POLICIES[tool_name]
