from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class RiskTolerance(str, Enum):
    """Runtime risk tolerance that controls which tools require human approval."""

    STRICT = "strict"       # All high + medium tools need approval
    MODERATE = "moderate"   # Only high tools need approval (default)
    RELAXED = "relaxed"     # Only critical tools need approval
    NONE = "none"           # Fully automatic, no approval gate


class RiskLevel(str, Enum):
    """Intrinsic risk rating of an individual tool."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class RiskPolicy:
    tool_name: str
    risk_level: RiskLevel
    tolerance_levels: frozenset[RiskTolerance] = field(default_factory=frozenset)
    approval_required: bool = False
    description: str = ""


# ── Policy definitions ──────────────────────────────────────────────────────
# tolerance_levels encodes the set of tolerance settings under which this
# tool MUST go through the approval gate.  The default tolerance is MODERATE.
#
# Pattern:
#   LOW      → frozenset()                                      (never gated)
#   MEDIUM   → frozenset({STRICT})                              (gated only under STRICT)
#   HIGH     → frozenset({STRICT, MODERATE})                    (gated under STRICT+MODERATE)
#   CRITICAL → frozenset({STRICT, MODERATE, RELAXED})           (gated unless NONE)

POLICIES: dict[str, RiskPolicy] = {
    "asset_discovery": RiskPolicy(
        tool_name="asset_discovery",
        risk_level=RiskLevel.LOW,
        tolerance_levels=frozenset(),
        description="Low-intensity host discovery inside the approved lab scope.",
    ),
    "service_fingerprint": RiskPolicy(
        tool_name="service_fingerprint",
        risk_level=RiskLevel.LOW,
        tolerance_levels=frozenset(),
        description="Version detection on discovered ports with bounded scan intensity.",
    ),
    "web_probe": RiskPolicy(
        tool_name="web_probe",
        risk_level=RiskLevel.LOW,
        tolerance_levels=frozenset(),
        description="Safe HTTP probing for titles, headers, and common entry points.",
    ),
    "dir_enum": RiskPolicy(
        tool_name="dir_enum",
        risk_level=RiskLevel.MEDIUM,
        tolerance_levels=frozenset({RiskTolerance.STRICT}),
        description="Rate-limited directory enumeration with a fixed small path set.",
    ),
    "ffuf_enum": RiskPolicy(
        tool_name="ffuf_enum",
        risk_level=RiskLevel.MEDIUM,
        tolerance_levels=frozenset({RiskTolerance.STRICT}),
        description="Bounded ffuf content discovery using a tiny curated wordlist and low request rate.",
    ),
    "http_snapshot": RiskPolicy(
        tool_name="http_snapshot",
        risk_level=RiskLevel.LOW,
        tolerance_levels=frozenset(),
        description="Capture short HTTP body snippets and key headers for already discovered paths.",
    ),
    "http_get": RiskPolicy(
        tool_name="http_get",
        risk_level=RiskLevel.LOW,
        tolerance_levels=frozenset(),
        description="Structured HTTP request primitive for targeted observation.",
    ),
    "http_request": RiskPolicy(
        tool_name="http_request",
        risk_level=RiskLevel.MEDIUM,
        tolerance_levels=frozenset({RiskTolerance.STRICT}),
        description="Structured standard HTTP request primitive for bounded API and RPC capability checks.",
    ),
    "header_mutation": RiskPolicy(
        tool_name="header_mutation",
        risk_level=RiskLevel.MEDIUM,
        tolerance_levels=frozenset({RiskTolerance.STRICT}),
        description="Structured HTTP exploit primitive with explicit header control.",
    ),
    "raw_http": RiskPolicy(
        tool_name="raw_http",
        risk_level=RiskLevel.MEDIUM,
        tolerance_levels=frozenset({RiskTolerance.STRICT}),
        description="Raw HTTP request primitive for exploit reproduction and protocol edge cases.",
    ),
    "tcp_send": RiskPolicy(
        tool_name="tcp_send",
        risk_level=RiskLevel.HIGH,
        tolerance_levels=frozenset({RiskTolerance.STRICT, RiskTolerance.MODERATE}),
        description="Low-level TCP payload primitive for manual protocol interaction.",
    ),
    "template_runner": RiskPolicy(
        tool_name="template_runner",
        risk_level=RiskLevel.MEDIUM,
        tolerance_levels=frozenset({RiskTolerance.STRICT}),
        description="Run a bounded scanner template such as Nikto or nmap service checks.",
    ),
    "vuln_verify": RiskPolicy(
        tool_name="vuln_verify",
        risk_level=RiskLevel.HIGH,
        tolerance_levels=frozenset({RiskTolerance.STRICT, RiskTolerance.MODERATE}),
        description="Controlled verification using Nikto against the local web target.",
    ),
    "report_tool": RiskPolicy(
        tool_name="report_tool",
        risk_level=RiskLevel.LOW,
        tolerance_levels=frozenset(),
        description="Local report generation with no network side effects.",
    ),
    "ssh_version": RiskPolicy(
        tool_name="ssh_version",
        risk_level=RiskLevel.LOW,
        tolerance_levels=frozenset(),
        description="SSH version fingerprinting via banner grab and ssh -v.",
    ),
    "ftp_anon": RiskPolicy(
        tool_name="ftp_anon",
        risk_level=RiskLevel.LOW,
        tolerance_levels=frozenset(),
        description="Anonymous FTP login check against a bounded credential set.",
    ),
    "smb_enum": RiskPolicy(
        tool_name="smb_enum",
        risk_level=RiskLevel.MEDIUM,
        tolerance_levels=frozenset({RiskTolerance.STRICT}),
        description="SMB share enumeration and version detection via negotiate protocol.",
    ),
    "redis_check": RiskPolicy(
        tool_name="redis_check",
        risk_level=RiskLevel.MEDIUM,
        tolerance_levels=frozenset({RiskTolerance.STRICT}),
        description="Redis unauthorized access check using PING / INFO / CONFIG GET.",
    ),
    "mongodb_check": RiskPolicy(
        tool_name="mongodb_check",
        risk_level=RiskLevel.MEDIUM,
        tolerance_levels=frozenset({RiskTolerance.STRICT}),
        description="MongoDB unauthorized access check using ismaster wire protocol.",
    ),
    "sqli_probe": RiskPolicy(
        tool_name="sqli_probe",
        risk_level=RiskLevel.HIGH,
        tolerance_levels=frozenset({RiskTolerance.STRICT, RiskTolerance.MODERATE}),
        description="Structured SQL injection probing with bounded payload set.",
    ),
    "default_creds": RiskPolicy(
        tool_name="default_creds",
        risk_level=RiskLevel.HIGH,
        tolerance_levels=frozenset({RiskTolerance.STRICT, RiskTolerance.MODERATE}),
        description="Default credential check against known service account lists.",
    ),
}


def get_policy(
    tool_name: str, tolerance: RiskTolerance = RiskTolerance.MODERATE
) -> RiskPolicy:
    """Return the RiskPolicy for *tool_name*, computing ``approval_required``
    from the provided *tolerance* level.

    Raises :class:`KeyError` when the tool name is unknown.
    """
    if tool_name not in POLICIES:
        raise KeyError(f"Unknown tool policy: {tool_name}")
    base = POLICIES[tool_name]
    return RiskPolicy(
        tool_name=base.tool_name,
        risk_level=base.risk_level,
        tolerance_levels=base.tolerance_levels,
        approval_required=tolerance in base.tolerance_levels,
        description=base.description,
    )
