from __future__ import annotations

from app.core.risk_policy import RiskTolerance, RiskPolicy, RiskLevel, get_policy, POLICIES


# ── Tolerance-based approval ──────────────────────────────────────────────────

def test_strict_tolerance_requires_approval_for_medium():
    """Under STRICT tolerance, medium-risk tools like dir_enum need approval."""
    policy = get_policy("dir_enum", tolerance=RiskTolerance.STRICT)
    assert policy.approval_required
    assert policy.risk_level == RiskLevel.MEDIUM


def test_relaxed_tolerance_bypasses_medium():
    """Under RELAXED tolerance, only HIGH/CRITICAL tools need approval.
    Medium tools like dir_enum should bypass."""
    policy = get_policy("dir_enum", tolerance=RiskTolerance.RELAXED)
    assert not policy.approval_required


def test_none_tolerance_bypasses_all():
    """Under NONE tolerance, even HIGH tools like vuln_verify should bypass."""
    policy = get_policy("vuln_verify", tolerance=RiskTolerance.NONE)
    assert not policy.approval_required


# ── Additional risk-policy tests ──────────────────────────────────────────────

def test_default_tolerance_is_moderate():
    """get_policy without a tolerance should use MODERATE."""
    policy = get_policy("vuln_verify")
    assert policy.approval_required  # HIGH, gated under MODERATE
    assert policy.risk_level == RiskLevel.HIGH


def test_low_tools_never_require_approval():
    """Low-risk tools should never require approval regardless of tolerance."""
    for tolerance in RiskTolerance:
        policy = get_policy("asset_discovery", tolerance=tolerance)
        assert not policy.approval_required


def test_high_tool_requires_approval_under_moderate():
    """High-risk tools require approval under MODERATE tolerance."""
    policy = get_policy("tcp_send", tolerance=RiskTolerance.MODERATE)
    assert policy.approval_required


def test_high_tool_bypasses_under_relaxed():
    """High-risk tools should NOT require approval under RELAXED tolerance."""
    policy = get_policy("tcp_send", tolerance=RiskTolerance.RELAXED)
    assert not policy.approval_required


def test_unknown_tool_raises_keyerror():
    """Requesting a policy for an unknown tool raises KeyError."""
    import pytest
    with pytest.raises(KeyError):
        get_policy("nonexistent_tool")


def test_all_policies_have_valid_enums():
    """Every tool in POLICIES should have a valid RiskLevel value."""
    for name, policy in POLICIES.items():
        assert policy.risk_level in RiskLevel
        assert isinstance(policy.tool_name, str)
        assert len(policy.description) > 0


def test_new_tool_policies_exist():
    """The recently-added tools should each have a policy entry."""
    expected_tools = [
        "ssh_version",
        "ftp_anon",
        "smb_enum",
        "redis_check",
        "mongodb_check",
        "sqli_probe",
        "default_creds",
    ]
    for name in expected_tools:
        assert name in POLICIES
        assert isinstance(POLICIES[name], RiskPolicy)
