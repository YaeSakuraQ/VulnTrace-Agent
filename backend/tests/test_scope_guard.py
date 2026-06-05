from __future__ import annotations

import pytest

from app.core.scope_guard import ScopeGuard, ScopeValidationError


def test_private_scope_is_allowed() -> None:
    guard = ScopeGuard()
    normalized = guard.validate_scope(["192.168.56.0/24", "127.0.0.1"])
    assert normalized == ["192.168.56.0/24", "127.0.0.1"]


def test_public_scope_is_rejected_by_default() -> None:
    guard = ScopeGuard()
    with pytest.raises(ScopeValidationError):
        guard.validate_scope(["8.8.8.8"])


def test_target_must_be_inside_scope() -> None:
    guard = ScopeGuard()
    guard.ensure_target_allowed("192.168.56.10", ["192.168.56.0/24"])
    with pytest.raises(ScopeValidationError):
        guard.ensure_target_allowed("192.168.57.10", ["192.168.56.0/24"])
