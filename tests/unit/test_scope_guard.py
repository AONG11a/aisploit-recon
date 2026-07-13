"""Unit tests for the fail-closed scope guard — the core safety control."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aisploit_recon.config.scope import AuthorizationProof, ScopeConfig, ScopeRule
from aisploit_recon.core.scope_guard import ScopeGuard, ScopeViolation


def _proof(expires: datetime | None = None) -> AuthorizationProof:
    return AuthorizationProof(
        program="internal:test",
        scope_reference="https://example.com/scope",
        authorized_by="tester",
        authorized_at=datetime.now(UTC),
        expires_at=expires,
    )


def _guard(**rule_kwargs: object) -> ScopeGuard:
    rules = ScopeRule(allowed_hosts=["chat.example.com"], **rule_kwargs)  # type: ignore[arg-type]
    return ScopeGuard(ScopeConfig(proof=_proof(), rules=rules))


def test_allows_in_scope_host() -> None:
    _guard().assert_in_scope("https://chat.example.com/api/chat")


def test_blocks_out_of_scope_host() -> None:
    with pytest.raises(ScopeViolation):
        _guard().assert_in_scope("https://evil.example.org/chat")


def test_blocks_non_http_scheme() -> None:
    with pytest.raises(ScopeViolation):
        _guard().assert_in_scope("file:///etc/passwd")


def test_denied_path_blocks() -> None:
    with pytest.raises(ScopeViolation):
        _guard(denied_paths=["/admin/*"]).assert_in_scope("https://chat.example.com/admin/x")


def test_expired_authorization_refuses_at_construction() -> None:
    expired = datetime.now(UTC) - timedelta(days=1)
    rules = ScopeRule(allowed_hosts=["chat.example.com"])
    with pytest.raises(ScopeViolation):
        ScopeGuard(ScopeConfig(proof=_proof(expires=expired), rules=rules))


def test_dangerous_wildcard_host_rejected_by_validation() -> None:
    with pytest.raises(ValueError):
        ScopeRule(allowed_hosts=["*"])


def test_bare_tld_wildcard_rejected() -> None:
    with pytest.raises(ValueError):
        ScopeRule(allowed_hosts=["*.com"])
