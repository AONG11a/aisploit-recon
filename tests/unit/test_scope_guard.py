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


def _guard_hosts(hosts: list[str], **rule_kwargs: object) -> ScopeGuard:
    rules = ScopeRule(allowed_hosts=hosts, **rule_kwargs)  # type: ignore[arg-type]
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


# --- D9: SSRF / private-range destination guard -----------------------------


def test_blocks_loopback_destination() -> None:
    with pytest.raises(ScopeViolation):
        _guard_hosts(["127.0.0.1"]).assert_in_scope("http://127.0.0.1/api/chat")


def test_blocks_rfc1918_destination() -> None:
    with pytest.raises(ScopeViolation):
        _guard_hosts(["10.0.0.5"]).assert_in_scope("http://10.0.0.5/api/chat")


def test_blocks_cloud_metadata_ip() -> None:
    with pytest.raises(ScopeViolation):
        _guard_hosts(["169.254.169.254"]).assert_in_scope(
            "http://169.254.169.254/latest/meta-data/"
        )


def test_blocks_metadata_fqdn() -> None:
    with pytest.raises(ScopeViolation):
        _guard_hosts(["metadata.google.internal"]).assert_in_scope(
            "http://metadata.google.internal/"
        )


def test_allows_private_destination_when_opted_in() -> None:
    _guard_hosts(["127.0.0.1"], allow_private_destinations=True).assert_in_scope(
        "http://127.0.0.1/api/chat"
    )


def test_allows_public_ip_destination() -> None:
    _guard_hosts(["8.8.8.8"]).assert_in_scope("http://8.8.8.8/api/chat")
