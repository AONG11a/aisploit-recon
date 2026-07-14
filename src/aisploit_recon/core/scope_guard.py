"""Fail-closed authorization gate.

Every probe target passes through ``assert_in_scope`` before a single byte is
sent. The rule is deny-by-default: if anything is ambiguous or a check can't be
satisfied, the request is blocked. This protects the operator from their own
typos and is the artifact that demonstrates good-faith, in-scope testing.

This is enforcement, not decoration: the scheduler calls it and will not run a
campaign if it raises.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from datetime import UTC, datetime
from urllib.parse import urlparse

from aisploit_recon.config.scope import ScopeConfig
from aisploit_recon.utils.logging import get_logger

log = get_logger(__name__)


class ScopeViolation(Exception):
    """Raised when a target is not provably within authorized scope."""


# Named cloud/link-local metadata endpoints that must never be probed unless the
# operator explicitly opts into private-destination testing.
_METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata", "instance-data"})


def _is_private_destination(host: str) -> bool:
    """True if *host* is a loopback / link-local / private / metadata destination.

    Only IP literals and known metadata FQDNs are classified here; hostnames are
    not actively resolved — that is a documented follow-up (see docs/DESIGN.md D9)
    so the guard stays fast and free of DNS-timeout side effects.
    """
    h = host.strip("[]").lower()
    if h == "localhost" or h.endswith(".localhost") or h in _METADATA_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


class ScopeGuard:
    def __init__(self, config: ScopeConfig) -> None:
        self._cfg = config
        self._check_authorization_window()

    def _check_authorization_window(self) -> None:
        exp = self._cfg.proof.expires_at
        if exp is not None and datetime.now(UTC) > exp:
            raise ScopeViolation(
                f"Authorization expired at {exp.isoformat()}. "
                "Re-confirm scope before continuing."
            )

    def assert_in_scope(self, target_url: str) -> None:
        parsed = urlparse(target_url)

        # Only http(s) targets are in scope; reject file://, data:, etc.
        if parsed.scheme not in ("http", "https"):
            raise ScopeViolation(f"Unsupported scheme in target: {parsed.scheme!r}")

        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"

        if not host:
            raise ScopeViolation("Target URL has no host")

        rules = self._cfg.rules

        # 1) Host must match an allowed pattern.
        if not any(fnmatch.fnmatch(host, pat.lower()) for pat in rules.allowed_hosts):
            log.warning("scope.block", reason="host", host=host, target=target_url)
            raise ScopeViolation(
                f"Host {host!r} is not in authorized scope. "
                f"Allowed: {rules.allowed_hosts}"
            )

        # 1b) Destination-sensitivity guard (SSRF): refuse loopback / link-local
        # / RFC-1918 / cloud-metadata targets unless explicitly authorized.
        if not rules.allow_private_destinations and _is_private_destination(host):
            log.warning("scope.block", reason="private_destination", host=host)
            raise ScopeViolation(
                f"Host {host!r} is a private/loopback/metadata destination. "
                "Set allow_private_destinations: true in scope only for "
                "authorized internal testing."
            )

        # 2) Path must not match any denied pattern.
        for denied in rules.denied_paths:
            if fnmatch.fnmatch(path, denied):
                log.warning("scope.block", reason="path_denied", path=path)
                raise ScopeViolation(f"Path {path!r} is explicitly denied")

        # 3) Path must match an allowed pattern.
        if not any(fnmatch.fnmatch(path, pat) for pat in rules.allowed_paths):
            log.warning("scope.block", reason="path", path=path)
            raise ScopeViolation(f"Path {path!r} is not in allowed paths")

        # 4) Optional testing-window enforcement.
        if rules.allowed_hours_utc is not None:
            start, end = rules.allowed_hours_utc
            hour = datetime.now(UTC).hour
            if not (start <= hour < end):
                raise ScopeViolation(
                    f"Outside allowed testing window {start:02d}:00-{end:02d}:00 UTC "
                    f"(now {hour:02d}:00 UTC)"
                )

        log.info("scope.allow", target=target_url, host=host)
