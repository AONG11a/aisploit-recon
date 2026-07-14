"""SSRF destination guard.

Blocks probes whose *target URL* resolves to a non-routable / sensitive
destination: cloud-metadata endpoints (169.254.169.254), loopback, link-local,
and RFC-1918 private ranges. This prevents an attacker-controlled target URL
from turning the scanner into an SSRF proxy — e.g. pointing it at AWS metadata
to exfiltrate instance credentials.

For legitimate internal testing (scanning a staging instance on a private
network), the operator can set ``allow_private_destinations=True`` in the scope
config. The override is logged at WARNING so it shows up in evidence.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from aisploit_recon.utils.logging import get_logger

log = get_logger(__name__)

# Cloud-metadata IPs / hostnames that must NEVER be probed.
_METADATA_HOSTS: frozenset[str] = frozenset({
    "169.254.169.254",  # AWS / Azure / GCP metadata
    "169.254.169.253",
    "100.100.100.200",  # Alibaba Cloud metadata
    "metadata.google.internal",  # GCP metadata (DNS name)
    "metadata.azure.com",  # Azure metadata (DNS name)
})


class SSRFViolation(Exception):
    """Raised when a target resolves to a blocked destination."""


def check_destination(target_url: str, *, allow_private: bool = False) -> None:
    """Resolve the URL host and reject loopback / private / metadata targets.

    Parameters
    ----------
    target_url
        The full URL the scanner is about to send a probe to.
    allow_private
        When True, private/loopback/link-local addresses are permitted
        (for authorized internal testing). Metadata endpoints are ALWAYS
        blocked regardless of this flag.
    """
    parsed = urlparse(target_url)
    host = (parsed.hostname or "").lower()

    if not host:
        raise SSRFViolation("SSRF guard: target URL has no hostname")

    # 1) Block known metadata hosts by name (before DNS resolution, to catch
    #    the DNS aliases that cloud providers set up).
    if host in _METADATA_HOSTS:
        raise SSRFViolation(
            f"SSRF guard: target host {host!r} is a cloud-metadata endpoint — "
            "probing it is always blocked."
        )

    # 2) If the host is a literal IP, check it directly.
    # 3) Otherwise resolve it and check ALL resolved addresses (mitigate DNS
    #    rebinding where the first lookup returns a public IP and the second
    #    returns 127.0.0.1).
    addrs: list[str] = []
    try:
        infos = socket.getaddrinfo(host, None)
        addrs = list({info[4][0] for info in infos if isinstance(info[4][0], str)})
    except socket.gaierror:
        # Can't resolve — let the transport fail naturally; not an SSRF risk.
        return

    for addr in addrs:
        ip = ipaddress.ip_address(addr)
        if str(ip) in _METADATA_HOSTS:
            raise SSRFViolation(
                f"SSRF guard: {host!r} resolves to metadata IP {addr} — blocked."
            )
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
            if not allow_private:
                kind = (
                    "loopback" if ip.is_loopback
                    else "private" if ip.is_private
                    else "link-local" if ip.is_link_local
                    else "reserved"
                )
                raise SSRFViolation(
                    f"SSRF guard: {host!r} resolves to {kind} address {addr}. "
                    "Set allow_private_destinations=True in scope for internal testing."
                )
            log.warning(
                "ssrf.allow_private",
                host=host,
                addr=addr,
                note="private destination permitted by scope override",
            )
