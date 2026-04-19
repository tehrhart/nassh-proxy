"""Target-host allow/deny policy for /v4/connect.

Resolves the requested host, then asserts every resolved IP passes policy.
Callers should connect to the returned IP — re-resolving the hostname at
dial time re-opens a DNS-rebinding window.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Iterable

# Always blocked regardless of allowlist. Covers loopback, link-local (incl.
# AWS/GCE metadata at 169.254.169.254), multicast, reserved, the IPv4 "this
# host" block, and IPv6 analogues. Operators who genuinely need one of these
# can remove the default by forking; we will not provide a flag.
BUILTIN_DENY_V4 = [
    "0.0.0.0/8",       # "this host" / current network
    "127.0.0.0/8",     # loopback
    "169.254.0.0/16",  # link-local incl. cloud metadata
    "224.0.0.0/4",     # multicast
    "240.0.0.0/4",     # reserved
    "255.255.255.255/32",
]
BUILTIN_DENY_V6 = [
    "::1/128",         # loopback
    "fe80::/10",       # link-local
    "fc00::/7",        # unique local (private IPv6)
    "ff00::/8",        # multicast
    "::/128",          # unspecified
]


class TargetDenied(Exception):
    """Raised when the target is blocked by policy."""


@dataclass(frozen=True)
class ResolvedTarget:
    host: str            # original hostname (for logging)
    ip: str              # the IP we checked and should connect to
    port: int


class TargetPolicy:
    def __init__(
        self,
        allowlist_cidrs: Iterable[str] | None = None,
        extra_deny_cidrs: Iterable[str] | None = None,
        unsafe_allow_loopback: bool = False,
    ):
        self._allow = [ip_network(c, strict=False) for c in (allowlist_cidrs or [])]
        builtin = BUILTIN_DENY_V4 + BUILTIN_DENY_V6
        if unsafe_allow_loopback:
            builtin = [c for c in builtin if c not in ("127.0.0.0/8", "::1/128")]
        self._deny = [ip_network(c, strict=False) for c in builtin + list(extra_deny_cidrs or [])]

    async def resolve_and_check(self, host: str, port: int) -> ResolvedTarget:
        loop = asyncio.get_running_loop()
        try:
            addrinfos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise TargetDenied(f"cannot resolve {host!r}: {e}") from e

        if not addrinfos:
            raise TargetDenied(f"no addresses for {host!r}")

        # Check every resolved IP. If any is denied, fail closed — a host with
        # mixed good/bad records is still a deny. Return the first non-denied.
        first_allowed: str | None = None
        for _family, _sock_type, _proto, _canon, sockaddr in addrinfos:
            ip_str = sockaddr[0]
            ip = ip_address(ip_str)
            if any(ip in net for net in self._deny):
                raise TargetDenied(f"{host} resolves to blocked address {ip}")
            if self._allow and not any(ip in net for net in self._allow):
                raise TargetDenied(f"{host} resolves to {ip} not in allowlist")
            if first_allowed is None:
                first_allowed = ip_str

        assert first_allowed is not None
        return ResolvedTarget(host=host, ip=first_allowed, port=port)
