"""Name resolution backed by the system resolver."""

from __future__ import annotations

import socket

from netintel.errors import TargetError


class SystemResolver:
    """Forward and reverse DNS with failures mapped to domain errors.

    Reverse lookups return ``None`` on failure rather than raising: a router
    without a PTR record is the normal case in a traceroute, not an error.
    """

    def __init__(self, *, timeout_s: float = 2.0) -> None:
        self._timeout = timeout_s

    def resolve(self, hostname: str) -> str:
        previous = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self._timeout)
        try:
            infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise TargetError(f"cannot resolve {hostname!r}: {exc.strerror}") from exc
        finally:
            socket.setdefaulttimeout(previous)

        # Prefer IPv4: the probe senders below are IPv4-only for now, and
        # silently handing them a v6 address would fail further down with a
        # much worse message.
        for family, *_rest, sockaddr in infos:
            if family == socket.AF_INET:
                return str(sockaddr[0])
        return str(infos[0][-1][0])

    def reverse(self, ip: str) -> str | None:
        previous = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self._timeout)
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return None
        finally:
            socket.setdefaulttimeout(previous)


class NullResolver:
    """Resolver that does no I/O — used when name resolution is disabled."""

    def resolve(self, hostname: str) -> str:
        raise TargetError(f"name resolution is disabled; give {hostname!r} as an IP address")

    def reverse(self, ip: str) -> str | None:
        return None
