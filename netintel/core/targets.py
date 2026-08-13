"""Parsing and validation of user-supplied targets.

The original code passed the raw contents of a text box straight to
``nmap.PortScanner().scan(hosts=...)``, which meant a typo produced a stack
trace and a string like ``127.0.0.1; rm -rf ~`` was forwarded verbatim to a
subprocess-backed library. Everything here exists so that by the time a target
reaches a backend it has been parsed into addresses this code understands.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from netintel.errors import TargetError

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

DEFAULT_MAX_HOSTS = 4096
"""Refuse to expand a range larger than this without an explicit override.

A ``/8`` is 16.7 million addresses. Expanding one by accident is how a
diagnostics tool turns into an outage — the cap makes the mistake loud."""

LOCAL_PREFIXES: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "0.0.0.0/8",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
)
"""Address space that belongs to the machine or its own LAN.

Note what is *not* here. ``ipaddress`` reports 100.64.0.0/10 (carrier-grade
NAT) and the documentation ranges as ``is_private``, so a guard built on that
predicate would quietly place a mobile carrier's customers inside the default
scanning scope. This list is the one the policy actually uses.
"""

_LOCAL_NETWORKS: tuple[IPNetwork, ...] = tuple(
    ipaddress.ip_network(prefix) for prefix in LOCAL_PREFIXES
)

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
_DASH_RANGE_RE = re.compile(r"^(?P<base>\d+\.\d+\.\d+\.)(?P<lo>\d{1,3})-(?P<hi>\d{1,3})$")


@dataclass(frozen=True, slots=True)
class TargetSpec:
    """A validated target expression and the addresses it expands to."""

    raw: str
    addresses: tuple[IPAddress, ...]

    def __len__(self) -> int:
        return len(self.addresses)

    def __iter__(self) -> Iterator[IPAddress]:
        return iter(self.addresses)

    @property
    def as_strings(self) -> tuple[str, ...]:
        return tuple(str(address) for address in self.addresses)

    @property
    def has_public(self) -> bool:
        return any(is_public(address) for address in self.addresses)


def is_public(address: IPAddress) -> bool:
    """True when an address is outside local address space.

    "Public" here means "not obviously yours" — the question the scope guard
    needs answered. Multicast and reserved blocks are excluded because they
    are not host addresses at all.
    """
    if address.is_multicast or address.is_reserved or address.is_unspecified:
        return False
    return not any(address in network for network in _LOCAL_NETWORKS)


def parse_address(text: str) -> IPAddress:
    """Parse a single IP literal, rejecting the shorthand forms.

    ``socket.inet_aton`` — used by the original geolocation tab — accepts
    ``10.1`` as ``10.0.0.1`` and ``0x7f.1`` as loopback. Silently reinterpreting
    a user's input as a different host is not a convenience.
    """
    candidate = text.strip()
    if not candidate:
        raise TargetError("empty address")
    try:
        return ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise TargetError(f"{candidate!r} is not a valid IP address") from exc


def is_hostname(text: str) -> bool:
    candidate = text.strip()
    if not candidate or _looks_like_ip(candidate):
        return False
    return bool(_HOSTNAME_RE.match(candidate))


def _looks_like_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def parse_targets(expression: str, *, max_hosts: int = DEFAULT_MAX_HOSTS) -> TargetSpec:
    """Expand a target expression into concrete addresses.

    Accepts comma- or space-separated items, each one of:

    * a single address — ``192.168.1.10``, ``2001:db8::1``
    * CIDR notation — ``192.168.1.0/24`` (network and broadcast addresses of
      an IPv4 prefix are excluded; probing them is noise at best)
    * a last-octet range — ``192.168.1.100-110``

    Hostnames are deliberately *not* accepted here: resolution is I/O, and
    parsing must stay pure so it can run on the UI thread as you type.
    """
    items = [item for item in re.split(r"[,\s]+", expression.strip()) if item]
    if not items:
        raise TargetError("no target specified")

    seen: set[IPAddress] = set()
    ordered: list[IPAddress] = []
    for item in items:
        for address in _expand_item(item):
            if address not in seen:
                seen.add(address)
                ordered.append(address)
            if len(ordered) > max_hosts:
                raise TargetError(
                    f"target expands to more than {max_hosts} addresses; "
                    "narrow the range or raise the limit explicitly"
                )
    return TargetSpec(raw=expression.strip(), addresses=tuple(ordered))


def _expand_item(item: str) -> Iterator[IPAddress]:
    dash = _DASH_RANGE_RE.match(item)
    if dash:
        yield from _expand_dash_range(dash["base"], dash["lo"], dash["hi"], item)
        return

    if "/" in item:
        yield from _expand_cidr(item)
        return

    yield parse_address(item)


def _expand_dash_range(base: str, lo_text: str, hi_text: str, item: str) -> Iterator[IPAddress]:
    lo, hi = int(lo_text), int(hi_text)
    if lo > hi:
        raise TargetError(f"{item!r}: range start is above its end")
    for octet in range(lo, hi + 1):
        try:
            yield ipaddress.IPv4Address(f"{base}{octet}")
        except ValueError as exc:
            raise TargetError(f"{item!r} is not a valid address range") from exc


def _expand_cidr(item: str) -> Iterator[IPAddress]:
    try:
        network = ipaddress.ip_network(item, strict=False)
    except ValueError as exc:
        raise TargetError(f"{item!r} is not a valid network") from exc

    if isinstance(network, ipaddress.IPv4Network) and network.prefixlen < 31:
        yield from network.hosts()
    elif network.num_addresses == 1:
        yield network.network_address
    else:
        yield from network


def summarise(addresses: Sequence[IPAddress], *, limit: int = 3) -> str:
    """Short human description of an address set, for logs and confirmations."""
    if not addresses:
        return "no addresses"
    shown = ", ".join(str(a) for a in addresses[:limit])
    if len(addresses) <= limit:
        return shown
    return f"{shown} … (+{len(addresses) - limit} more)"
