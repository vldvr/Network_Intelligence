"""Authorised-scope enforcement for active scanning.

Passive tools (traceroute, a lookup, a capture on your own interface) are
unremarkable. Sweeping address ranges is different: unauthorised port scanning
is a criminal offence under, among others, the UK Computer Misuse Act 1990 and
§ 202c StGB in Germany, and it will get a host null-routed by most providers
regardless of the law.

So the policy is not a paragraph in the README. Scanning is confined to
RFC 1918 space by default, and reaching outside it takes a deliberate,
recorded act: an explicit allowlist of prefixes the operator states they are
authorised to test. The default is the safe one, and the audit trail exists
whether or not anyone reads it.
"""

from __future__ import annotations

import ipaddress
import json
import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from netintel.core.targets import (
    LOCAL_PREFIXES,
    IPAddress,
    IPNetwork,
    TargetSpec,
    is_public,
)
from netintel.errors import ScopeViolationError, TargetError

DEFAULT_SCOPE_FILENAME = "netintel-scope.json"
SCOPE_ENV_VAR = "NETINTEL_SCOPE_FILE"

PRIVATE_PREFIXES: tuple[str, ...] = LOCAL_PREFIXES
"""The default scope. Defined once, in :mod:`netintel.core.targets`, so the
guard and the classifier cannot disagree about what counts as local."""


def _parse_prefixes(prefixes: Iterable[str]) -> tuple[IPNetwork, ...]:
    networks: list[IPNetwork] = []
    for prefix in prefixes:
        try:
            networks.append(ipaddress.ip_network(prefix, strict=False))
        except ValueError as exc:
            raise TargetError(f"{prefix!r} is not a valid network prefix") from exc
    return tuple(networks)


@dataclass(frozen=True, slots=True)
class ScopePolicy:
    """Which addresses this installation is permitted to actively scan."""

    allowed: tuple[IPNetwork, ...] = field(
        default_factory=lambda: _parse_prefixes(PRIVATE_PREFIXES)
    )
    allow_public: bool = False
    max_hosts: int = 4096
    note: str = "default policy: private address space only"

    @classmethod
    def private_only(cls) -> ScopePolicy:
        return cls()

    @classmethod
    def from_prefixes(
        cls, prefixes: Sequence[str], *, note: str = "operator-supplied scope"
    ) -> ScopePolicy:
        """Build a policy from prefixes the operator states they may test."""
        networks = _parse_prefixes(prefixes)
        allow_public = any(is_public(network.network_address) for network in networks)
        merged = _parse_prefixes(PRIVATE_PREFIXES) + networks
        return cls(allowed=merged, allow_public=allow_public, note=note)

    @classmethod
    def load(cls, path: Path | str | None = None) -> ScopePolicy:
        """Load a scope file, falling back to the private-only default.

        Resolution order: explicit ``path``, then ``$NETINTEL_SCOPE_FILE``,
        then ``./netintel-scope.json``. A missing file is not an error — it
        means "no extra authorisation has been declared".
        """
        candidate = _resolve_scope_path(path)
        if candidate is None or not candidate.is_file():
            return cls.private_only()

        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TargetError(f"cannot read scope file {candidate}: {exc}") from exc

        prefixes = data.get("authorized_prefixes", [])
        if not isinstance(prefixes, list):
            raise TargetError("scope file: 'authorized_prefixes' must be a list")

        policy = cls.from_prefixes(
            [str(p) for p in prefixes],
            note=str(data.get("note") or f"scope file {candidate}"),
        )
        max_hosts = data.get("max_hosts")
        if isinstance(max_hosts, int) and max_hosts > 0:
            policy = ScopePolicy(
                allowed=policy.allowed,
                allow_public=policy.allow_public,
                max_hosts=max_hosts,
                note=policy.note,
            )
        return policy

    def permits(self, address: IPAddress) -> bool:
        return any(address in network for network in self.allowed)

    def check(self, spec: TargetSpec) -> None:
        """Raise :class:`ScopeViolationError` unless every address is in scope."""
        if len(spec) > self.max_hosts:
            raise ScopeViolationError(
                f"{len(spec)} addresses exceeds the configured limit of {self.max_hosts}"
            )

        rejected = [address for address in spec if not self.permits(address)]
        if not rejected:
            return

        sample = ", ".join(str(a) for a in rejected[:5])
        more = "" if len(rejected) <= 5 else f" (+{len(rejected) - 5} more)"
        raise ScopeViolationError(
            f"{len(rejected)} address(es) outside the authorised scope: {sample}{more}. "
            f"Active scanning is limited by {self.note}. To scan hosts you are "
            f"authorised to test, list their prefixes in a scope file "
            f"({DEFAULT_SCOPE_FILENAME}) or pass --authorized-scope."
        )

    def describe(self) -> str:
        prefixes = ", ".join(str(network) for network in self.allowed)
        return f"{self.note}; allowed: {prefixes}; max hosts: {self.max_hosts}"


def _resolve_scope_path(path: Path | str | None) -> Path | None:
    if path is not None:
        return Path(path)
    from_env = os.environ.get(SCOPE_ENV_VAR)
    if from_env:
        return Path(from_env)
    return Path.cwd() / DEFAULT_SCOPE_FILENAME
