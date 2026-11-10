"""TCP port scanning: port specifications, service names, banner analysis.

The scanner itself (:mod:`netintel.adapters.portprobe`) is an unprivileged
connect() scan with banner grabbing — no nmap. This module holds the logic
around it: parsing ``22,80,8000-8100`` or ``top100``, naming services, and
reading banners for version strings and protocols that should not be
exposed (Telnet, unauthenticated Redis, SMB on the internet).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from netintel.cancellation import NEVER_CANCELLED, CancellationToken
from netintel.core.findings import Finding, Severity, clean
from netintel.core.scope import ScopePolicy
from netintel.core.targets import parse_targets
from netintel.errors import TargetError

SERVICES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    1883: "mqtt",
    2049: "nfs",
    2375: "docker",
    3000: "http-dev",
    3306: "mysql",
    3389: "rdp",
    5000: "http-dev",
    5432: "postgresql",
    5601: "kibana",
    5900: "vnc",
    5985: "winrm",
    6379: "redis",
    6443: "kubernetes",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9000: "http-alt",
    9090: "prometheus",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

TOP_PORTS: tuple[int, ...] = tuple(sorted(SERVICES))

RISKY: dict[int, tuple[Severity, str]] = {
    23: (Severity.HIGH, "Telnet sends credentials in clear text"),
    21: (Severity.MEDIUM, "FTP sends credentials in clear text"),
    445: (Severity.MEDIUM, "SMB should never face the internet"),
    3389: (Severity.MEDIUM, "RDP is a top ransomware entry point"),
    5900: (Severity.MEDIUM, "VNC is often weakly authenticated"),
    2375: (Severity.HIGH, "unauthenticated Docker API = root on the host"),
    6379: (Severity.HIGH, "Redis is unauthenticated by default"),
    9200: (Severity.HIGH, "Elasticsearch is unauthenticated by default"),
    11211: (Severity.HIGH, "memcached: data exposure and UDP amplification"),
    27017: (Severity.HIGH, "MongoDB is often exposed without auth"),
}

MAX_PORTS = 65535

_BANNER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ssh", re.compile(r"^SSH-[\d.]+-(\S+)")),
    ("telnet", re.compile(r"^\xff[\xfb-\xfe]")),  # IAC WILL/WONT/DO/DONT negotiation
    ("ftp", re.compile(r"^220[ -].*?(\w*FTP\w*[^\r\n]*)", re.I)),
    ("smtp", re.compile(r"^220[ -](\S+ .*?(?:SMTP|ESMTP)[^\r\n]*)", re.I)),
    ("http", re.compile(r"^HTTP/\d\.\d \d{3}.*?\r?\nServer: ([^\r\n]+)", re.I | re.S)),
    ("redis", re.compile(r"^-(NOAUTH|ERR)|^\$\d+\r\n# Server", re.I)),
    ("mysql", re.compile(r"^.{4}\n([\d.]+[^\x00]*)", re.S)),
)


def parse_ports(spec: str) -> tuple[int, ...]:
    """``'22,80,8000-8010'``, ``'top'`` or ``'all'`` → sorted unique ports."""
    text = spec.strip().lower()
    if text in ("top", "top100", "common"):
        return TOP_PORTS
    if text == "all":
        return tuple(range(1, MAX_PORTS + 1))
    ports: set[int] = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            if not (lo_s.isdigit() and hi_s.isdigit()):
                raise TargetError(f"bad port range {part!r}")
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                raise TargetError(f"port range {part!r} is backwards")
        elif part.isdigit():
            lo = hi = int(part)
        else:
            raise TargetError(f"bad port {part!r}")
        if not 1 <= lo <= hi <= MAX_PORTS:
            raise TargetError(f"port {part!r} out of range 1-65535")
        ports.update(range(lo, hi + 1))
    if not ports:
        raise TargetError("no ports given")
    return tuple(sorted(ports))


def identify_banner(banner: str) -> tuple[str | None, str | None]:
    """Return ``(service, product/version)`` recognised in a banner."""
    for service, pattern in _BANNER_PATTERNS:
        match = pattern.search(banner)
        if match:
            version = match.group(1) if match.groups() else None
            return service, (version.strip() if version else None)
    return None, None


@dataclass(frozen=True, slots=True)
class OpenPort:
    host: str
    port: int
    banner: str = ""
    latency_ms: float | None = None

    @property
    def service(self) -> str:
        detected, _ = identify_banner(self.banner)
        return detected or SERVICES.get(self.port, "unknown")

    @property
    def product(self) -> str | None:
        return identify_banner(self.banner)[1]

    def to_json(self) -> dict[str, object]:
        return {
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "product": self.product,
            "banner": self.banner,
            "latency_ms": self.latency_ms,
        }


def port_findings(port: OpenPort) -> list[Finding]:
    findings = []
    # The banner wins over the port number: Telnet on 2323 is still Telnet.
    known = {SERVICES[p]: p for p in RISKY}
    risk_key = known.get(
        port.service, port.port if port.service == SERVICES.get(port.port) else None
    )
    if risk_key in RISKY:
        severity, why = RISKY[risk_key]
        findings.append(
            Finding("ports", severity, f"{port.host}:{port.port} {port.service} open", why)
        )
    if port.service == "redis" and "NOAUTH" not in port.banner.upper():
        findings.append(
            Finding("ports", Severity.HIGH, f"{port.host}:{port.port} Redis answered without auth")
        )
    return findings


@dataclass(frozen=True, slots=True)
class PortScanReport:
    hosts: tuple[str, ...]
    ports_per_host: int
    open_ports: tuple[OpenPort, ...]
    cancelled: bool = False
    findings: tuple[Finding, ...] = field(default_factory=tuple)

    def to_json(self) -> dict[str, object]:
        return {
            "hosts": list(self.hosts),
            "ports_per_host": self.ports_per_host,
            "open": [p.to_json() for p in self.open_ports],
            "cancelled": self.cancelled,
            "findings": [f.to_json() for f in self.findings],
        }


PortProber = Callable[..., Sequence[OpenPort]]


def run_port_scan(
    targets: str,
    ports: Sequence[int],
    prober: PortProber,
    *,
    policy: ScopePolicy | None = None,
    timeout: float = 1.0,
    token: CancellationToken = NEVER_CANCELLED,
    on_open: Callable[[OpenPort], None] | None = None,
) -> PortScanReport:
    """Scope-check ``targets`` and scan ``ports`` on every address."""
    scope = policy or ScopePolicy.private_only()
    spec = parse_targets(targets, max_hosts=scope.max_hosts)
    scope.check(spec)
    found = prober(
        spec.as_strings,
        ports,
        timeout=timeout,
        should_continue=token.should_continue,
        on_open=on_open,
    )
    ordered = tuple(sorted(found, key=lambda p: (p.host, p.port)))
    findings = tuple(f for p in ordered for f in port_findings(p))
    return PortScanReport(spec.as_strings, len(ports), ordered, token.cancelled, findings)


def format_port_report(report: PortScanReport) -> str:
    lines = [
        f"{len(report.open_ports)} open port(s) on {len(report.hosts)} host(s), "
        f"{report.ports_per_host} ports each"
    ]
    for p in report.open_ports:
        line = f"  {p.host:<16} {p.port:>5}/tcp  {p.service:<14}"
        if p.product:
            line += f" {clean(p.product)}"
        lines.append(line.rstrip())
    if report.cancelled:
        lines.append("cancelled — results are partial")
    return "\n".join(lines)
