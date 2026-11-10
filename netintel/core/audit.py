"""One-shot external audit of a domain.

Runs the passive checks a first look at any organisation starts with — DNS
records, mail spoofing protection, the TLS certificate and the web security
headers — and merges them into one finding list. No port scanning: an
audit of a domain you do not own must stay within what any visitor sees.

Probes are injected, so the orchestration is tested without a network.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from netintel.core.dnswire import DnsRecord
from netintel.core.findings import Finding, Severity, worst
from netintel.core.headers import HttpObservation, audit_headers, grade
from netintel.core.mailsec import check_mail
from netintel.core.tlsaudit import TlsObservation, assess
from netintel.errors import NetIntelError

RECORD_TYPES = ("A", "AAAA", "NS", "MX", "TXT", "CAA")


@dataclass(frozen=True, slots=True)
class AuditProbes:
    query: Callable[[str, str], Sequence[DnsRecord]]
    txt: Callable[[str], Sequence[str]]
    tls: Callable[[str], TlsObservation]
    http: Callable[[str], HttpObservation]


@dataclass(frozen=True, slots=True)
class AuditReport:
    domain: str
    records: tuple[DnsRecord, ...]
    findings: tuple[Finding, ...]
    header_grade: str | None = None
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def worst(self) -> Severity:
        return worst(self.findings)

    def to_json(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "records": [r.to_json() for r in self.records],
            "findings": [f.to_json() for f in self.findings],
            "header_grade": self.header_grade,
            "errors": list(self.errors),
            "worst": self.worst.label,
        }


def dns_findings(records: Sequence[DnsRecord]) -> list[Finding]:
    types = {r.type_name for r in records}
    findings = [
        Finding(
            "dns",
            Severity.INFO,
            f"{t}: {', '.join(sorted({r.value for r in records if r.type_name == t}))[:150]}",
        )
        for t in RECORD_TYPES
        if t in types and t != "TXT"
    ]
    if "CAA" not in types:
        findings.append(
            Finding(
                "dns",
                Severity.LOW,
                "no CAA record",
                "any CA may issue certificates for this domain",
            )
        )
    if any(r.type_name == "MX" and r.value.endswith(" .") for r in records):
        findings.append(
            Finding("dns", Severity.OK, "null MX", "domain explicitly accepts no mail (RFC 7505)")
        )
    if "MX" not in types:
        findings.append(
            Finding("dns", Severity.INFO, "no MX record", "domain does not receive mail")
        )
    if len({r.value for r in records if r.type_name == "NS"}) == 1:
        findings.append(Finding("dns", Severity.LOW, "single nameserver", "no DNS redundancy"))
    return findings


def run_audit(
    domain: str,
    probes: AuditProbes,
    *,
    on_section: Callable[[str, list[Finding]], None] | None = None,
) -> AuditReport:
    domain = domain.strip().lower().rstrip(".")
    for prefix in ("https://", "http://"):
        domain = domain.removeprefix(prefix)
    domain = domain.split("/", 1)[0]

    records: list[DnsRecord] = []
    findings: list[Finding] = []
    errors: list[str] = []
    header_grade = None

    def section(name: str, items: list[Finding]) -> None:
        findings.extend(items)
        if on_section:
            on_section(name, items)

    for rtype in RECORD_TYPES:
        try:
            records.extend(probes.query(domain, rtype))
        except NetIntelError as exc:
            errors.append(f"dns {rtype}: {exc}")
    section("dns", dns_findings(records))

    try:
        section("mail", check_mail(domain, probes.txt))
    except NetIntelError as exc:
        errors.append(f"mail: {exc}")

    try:
        section("tls", assess(probes.tls(domain)))
    except NetIntelError as exc:
        errors.append(f"tls: {exc}")

    try:
        header_items = audit_headers(probes.http(domain))
        header_grade = grade(header_items)
        section("headers", header_items)
    except NetIntelError as exc:
        errors.append(f"headers: {exc}")

    return AuditReport(domain, tuple(records), tuple(findings), header_grade, tuple(errors))
