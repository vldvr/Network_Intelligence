"""TLS endpoint assessment.

The adapter performs a handshake and hands back a :class:`TlsObservation`;
this module decides what is wrong with it. Kept apart so every rule —
expiry windows, legacy protocols, weak ciphers, hostname mismatch — is
testable with a hand-written observation and no network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from netintel.core.findings import Finding, Severity

LEGACY_PROTOCOLS = {"SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5", "anon")


@dataclass(frozen=True, slots=True)
class TlsObservation:
    host: str
    port: int
    protocol: str
    cipher: str
    cipher_bits: int
    subject_cn: str | None
    issuer: str | None
    san: tuple[str, ...]
    not_before: datetime
    not_after: datetime
    verified: bool
    verify_error: str | None = None
    legacy_accepted: tuple[str, ...] = field(default_factory=tuple)

    @property
    def self_signed(self) -> bool:
        return self.issuer is not None and self.issuer == self.subject_cn

    def to_json(self) -> dict[str, object]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "cipher": self.cipher,
            "cipher_bits": self.cipher_bits,
            "subject_cn": self.subject_cn,
            "issuer": self.issuer,
            "san": list(self.san),
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "verified": self.verified,
            "verify_error": self.verify_error,
            "legacy_accepted": list(self.legacy_accepted),
        }


def hostname_matches(hostname: str, patterns: tuple[str, ...]) -> bool:
    """RFC 6125 matching: a wildcard covers exactly one left-most label."""
    host = hostname.lower().rstrip(".")
    for pattern in patterns:
        pattern = pattern.lower().rstrip(".")
        if pattern == host:
            return True
        if pattern.startswith("*."):
            suffix = pattern[1:]
            head, _, rest = host.partition(".")
            if head and "." + rest == suffix:
                return True
    return False


def parse_cert_time(text: str) -> datetime:
    """Parse the ``'Jun  1 12:00:00 2026 GMT'`` format :mod:`ssl` returns."""
    return datetime.strptime(text, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)


def assess(obs: TlsObservation, *, now: datetime | None = None) -> list[Finding]:
    moment = now or datetime.now(UTC)
    findings = [
        Finding("tls", Severity.INFO, f"{obs.protocol}, {obs.cipher} ({obs.cipher_bits} bit)"),
        Finding("tls", Severity.INFO, f"issued to {obs.subject_cn or '?'} by {obs.issuer or '?'}"),
    ]

    days_left = (obs.not_after - moment).days
    if obs.not_after < moment:
        findings.append(
            Finding(
                "tls", Severity.HIGH, "certificate has expired", obs.not_after.date().isoformat()
            )
        )
    elif obs.not_before > moment:
        findings.append(Finding("tls", Severity.HIGH, "certificate is not yet valid"))
    elif days_left < 14:
        findings.append(Finding("tls", Severity.MEDIUM, f"certificate expires in {days_left} days"))
    elif days_left < 30:
        findings.append(Finding("tls", Severity.LOW, f"certificate expires in {days_left} days"))
    else:
        findings.append(Finding("tls", Severity.OK, f"certificate valid for {days_left} more days"))

    names = obs.san or ((obs.subject_cn,) if obs.subject_cn else ())
    if not hostname_matches(obs.host, names):
        findings.append(
            Finding(
                "tls", Severity.HIGH, "hostname does not match the certificate", ", ".join(names)
            )
        )

    if obs.self_signed:
        findings.append(Finding("tls", Severity.HIGH, "self-signed certificate"))
    elif not obs.verified:
        findings.append(
            Finding(
                "tls", Severity.HIGH, "certificate chain does not verify", obs.verify_error or ""
            )
        )
    else:
        findings.append(Finding("tls", Severity.OK, "certificate chain verifies"))

    if obs.protocol in LEGACY_PROTOCOLS:
        findings.append(Finding("tls", Severity.HIGH, f"negotiated legacy protocol {obs.protocol}"))
    for proto in obs.legacy_accepted:
        findings.append(Finding("tls", Severity.MEDIUM, f"server still accepts {proto}"))

    if any(marker.lower() in obs.cipher.lower() for marker in WEAK_CIPHER_MARKERS):
        findings.append(Finding("tls", Severity.HIGH, f"weak cipher {obs.cipher}"))
    elif obs.cipher_bits and obs.cipher_bits < 128:
        findings.append(Finding("tls", Severity.MEDIUM, f"short key: {obs.cipher_bits} bit"))
    return findings
