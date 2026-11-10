"""Mail-domain security: SPF and DMARC analysis.

A domain without a strict SPF and DMARC policy can be spoofed in a phishing
mail with no technical effort at all — one of the most common findings in
an external assessment, and one a beginner can understand and fix. The
parsing here follows RFC 7208 (SPF) and RFC 7489 (DMARC) closely enough to
catch what matters: missing records, permissive ``all`` qualifiers, the
10-lookup limit that silently breaks SPF, and ``p=none`` monitoring-only
policies.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from netintel.core.findings import Finding, Severity

TxtLookup = Callable[[str], Sequence[str]]
"""Returns the TXT strings published at a name (empty if none)."""

SPF_LOOKUP_LIMIT = 10
_LOOKUP_MECHANISMS = ("include", "a", "mx", "ptr", "exists", "redirect")


@dataclass(frozen=True, slots=True)
class SpfRecord:
    raw: str
    mechanisms: tuple[str, ...]
    all_qualifier: str | None  # '+', '-', '~', '?' or None when absent
    redirect: str | None

    @property
    def includes(self) -> tuple[str, ...]:
        return tuple(
            m.split(":", 1)[1] for m in self.mechanisms if m.lstrip("+-~?").startswith("include:")
        )


def parse_spf(raw: str) -> SpfRecord:
    terms = raw.split()[1:]  # drop "v=spf1"
    mechanisms: list[str] = []
    all_qualifier = None
    redirect = None
    for term in terms:
        lowered = term.lower()
        if lowered.startswith("redirect="):
            redirect = term.split("=", 1)[1]
            continue
        if "=" in lowered:  # other modifiers (exp=...)
            continue
        mechanisms.append(lowered)
        bare = lowered.lstrip("+-~?")
        if bare == "all":
            all_qualifier = lowered[0] if lowered[0] in "+-~?" else "+"
    return SpfRecord(raw, tuple(mechanisms), all_qualifier, redirect)


def _spf_records(txt: Sequence[str]) -> list[str]:
    return [t for t in txt if t.lower().startswith("v=spf1")]


_SPF_MAX_DEPTH = 10
_SPF_BUDGET = SPF_LOOKUP_LIMIT * 3


def count_spf_lookups(domain: str, lookup: TxtLookup) -> int:
    """Count DNS-querying terms, following include/redirect recursively.

    Past :data:`SPF_LOOKUP_LIMIT` a receiver must return ``permerror`` —
    the record stops protecting anything, and nobody notices because mail
    still flows. A hostile zone can publish a wide or deep include tree, so
    one budget is shared across the whole walk and checked before every
    query: counting stops a little past the limit instead of following it all.
    """
    state = {"total": 0}
    _walk_spf(domain, lookup, set(), state, depth=0)
    return state["total"]


def _walk_spf(
    domain: str, lookup: TxtLookup, seen: set[str], state: dict[str, int], *, depth: int
) -> None:
    if domain in seen or depth > _SPF_MAX_DEPTH or state["total"] > _SPF_BUDGET:
        return
    seen.add(domain)
    records = _spf_records(lookup(domain))
    if not records:
        return
    spf = parse_spf(records[0])
    targets = []
    for mechanism in spf.mechanisms:
        bare = mechanism.lstrip("+-~?")
        name = bare.split(":", 1)[0].split("/", 1)[0]
        if name in _LOOKUP_MECHANISMS:
            state["total"] += 1
            if name == "include" and ":" in bare:
                targets.append(bare.split(":", 1)[1])
    if spf.redirect:
        state["total"] += 1
        targets.append(spf.redirect)
    for target in targets:
        if state["total"] > _SPF_BUDGET:
            return
        _walk_spf(target, lookup, seen, state, depth=depth + 1)


def check_spf(domain: str, lookup: TxtLookup) -> list[Finding]:
    records = _spf_records(lookup(domain))
    if not records:
        return [
            Finding("spf", Severity.HIGH, "no SPF record", "anyone can send mail as this domain")
        ]
    if len(records) > 1:
        return [
            Finding(
                "spf",
                Severity.HIGH,
                "multiple SPF records",
                "receivers must treat this as permerror",
            )
        ]

    spf = parse_spf(records[0])
    findings = [Finding("spf", Severity.INFO, "SPF record", spf.raw)]
    qualifier = spf.all_qualifier
    if qualifier == "+":
        findings.append(
            Finding(
                "spf", Severity.HIGH, "SPF ends in +all", "authorises every server on the internet"
            )
        )
    elif qualifier == "?":
        findings.append(
            Finding(
                "spf", Severity.MEDIUM, "SPF ends in ?all", "neutral — spoofed mail is not rejected"
            )
        )
    elif qualifier == "~":
        findings.append(
            Finding("spf", Severity.LOW, "SPF ends in ~all", "softfail; relies on DMARC to enforce")
        )
    elif qualifier == "-":
        findings.append(Finding("spf", Severity.OK, "SPF ends in -all"))
    elif not spf.redirect:
        findings.append(
            Finding(
                "spf",
                Severity.MEDIUM,
                "SPF has no 'all' mechanism",
                "unlisted senders default to neutral",
            )
        )

    if any(m.lstrip("+-~?").startswith("ptr") for m in spf.mechanisms):
        findings.append(
            Finding(
                "spf", Severity.LOW, "SPF uses ptr", "deprecated by RFC 7208, slow and unreliable"
            )
        )

    lookups = count_spf_lookups(domain, lookup)
    if lookups > SPF_LOOKUP_LIMIT:
        findings.append(
            Finding(
                "spf",
                Severity.HIGH,
                f"SPF needs {lookups} DNS lookups",
                f"over the limit of {SPF_LOOKUP_LIMIT}: permerror",
            )
        )
    return findings


def parse_dmarc(raw: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in raw.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


def check_dmarc(domain: str, lookup: TxtLookup) -> list[Finding]:
    records = [t for t in lookup(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    if not records:
        return [
            Finding(
                "dmarc",
                Severity.HIGH,
                "no DMARC record",
                "spoofed mail is delivered and nobody is told",
            )
        ]
    tags = parse_dmarc(records[0])
    findings = [Finding("dmarc", Severity.INFO, "DMARC record", records[0])]

    policy = tags.get("p", "").lower()
    if policy == "reject":
        findings.append(Finding("dmarc", Severity.OK, "DMARC policy is reject"))
    elif policy == "quarantine":
        findings.append(
            Finding(
                "dmarc", Severity.LOW, "DMARC policy is quarantine", "spoofed mail goes to spam"
            )
        )
    elif policy == "none":
        findings.append(
            Finding(
                "dmarc",
                Severity.MEDIUM,
                "DMARC policy is none",
                "monitoring only — nothing is blocked",
            )
        )
    else:
        findings.append(
            Finding("dmarc", Severity.HIGH, "DMARC has no valid p= tag", "the record is ignored")
        )

    pct = tags.get("pct", "100")
    if pct.isdigit() and int(pct) < 100 and policy in ("reject", "quarantine"):
        findings.append(Finding("dmarc", Severity.LOW, f"DMARC applies to {pct}% of mail"))
    if "rua" not in tags:
        findings.append(
            Finding(
                "dmarc", Severity.LOW, "no aggregate reports (rua)", "spoofing attempts go unseen"
            )
        )
    return findings


def check_mail(domain: str, lookup: TxtLookup) -> list[Finding]:
    return check_spf(domain, lookup) + check_dmarc(domain, lookup)
