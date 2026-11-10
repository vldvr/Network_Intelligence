"""HTTP security-header audit.

Checks the response headers a browser relies on for defence in depth —
HSTS, CSP, framing, MIME sniffing, referrer and permissions policy — plus
headers that leak the server stack, and cookie flags. Each missing control
costs points; the result is a letter grade a beginner can act on and a
finding list a pentester can paste into a report.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from netintel.core.findings import Finding, Severity

HSTS_MIN_AGE = 15_552_000  # 180 days


@dataclass(frozen=True, slots=True)
class HttpObservation:
    url: str
    status: int
    headers: tuple[tuple[str, str], ...]  # keeps duplicates (Set-Cookie)
    https: bool

    def get(self, name: str) -> str | None:
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return None

    def get_all(self, name: str) -> list[str]:
        lowered = name.lower()
        return [value for key, value in self.headers if key.lower() == lowered]

    @classmethod
    def from_mapping(
        cls, url: str, status: int, headers: Mapping[str, str] | Iterable[tuple[str, str]]
    ) -> HttpObservation:
        items = tuple(headers.items()) if isinstance(headers, Mapping) else tuple(headers)
        return cls(url, status, items, url.lower().startswith("https://"))


def _hsts(obs: HttpObservation) -> Finding:
    value = obs.get("Strict-Transport-Security")
    if not obs.https:
        return Finding(
            "headers", Severity.MEDIUM, "site served over plain HTTP", "HSTS cannot apply"
        )
    if value is None:
        return Finding(
            "headers",
            Severity.MEDIUM,
            "no Strict-Transport-Security",
            "first visit can be downgraded to HTTP",
        )
    age = 0
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            digits = part.split("=", 1)[1].strip('"')
            age = int(digits) if digits.isdigit() else 0
    if age < HSTS_MIN_AGE:
        return Finding(
            "headers", Severity.LOW, f"HSTS max-age is short ({age}s)", "use at least 180 days"
        )
    return Finding("headers", Severity.OK, "HSTS enabled", value)


def _csp(obs: HttpObservation) -> Finding:
    value = obs.get("Content-Security-Policy")
    if value is None:
        return Finding(
            "headers",
            Severity.MEDIUM,
            "no Content-Security-Policy",
            "no second line of defence against XSS",
        )
    directives = parse_csp(value)
    scripts = directives.get("script-src", directives.get("default-src"))
    if scripts is None:
        return Finding(
            "headers", Severity.LOW, "CSP does not restrict scripts", "no script-src or default-src"
        )
    has_nonce = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in scripts)
    if "'unsafe-inline'" in scripts and not has_nonce:
        return Finding(
            "headers", Severity.LOW, "CSP allows inline scripts", "script-src 'unsafe-inline'"
        )
    if "*" in scripts or "data:" in scripts:
        return Finding("headers", Severity.LOW, "CSP allows scripts from any origin")
    return Finding("headers", Severity.OK, "Content-Security-Policy restricts scripts")


def parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


def _framing(obs: HttpObservation) -> Finding:
    csp = (obs.get("Content-Security-Policy") or "").lower()
    if "frame-ancestors" in csp or obs.get("X-Frame-Options"):
        return Finding("headers", Severity.OK, "clickjacking protection set")
    return Finding(
        "headers",
        Severity.LOW,
        "no X-Frame-Options or frame-ancestors",
        "page can be framed (clickjacking)",
    )


def _simple(
    obs: HttpObservation, name: str, expected: str | None, severity: Severity, why: str
) -> Finding:
    value = obs.get(name)
    if value is None or (expected and value.strip().lower() != expected):
        return Finding(
            "headers", severity, f"no {name}" if value is None else f"{name}: {value}", why
        )
    return Finding("headers", Severity.OK, f"{name} set")


def _leaks(obs: HttpObservation) -> list[Finding]:
    found = []
    for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        value = obs.get(name)
        if value and any(ch.isdigit() for ch in value):
            found.append(Finding("headers", Severity.LOW, f"{name} discloses a version", value))
        elif value and name != "Server":
            found.append(Finding("headers", Severity.INFO, f"{name} header present", value))
    return found


def _cookies(obs: HttpObservation) -> list[Finding]:
    found = []
    for cookie in obs.get_all("Set-Cookie"):
        name = cookie.split("=", 1)[0].strip()
        attrs = {part.strip().split("=", 1)[0].lower() for part in cookie.split(";")[1:]}
        missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in attrs]
        if obs.https and missing:
            found.append(
                Finding("headers", Severity.LOW, f"cookie {name} lacks {', '.join(missing)}")
            )
    return found


def audit_headers(obs: HttpObservation) -> list[Finding]:
    findings = [
        Finding("headers", Severity.INFO, f"HTTP {obs.status} from {obs.url}"),
        _hsts(obs),
        _csp(obs),
        _framing(obs),
        _simple(
            obs,
            "X-Content-Type-Options",
            "nosniff",
            Severity.LOW,
            "browser may MIME-sniff responses",
        ),
        _simple(obs, "Referrer-Policy", None, Severity.LOW, "full URLs may leak to third parties"),
        _simple(
            obs, "Permissions-Policy", None, Severity.INFO, "camera/mic/geolocation not restricted"
        ),
    ]
    return findings + _leaks(obs) + _cookies(obs)


_PENALTY = {
    Severity.HIGH: 30,
    Severity.MEDIUM: 20,
    Severity.LOW: 7,
    Severity.INFO: 0,
    Severity.OK: 0,
}


def grade(findings: Iterable[Finding]) -> str:
    score = 100 - sum(_PENALTY[f.severity] for f in findings)
    for threshold, letter in ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (20, "E")):
        if score >= threshold:
            return letter
    return "F"
