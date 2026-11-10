"""Mail, TLS, header, port and audit logic — all without a network."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from netintel.core.audit import AuditProbes, run_audit
from netintel.core.dnswire import DnsRecord
from netintel.core.findings import Severity, worst
from netintel.core.headers import HttpObservation, audit_headers, grade
from netintel.core.mailsec import check_dmarc, check_spf, count_spf_lookups, parse_spf
from netintel.core.portscan import (
    OpenPort,
    identify_banner,
    parse_ports,
    port_findings,
    run_port_scan,
)
from netintel.core.scope import ScopePolicy
from netintel.core.tlsaudit import TlsObservation, assess, hostname_matches
from netintel.errors import ScopeViolationError, TargetError

NOW = datetime(2026, 6, 1, tzinfo=UTC)


def txt_zone(zone: dict[str, list[str]]):
    return lambda name: zone.get(name, [])


def titles(findings) -> list[str]:
    return [f.title for f in findings]


# ---------------------------------------------------------------- mail


def test_spf_all_qualifier_is_parsed():
    assert parse_spf("v=spf1 include:_spf.example.net ~all").all_qualifier == "~"
    assert parse_spf("v=spf1 a mx all").all_qualifier == "+"


@pytest.mark.parametrize(
    ("record", "severity"),
    [("v=spf1 -all", Severity.OK), ("v=spf1 ~all", Severity.LOW), ("v=spf1 +all", Severity.HIGH)],
)
def test_spf_severity_follows_the_all_qualifier(record, severity):
    findings = check_spf("example.com", txt_zone({"example.com": [record]}))
    assert worst(findings) == severity


def test_missing_and_duplicate_spf_are_high():
    assert worst(check_spf("example.com", txt_zone({}))) == Severity.HIGH
    dup = txt_zone({"example.com": ["v=spf1 -all", "v=spf1 ~all"]})
    assert "multiple SPF records" in titles(check_spf("example.com", dup))


def test_spf_lookup_counting_follows_includes_and_survives_loops():
    zone = {
        "example.com": ["v=spf1 include:a.example include:b.example mx -all"],
        "a.example": ["v=spf1 include:b.example a -all"],
        "b.example": ["v=spf1 include:example.com -all"],  # loop back to the start
    }
    # example.com: include a, include b, mx = 3; a: include b, a = 2; b: include = 1
    assert count_spf_lookups("example.com", txt_zone(zone)) == 6


def test_spf_over_ten_lookups_is_flagged():
    includes = " ".join(f"include:s{i}.example" for i in range(11))
    zone = {"example.com": [f"v=spf1 {includes} -all"]}
    assert any("DNS lookups" in t for t in titles(check_spf("example.com", txt_zone(zone))))


def test_dmarc_policies():
    def dmarc(record):
        return check_dmarc("example.com", txt_zone({"_dmarc.example.com": [record]}))

    assert worst(dmarc("v=DMARC1; p=reject; rua=mailto:d@example.com")) == Severity.OK
    assert worst(dmarc("v=DMARC1; p=none; rua=mailto:d@example.com")) == Severity.MEDIUM
    assert "no aggregate reports (rua)" in titles(dmarc("v=DMARC1; p=reject"))
    assert worst(check_dmarc("example.com", txt_zone({}))) == Severity.HIGH


# ----------------------------------------------------------------- tls


def tls_obs(**overrides) -> TlsObservation:
    base = dict(
        host="www.example.com",
        port=443,
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        subject_cn="example.com",
        issuer="Example CA",
        san=("example.com", "*.example.com"),
        not_before=NOW - timedelta(days=30),
        not_after=NOW + timedelta(days=60),
        verified=True,
    )
    base.update(overrides)
    return TlsObservation(**base)


def test_healthy_endpoint_has_no_problems():
    assert worst(assess(tls_obs(), now=NOW)) == Severity.OK


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"not_after": NOW - timedelta(days=1)}, "certificate has expired"),
        ({"not_after": NOW + timedelta(days=5)}, "certificate expires in 5 days"),
        ({"host": "evil.test"}, "hostname does not match the certificate"),
        ({"issuer": "example.com"}, "self-signed certificate"),
        ({"protocol": "TLSv1"}, "negotiated legacy protocol TLSv1"),
        ({"cipher": "DES-CBC3-SHA"}, "weak cipher DES-CBC3-SHA"),
        ({"legacy_accepted": ("TLSv1.1",)}, "server still accepts TLSv1.1"),
    ],
)
def test_tls_problems_are_reported(overrides, expected):
    assert expected in titles(assess(tls_obs(**overrides), now=NOW))


def test_wildcards_cover_exactly_one_label():
    assert hostname_matches("www.example.com", ("*.example.com",))
    assert not hostname_matches("a.b.example.com", ("*.example.com",))
    assert not hostname_matches("example.com", ("*.example.com",))


# ------------------------------------------------------------- headers

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
}


def test_well_configured_site_gets_an_a():
    findings = audit_headers(
        HttpObservation.from_mapping("https://example.com/", 200, GOOD_HEADERS)
    )
    assert grade(findings) == "A"


def test_bare_site_gets_a_low_grade_and_version_leak():
    obs = HttpObservation.from_mapping(
        "https://example.com/", 200, {"Server": "Apache/2.4.29", "X-Powered-By": "PHP/7.2"}
    )
    findings = audit_headers(obs)
    assert grade(findings) in "DEF"
    assert "X-Powered-By discloses a version" in titles(findings)


def test_inline_styles_do_not_count_as_inline_scripts():
    headers = dict(
        GOOD_HEADERS, **{"Content-Security-Policy": "script-src 'self'; style-src 'unsafe-inline'"}
    )
    findings = audit_headers(HttpObservation.from_mapping("https://example.com/", 200, headers))
    assert "CSP allows inline scripts" not in titles(findings)


def test_inline_scripts_without_nonce_are_flagged():
    headers = dict(
        GOOD_HEADERS, **{"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"}
    )
    findings = audit_headers(HttpObservation.from_mapping("https://example.com/", 200, headers))
    assert "CSP allows inline scripts" in titles(findings)


def test_cookie_flags_are_checked_per_cookie():
    obs = HttpObservation.from_mapping(
        "https://example.com/",
        200,
        [
            ("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Lax"),
            ("Set-Cookie", "track=2; Path=/"),
        ],
    )
    flagged = [t for t in titles(audit_headers(obs)) if t.startswith("cookie")]
    assert flagged == ["cookie track lacks secure, httponly, samesite"]


# --------------------------------------------------------------- ports


def test_port_specs():
    assert parse_ports("22, 80,8000-8002") == (22, 80, 8000, 8001, 8002)
    assert 443 in parse_ports("top")
    for bad in ("0", "70000", "90-80", "ssh", ""):
        with pytest.raises(TargetError):
            parse_ports(bad)


@pytest.mark.parametrize(
    ("banner", "service", "product"),
    [
        ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3", "ssh", "OpenSSH_9.6p1"),
        ("HTTP/1.0 200 OK\r\nServer: nginx/1.25.3\r\n", "http", "nginx/1.25.3"),
        ("220 mail.example.com ESMTP Postfix", "smtp", "mail.example.com ESMTP Postfix"),
    ],
)
def test_banners_are_identified(banner, service, product):
    assert identify_banner(banner) == (service, product)


def test_banner_overrides_the_port_number_guess():
    assert OpenPort("10.0.0.1", 2222, "SSH-2.0-dropbear_2022.83").service == "ssh"
    assert OpenPort("10.0.0.1", 6379).service == "redis"


def test_risky_service_is_found_by_banner_on_a_nonstandard_port():
    telnet = OpenPort("10.0.0.1", 2323, "\xff\xfd\x18login:")
    assert telnet.service == "telnet"
    assert worst(port_findings(telnet)) == Severity.HIGH
    # ...and a known port with a different service is not blamed for it.
    assert port_findings(OpenPort("10.0.0.1", 23, "SSH-2.0-OpenSSH_9.6")) == []


def test_risky_services_produce_findings():
    assert worst(port_findings(OpenPort("10.0.0.1", 23))) == Severity.HIGH
    assert port_findings(OpenPort("10.0.0.1", 443)) == []


def test_port_scan_refuses_public_targets_before_sending_anything():
    calls = []

    def prober(*args, **kwargs):
        calls.append(args)
        return []

    with pytest.raises(ScopeViolationError):
        run_port_scan("8.8.8.8", (53,), prober)
    assert calls == []


def test_port_scan_sorts_results_and_collects_findings():
    def prober(hosts, ports, **_):
        return [OpenPort("192.168.1.5", 23), OpenPort("192.168.1.2", 22, "SSH-2.0-OpenSSH_9.6")]

    report = run_port_scan("192.168.1.0/29", (22, 23), prober, policy=ScopePolicy.private_only())
    assert [(p.host, p.port) for p in report.open_ports] == [
        ("192.168.1.2", 22),
        ("192.168.1.5", 23),
    ]
    assert worst(report.findings) == Severity.HIGH


# --------------------------------------------------------------- audit


def test_audit_merges_sections_and_survives_a_failing_probe():
    def failing_tls(host):
        raise TargetError("handshake failed")

    zone = {
        "example.com": ["v=spf1 -all"],
        "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:x@example.com"],
    }
    probes = AuditProbes(
        query=lambda name, rtype: (
            [DnsRecord(name, 2, 60, "ns1.example.net")] if rtype == "NS" else []
        ),
        txt=txt_zone(zone),
        tls=failing_tls,
        http=lambda host: HttpObservation.from_mapping(f"https://{host}/", 200, GOOD_HEADERS),
    )
    sections = []
    report = run_audit(
        "https://Example.com/path", probes, on_section=lambda name, _: sections.append(name)
    )

    assert report.domain == "example.com"
    assert sections == ["dns", "mail", "headers"]
    assert report.header_grade == "A"
    assert report.errors == ("tls: handshake failed",)
    assert "single nameserver" in titles(report.findings)


def test_spf_walk_is_bounded_on_a_hostile_include_tree():
    calls = []

    def lookup(name):
        calls.append(name)
        # every domain includes 50 fresh domains: unbounded without a budget
        return ["v=spf1 " + " ".join(f"include:{name}.{i}" for i in range(50)) + " -all"]

    total = count_spf_lookups("example.com", lookup)
    assert total > 10
    assert len(calls) < 10


def test_control_characters_in_remote_text_are_escaped():
    from netintel.core.findings import Finding, format_findings

    text = format_findings([Finding("ports", Severity.INFO, "banner", "evil\x1b[2Jtext")])
    assert "\x1b" not in text
    assert "\\x1b[2J" in text
