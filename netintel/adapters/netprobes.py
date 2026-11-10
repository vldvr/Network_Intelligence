"""Standard-library network probes for the audit modules.

Everything here is plain sockets, :mod:`ssl` and :mod:`http.client` — no
third-party scanner, no root. Each probe returns an observation object from
``core``; deciding what the observation means happens there.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import struct
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from netintel.core.dnswire import DnsError, DnsRecord, RecordType, build_query, parse_response
from netintel.core.headers import HttpObservation
from netintel.core.portscan import OpenPort
from netintel.core.tlsaudit import TlsObservation, parse_cert_time
from netintel.errors import NetIntelError, TargetError

FALLBACK_RESOLVER = "1.1.1.1"


# ---------------------------------------------------------------------- DNS


def system_nameserver(resolv_conf: Path = Path("/etc/resolv.conf")) -> str:
    try:
        for line in resolv_conf.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver" and ":" not in parts[1]:
                return parts[1]
    except OSError:
        pass
    return FALLBACK_RESOLVER


class WireDnsClient:
    """Sends hand-built queries over UDP, retrying over TCP when truncated."""

    def __init__(self, server: str | None = None, *, port: int = 53, timeout: float = 3.0) -> None:
        self.server = server or system_nameserver()
        self._port = port
        self._timeout = timeout
        self._udp_ok = True  # flips to False after the first UDP timeout

    def query(self, name: str, rtype: int | str) -> list[DnsRecord]:
        code = RecordType[rtype.upper()] if isinstance(rtype, str) else rtype
        packet = build_query(name, code)
        qid = struct.unpack_from("!H", packet)[0]
        try:
            try:
                if not self._udp_ok:
                    raise OSError("UDP disabled after an earlier timeout")
                response = parse_response(self._udp(packet), expected_id=qid)
            except OSError:
                self._udp_ok = False
                # UDP/53 is often filtered (corporate networks, sandboxes);
                # RFC 7766 makes TCP a first-class transport, so retry there.
                response = None
            if response is None or response.truncated:
                response = parse_response(self._tcp(packet), expected_id=qid)
        except OSError as exc:
            raise DnsError(f"DNS server {self.server} did not answer: {exc}") from exc
        if response.rcode == 3:
            return []
        if response.rcode != 0:
            raise DnsError(f"{name} {RecordType(code).name}: {response.rcode_name}")
        return [r for r in response.answers if r.rtype == code]

    def txt(self, name: str) -> list[str]:
        return [r.value for r in self.query(name, RecordType.TXT)]

    def _udp(self, packet: bytes) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self._timeout)
            sock.sendto(packet, (self.server, self._port))
            data, _ = sock.recvfrom(65535)
            return data

    def _tcp(self, packet: bytes) -> bytes:
        with socket.create_connection((self.server, self._port), timeout=self._timeout) as sock:
            sock.sendall(struct.pack("!H", len(packet)) + packet)
            (length,) = struct.unpack("!H", _recv_exact(sock, 2))
            return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise DnsError("connection closed mid-response")
        buf += chunk
    return bytes(buf)


# ---------------------------------------------------------------------- TLS


def _name(field: tuple[tuple[tuple[str, str], ...], ...], key: str) -> str | None:
    for rdn in field:
        for k, v in rdn:
            if k == key:
                return v
    return None


def _legacy_versions(host: str, port: int, timeout: float) -> tuple[str, ...]:
    """Try TLS 1.0/1.1 handshakes. Local OpenSSL may refuse to offer them;
    then we simply cannot tell, and report nothing rather than a guess."""
    accepted = []
    for label, version in (("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            ctx.minimum_version = version
            ctx.maximum_version = version
            with (
                socket.create_connection((host, port), timeout=timeout) as raw,
                ctx.wrap_socket(raw, server_hostname=host),
            ):
                accepted.append(label)
        except (ssl.SSLError, OSError, ValueError):
            continue
    return tuple(accepted)


def probe_tls(
    host: str, port: int = 443, *, timeout: float = 5.0, check_legacy: bool = True
) -> TlsObservation:
    verified, verify_error = True, None
    cert: Any
    cipher: Any
    proto: str | None
    ctx = ssl.create_default_context()
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as raw,
            ctx.wrap_socket(raw, server_hostname=host) as tls,
        ):
            cert, cipher, proto = tls.getpeercert(), tls.cipher(), tls.version()
    except ssl.SSLCertVerificationError as exc:
        verified, verify_error = False, exc.verify_message or str(exc)
        cert, cipher, proto = _unverified(host, port, timeout)
    except (OSError, ssl.SSLError) as exc:
        raise TargetError(f"TLS handshake with {host}:{port} failed: {exc}") from exc

    if not cert:
        raise NetIntelError(f"{host}:{port} sent no certificate")
    san = tuple(v for k, v in cert.get("subjectAltName", ()) if k == "DNS")
    return TlsObservation(
        host=host,
        port=port,
        protocol=proto or "?",
        cipher=cipher[0] if cipher else "?",
        cipher_bits=cipher[2] if cipher else 0,
        subject_cn=_name(cert.get("subject", ()), "commonName"),
        issuer=_name(cert.get("issuer", ()), "organizationName")
        or _name(cert.get("issuer", ()), "commonName"),
        san=san,
        not_before=parse_cert_time(cert["notBefore"]),
        not_after=parse_cert_time(cert["notAfter"]),
        verified=verified,
        verify_error=verify_error,
        legacy_accepted=_legacy_versions(host, port, timeout) if check_legacy else (),
    )


def _unverified(host: str, port: int, timeout: float) -> tuple[Any, Any, str | None]:
    """Re-handshake without verification so a broken cert can still be described."""
    import tempfile

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((host, port), timeout=timeout) as raw,
        ctx.wrap_socket(raw, server_hostname=host) as tls,
    ):
        der, cipher, proto = tls.getpeercert(binary_form=True), tls.cipher(), tls.version()
    # getpeercert() returns {} when unverified; decode the DER via ssl's helper.
    pem = ssl.DER_cert_to_PEM_cert(der or b"")
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
        fh.write(pem)
        path = fh.name
    try:
        decoded = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    finally:
        Path(path).unlink(missing_ok=True)
    return decoded, cipher, proto


# --------------------------------------------------------------------- HTTP


def fetch_headers(url: str, *, timeout: float = 8.0, max_redirects: int = 5) -> HttpObservation:
    if "://" not in url:
        url = "https://" + url
    for _ in range(max_redirects + 1):
        parts = urlsplit(url)
        conn_cls = (
            http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
        )
        conn = conn_cls(parts.hostname or "", parts.port, timeout=timeout)
        try:
            conn.request(
                "GET",
                (parts.path or "/") + (f"?{parts.query}" if parts.query else ""),
                headers={"User-Agent": "netintel-audit/1.0", "Accept": "*/*"},
            )
            resp = conn.getresponse()
            headers = resp.getheaders()
            resp.read(65536)
        except (OSError, http.client.HTTPException) as exc:
            raise TargetError(f"cannot fetch {url}: {exc}") from exc
        finally:
            conn.close()
        location = resp.getheader("Location")
        if resp.status in (301, 302, 303, 307, 308) and location:
            url = location if "://" in location else f"{parts.scheme}://{parts.netloc}{location}"
            continue
        return HttpObservation.from_mapping(url, resp.status, headers)
    raise TargetError(f"too many redirects from {url}")


# -------------------------------------------------------------------- ports

_PROBES: dict[int, bytes] = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\n\r\n",
    8888: b"HEAD / HTTP/1.0\r\n\r\n",
    6379: b"INFO server\r\n",
}


def _probe_port(host: str, port: int, timeout: float) -> OpenPort | None:
    started = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    latency = (time.perf_counter() - started) * 1000
    banner = b""
    with sock:
        sock.settimeout(min(timeout, 1.5))
        try:
            if port in _PROBES:
                sock.sendall(_PROBES[port])
            banner = sock.recv(512)
        except OSError:
            pass
    return OpenPort(
        host, port, banner.decode("latin-1", errors="replace").strip()[:200], round(latency, 1)
    )


def scan_ports(
    hosts: Sequence[str],
    ports: Sequence[int],
    *,
    timeout: float,
    should_continue: Callable[[], bool],
    on_open: Callable[[OpenPort], None] | None = None,
    max_workers: int = 200,
) -> list[OpenPort]:
    jobs = [(h, p) for h in hosts for p in ports]
    found: list[OpenPort] = []

    def work(job: tuple[str, int]) -> OpenPort | None:
        return _probe_port(*job, timeout) if should_continue() else None

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(jobs)))) as pool:
        for result in pool.map(work, jobs):
            if result is not None:
                found.append(result)
                if on_open:
                    on_open(result)
    return found
