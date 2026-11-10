"""DNS wire format (RFC 1035), encoded and decoded by hand.

The standard library can resolve a name to an address and nothing more: no
MX, no TXT, no NS. Instead of depending on dnspython, this module builds
query packets and parses responses itself, including name compression —
the pointer scheme that lets a response refer back to an earlier name. A
malicious or broken response must not be able to loop the parser forever,
so pointers are only allowed to jump backwards and the jump count is capped.

Pure functions only; sending the bytes is an adapter's job.
"""

from __future__ import annotations

import ipaddress
import secrets
import struct
from dataclasses import dataclass
from enum import IntEnum

from netintel.errors import NetIntelError


class DnsError(NetIntelError):
    """A response could not be parsed, or the server reported an error."""


class RecordType(IntEnum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    MX = 15
    TXT = 16
    AAAA = 28
    CAA = 257


RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

_MAX_POINTER_JUMPS = 32


@dataclass(frozen=True, slots=True)
class DnsRecord:
    name: str
    rtype: int
    ttl: int
    value: str

    @property
    def type_name(self) -> str:
        try:
            return RecordType(self.rtype).name
        except ValueError:
            return f"TYPE{self.rtype}"

    def to_json(self) -> dict[str, object]:
        return {"name": self.name, "type": self.type_name, "ttl": self.ttl, "value": self.value}


@dataclass(frozen=True, slots=True)
class DnsResponse:
    query_id: int
    rcode: int
    truncated: bool
    answers: tuple[DnsRecord, ...]

    @property
    def rcode_name(self) -> str:
        return RCODES.get(self.rcode, f"RCODE{self.rcode}")


def encode_name(name: str) -> bytes:
    """Encode ``example.com`` as length-prefixed labels."""
    name = name.rstrip(".")
    out = bytearray()
    if name:
        for label in name.split("."):
            try:
                raw = label.encode("idna")
            except UnicodeError as exc:
                raise DnsError(f"invalid label {label!r} in {name!r}") from exc
            if not 0 < len(raw) <= 63:
                raise DnsError(f"invalid label {label!r} in {name!r}")
            out.append(len(raw))
            out += raw
    out.append(0)
    if len(out) > 255:
        raise DnsError(f"name too long: {name!r}")
    return bytes(out)


def build_query(name: str, rtype: int, *, query_id: int | None = None) -> bytes:
    """A standard recursive query for one question."""
    qid = secrets.randbelow(0x10000) if query_id is None else query_id
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD=1
    return header + encode_name(name) + struct.pack("!HH", rtype, 1)


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read a possibly-compressed name; return it and the offset after it."""
    labels: list[str] = []
    jumps = 0
    end: int | None = None
    pos = offset
    while True:
        if pos >= len(data):
            raise DnsError("name runs past the end of the packet")
        length = data[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise DnsError("truncated compression pointer")
            target = ((length & 0x3F) << 8) | data[pos + 1]
            if target >= pos:
                raise DnsError("compression pointer does not point backwards")
            jumps += 1
            if jumps > _MAX_POINTER_JUMPS:
                raise DnsError("too many compression pointers")
            if end is None:
                end = pos + 2
            pos = target
            continue
        if length & 0xC0:
            raise DnsError("unsupported label type")
        pos += 1
        if length == 0:
            break
        if pos + length > len(data):
            raise DnsError("label runs past the end of the packet")
        labels.append(data[pos : pos + length].decode("ascii", errors="replace"))
        pos += length
    return ".".join(labels), (end if end is not None else pos)


def _decode_rdata(data: bytes, rtype: int, start: int, length: int) -> str:
    rdata = data[start : start + length]
    if rtype == RecordType.A and length == 4:
        return str(ipaddress.IPv4Address(rdata))
    if rtype == RecordType.AAAA and length == 16:
        return str(ipaddress.IPv6Address(rdata))
    if rtype in (RecordType.NS, RecordType.CNAME):
        return decode_name(data, start)[0]
    if rtype == RecordType.MX:
        (preference,) = struct.unpack_from("!H", data, start)
        return f"{preference} {decode_name(data, start + 2)[0] or '.'}"
    if rtype == RecordType.TXT:
        # A TXT record is one or more <length><bytes> strings that a reader
        # concatenates — long SPF records are routinely split this way.
        parts, pos = [], 0
        while pos < len(rdata):
            size = rdata[pos]
            parts.append(rdata[pos + 1 : pos + 1 + size].decode("utf-8", errors="replace"))
            pos += 1 + size
        return "".join(parts)
    if rtype == RecordType.SOA:
        mname, pos = decode_name(data, start)
        rname, pos = decode_name(data, pos)
        serial = struct.unpack_from("!I", data, pos)[0]
        return f"{mname} {rname} serial {serial}"
    if rtype == RecordType.CAA and length >= 2:
        flags, tag_len = rdata[0], rdata[1]
        tag = rdata[2 : 2 + tag_len].decode("ascii", errors="replace")
        value = rdata[2 + tag_len :].decode("utf-8", errors="replace")
        return f"{flags} {tag} {value}"
    return rdata.hex()


def parse_response(data: bytes, *, expected_id: int | None = None) -> DnsResponse:
    if len(data) < 12:
        raise DnsError("response shorter than a DNS header")
    qid, flags, qdcount, ancount, _ns, _ar = struct.unpack_from("!HHHHHH", data, 0)
    if expected_id is not None and qid != expected_id:
        raise DnsError("response id does not match the query (possible spoofing)")
    if not flags & 0x8000:
        raise DnsError("packet is a query, not a response")

    pos = 12
    for _ in range(qdcount):
        _, pos = decode_name(data, pos)
        pos += 4

    answers: list[DnsRecord] = []
    for _ in range(ancount):
        name, pos = decode_name(data, pos)
        if pos + 10 > len(data):
            raise DnsError("truncated resource record")
        rtype, _cls, ttl, rdlength = struct.unpack_from("!HHIH", data, pos)
        pos += 10
        if pos + rdlength > len(data):
            raise DnsError("record data runs past the end of the packet")
        answers.append(DnsRecord(name, rtype, ttl, _decode_rdata(data, rtype, pos, rdlength)))
        pos += rdlength

    return DnsResponse(
        query_id=qid,
        rcode=flags & 0x000F,
        truncated=bool(flags & 0x0200),
        answers=tuple(answers),
    )
