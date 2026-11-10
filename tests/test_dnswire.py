"""DNS wire-format encoding and parsing, including hostile packets."""

from __future__ import annotations

import struct

import pytest

from netintel.core.dnswire import (
    DnsError,
    RecordType,
    build_query,
    decode_name,
    encode_name,
    parse_response,
)


def _response(qid: int, answers: list[tuple[int, bytes]], *, flags: int = 0x8180) -> bytes:
    """A response for example.com whose answers point back at the question name."""
    question = encode_name("example.com") + struct.pack("!HH", 1, 1)
    body = bytearray(struct.pack("!HHHHHH", qid, flags, 1, len(answers), 0, 0) + question)
    for rtype, rdata in answers:
        body += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 300, len(rdata)) + rdata
    return bytes(body)


def test_encode_name_uses_length_prefixed_labels():
    assert encode_name("example.com") == b"\x07example\x03com\x00"
    assert encode_name("example.com.") == encode_name("example.com")


def test_encode_rejects_oversized_labels():
    with pytest.raises(DnsError):
        encode_name("a" * 64 + ".com")


def test_query_header_sets_recursion_desired():
    packet = build_query("example.com", RecordType.MX, query_id=0x1234)
    qid, flags, qd, an, _, _ = struct.unpack_from("!HHHHHH", packet)
    assert (qid, flags, qd, an) == (0x1234, 0x0100, 1, 0)
    assert packet.endswith(struct.pack("!HH", 15, 1))


def test_parses_a_aaaa_mx_and_split_txt():
    mx = struct.pack("!H", 10) + encode_name("mail.example.com")
    txt = b"\x05v=spf" + b"\x05 -all"  # two strings, concatenated by readers
    data = _response(
        7,
        [
            (RecordType.A, bytes([93, 184, 216, 34])),
            (RecordType.AAAA, bytes(15) + b"\x01"),
            (RecordType.MX, mx),
            (RecordType.TXT, txt),
        ],
    )
    response = parse_response(data, expected_id=7)
    values = [(r.type_name, r.value) for r in response.answers]
    assert values == [
        ("A", "93.184.216.34"),
        ("AAAA", "::1"),
        ("MX", "10 mail.example.com"),
        ("TXT", "v=spf -all"),
    ]
    assert all(r.name == "example.com" for r in response.answers)


def test_null_mx_is_rendered_as_root():
    data = _response(1, [(RecordType.MX, b"\x00\x00\x00")])
    assert parse_response(data).answers[0].value == "0 ."


def test_mismatched_id_is_rejected_as_possible_spoofing():
    with pytest.raises(DnsError, match="spoofing"):
        parse_response(_response(1, []), expected_id=2)


def test_rcode_and_truncation_flags_are_exposed():
    response = parse_response(_response(1, [], flags=0x8383))
    assert response.rcode_name == "NXDOMAIN"
    assert response.truncated


def test_compression_loop_cannot_hang_the_parser():
    # A pointer at offset 12 that points at itself.
    data = struct.pack("!HHHHHH", 1, 0x8180, 0, 0, 0, 0) + b"\xc0\x0c"
    with pytest.raises(DnsError, match="backwards"):
        decode_name(data, 12)


def test_truncated_packets_raise_instead_of_index_errors():
    full = _response(1, [(RecordType.A, bytes(4))])
    for cut in (5, 20, len(full) - 2):
        with pytest.raises(DnsError):
            parse_response(full[:cut])


def test_short_mx_rdata_is_a_dns_error_not_a_struct_error():
    with pytest.raises(DnsError, match="malformed"):
        parse_response(_response(1, [(RecordType.MX, b"\x00")]))
