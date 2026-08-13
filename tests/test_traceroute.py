"""Traceroute behaviour, driven entirely by a scripted probe sender."""

from __future__ import annotations

import pytest

from netintel.cancellation import CancellationToken
from netintel.core.traceroute import TraceConfig, Tracer, format_hop, format_trace
from netintel.errors import TargetError
from netintel.models import HopKind
from tests.conftest import FakeReply, FakeResolver, ScriptedProbeSender


def build_tracer(replies, **config_kwargs):
    config = TraceConfig(probes_per_hop=1, **config_kwargs)
    return Tracer(
        ScriptedProbeSender(replies),
        FakeResolver(forward={"example.com": "93.184.216.34"}),
        config=config,
    )


def test_trace_stops_at_the_destination():
    tracer = build_tracer(
        {
            1: FakeReply("10.0.0.1", 1.0),
            2: FakeReply("10.0.1.1", 5.0),
            3: FakeReply("93.184.216.34", 12.0, is_destination=True),
            4: FakeReply("10.9.9.9", 99.0),
        }
    )
    result = tracer.trace("93.184.216.34")

    assert result.reached is True
    assert len(result.hops) == 3, "must not probe past the destination"
    assert result.hops[-1].kind is HopKind.DESTINATION


def test_hostnames_are_resolved_before_probing():
    tracer = build_tracer({1: FakeReply("93.184.216.34", 3.0, is_destination=True)})
    result = tracer.trace("example.com")
    assert result.destination_ip == "93.184.216.34"


def test_unresolvable_hostname_raises_a_domain_error():
    tracer = build_tracer({})
    with pytest.raises(TargetError):
        tracer.trace("nope.invalid")


def test_timeouts_are_recorded_as_silent_hops():
    tracer = build_tracer({1: FakeReply("10.0.0.1", 1.0), 3: None}, max_hops=3)
    result = tracer.trace("10.0.0.9")
    assert [hop.kind for hop in result.hops] == [
        HopKind.ROUTER,
        HopKind.TIMEOUT,
        HopKind.TIMEOUT,
    ]


def test_trace_gives_up_after_a_run_of_silent_hops():
    """The original walked all 30 TTLs against a firewall that drops ICMP."""
    tracer = build_tracer({}, max_hops=30, give_up_after_silent_hops=4)
    result = tracer.trace("10.0.0.9")
    assert len(result.hops) == 4
    assert result.completed is False


def test_unreachable_reply_terminates_the_trace():
    tracer = build_tracer(
        {1: FakeReply("10.0.0.1", 1.0), 2: FakeReply("10.0.0.2", 2.0, is_unreachable=True)},
        max_hops=10,
    )
    result = tracer.trace("10.0.0.9")
    assert result.hops[-1].kind is HopKind.UNREACHABLE
    assert result.reached is False
    assert result.completed is True


def test_rtts_are_aggregated_across_probes():
    sender = ScriptedProbeSender({1: FakeReply("10.0.0.1", 4.0)})
    tracer = Tracer(sender, FakeResolver(), config=TraceConfig(probes_per_hop=3, max_hops=1))
    hop = tracer.trace("10.0.0.9").hops[0]

    assert hop.sent == 3
    assert hop.received == 3
    assert hop.avg_ms == pytest.approx(4.0)
    assert hop.loss_pct == 0.0


def test_partial_loss_is_reported():
    class Flaky(ScriptedProbeSender):
        def send_probe(self, destination_ip, ttl, *, timeout, sequence):
            super().send_probe(destination_ip, ttl, timeout=timeout, sequence=sequence)
            return FakeReply("10.0.0.1", 3.0) if sequence == 0 else None

    tracer = Tracer(Flaky({}), FakeResolver(), config=TraceConfig(probes_per_hop=3, max_hops=1))
    hop = tracer.trace("10.0.0.9").hops[0]
    assert hop.loss_pct == pytest.approx(66.7, abs=0.1)


def test_first_responder_wins_under_ecmp():
    """Later probes for one TTL can come from a different router."""

    class Alternating(ScriptedProbeSender):
        def send_probe(self, destination_ip, ttl, *, timeout, sequence):
            return FakeReply(f"10.0.0.{sequence + 1}", 1.0)

    tracer = Tracer(
        Alternating({}), FakeResolver(), config=TraceConfig(probes_per_hop=3, max_hops=1)
    )
    assert tracer.trace("10.0.0.9").hops[0].address == "10.0.0.1"


def test_probe_sequence_numbers_are_unique_per_probe():
    sender = ScriptedProbeSender({})
    tracer = Tracer(sender, FakeResolver(), config=TraceConfig(probes_per_hop=2, max_hops=2))
    tracer.trace("10.0.0.9")
    assert sender.sent == [
        ("10.0.0.9", 1, 0),
        ("10.0.0.9", 1, 1),
        ("10.0.0.9", 2, 0),
        ("10.0.0.9", 2, 1),
    ]


def test_reverse_lookups_are_cached_across_hops():
    class CountingResolver(FakeResolver):
        def __init__(self):
            super().__init__(reverse={"10.0.0.1": "gw.example"})
            self.calls = 0

        def reverse(self, ip):
            self.calls += 1
            return super().reverse(ip)

    resolver = CountingResolver()
    tracer = Tracer(
        ScriptedProbeSender({1: FakeReply("10.0.0.1", 1.0), 2: FakeReply("10.0.0.1", 1.0)}),
        resolver,
        config=TraceConfig(probes_per_hop=1, max_hops=2),
    )
    tracer.trace("10.0.0.9")
    assert resolver.calls == 1


def test_name_resolution_can_be_disabled():
    tracer = Tracer(
        ScriptedProbeSender({1: FakeReply("10.0.0.1", 1.0)}),
        FakeResolver(reverse={"10.0.0.1": "gw.example"}),
        config=TraceConfig(probes_per_hop=1, max_hops=1, resolve_names=False),
    )
    assert tracer.trace("10.0.0.9").hops[0].hostname is None


def test_cancellation_stops_the_trace_promptly():
    token = CancellationToken()

    class CancellingSender(ScriptedProbeSender):
        def send_probe(self, destination_ip, ttl, *, timeout, sequence):
            super().send_probe(destination_ip, ttl, timeout=timeout, sequence=sequence)
            if ttl == 2:
                token.cancel()
            return FakeReply("10.0.0.1", 1.0)

    tracer = Tracer(
        CancellingSender({}), FakeResolver(), config=TraceConfig(probes_per_hop=1, max_hops=30)
    )
    result = tracer.trace("10.0.0.9", token=token)
    assert len(result.hops) == 2
    assert result.completed is False


def test_hops_stream_to_the_callback_as_they_complete():
    seen = []
    tracer = build_tracer(
        {1: FakeReply("10.0.0.1", 1.0), 2: FakeReply("10.0.0.2", 2.0)}, max_hops=2
    )
    result = tracer.trace("10.0.0.9", on_hop=seen.append)
    assert [hop.ttl for hop in seen] == [1, 2]
    assert len(seen) == len(result.hops)


@pytest.mark.parametrize(
    "kwargs", [{"max_hops": 0}, {"max_hops": 300}, {"probes_per_hop": 0}, {"timeout_s": 0.0}]
)
def test_invalid_configuration_is_rejected(kwargs):
    with pytest.raises(TargetError):
        TraceConfig(**kwargs).validated()


def test_formatting_shows_timeouts_and_rtt():
    tracer = build_tracer({1: FakeReply("10.0.0.1", 1.5), 2: None}, max_hops=2)
    text = format_trace(tracer.trace("10.0.0.9"))
    assert "1.50 ms" in text
    assert "* * *" in text


def test_hop_jitter_is_the_mean_consecutive_delta():
    from netintel.models import Hop

    hop = Hop(ttl=1, kind=HopKind.ROUTER, address="10.0.0.1", rtts_ms=(10.0, 14.0, 12.0), sent=3)
    assert hop.jitter_ms == pytest.approx(3.0)
    assert format_hop(hop).startswith(" 1  10.0.0.1")
