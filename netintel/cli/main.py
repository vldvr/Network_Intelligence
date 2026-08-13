"""``netintel`` command-line interface.

A CLI is not decoration here. It is what makes the toolkit scriptable, what
lets CI exercise the real code paths, and what lets someone evaluate the
project without installing a GUI stack. Every command can emit JSON, so the
output composes with ``jq`` and with whatever runs next.

Exit codes follow the usual convention: ``0`` success, ``1`` a handled
failure, ``2`` a usage error, ``130`` interrupted.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
from collections.abc import Callable, Sequence
from typing import Any, TextIO

from netintel import __version__
from netintel.adapters.factory import (
    build_discovery_backend,
    build_geoip_provider,
    build_packet_source,
    build_probe_sender,
    build_resolver,
)
from netintel.cancellation import CancellationToken
from netintel.core.capture import CaptureSession, compile_bpf, format_packet
from netintel.core.discovery import (
    DiscoveryConfig,
    DiscoveryService,
    GeoFilter,
    format_report,
)
from netintel.core.geoip import haversine_km
from netintel.core.scope import ScopePolicy
from netintel.core.targets import is_hostname, parse_address
from netintel.core.traceroute import TraceConfig, Tracer, format_trace
from netintel.errors import NetIntelError
from netintel.models import CaptureFilter, GeoLocation, Protocol, to_json

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netintel",
        description="Network diagnostics: traceroute, geolocation, host discovery, capture.",
        epilog=(
            "Active scanning is restricted to private address space unless an "
            "authorised scope is supplied. See `netintel scope --help`."
        ),
    )
    parser.add_argument("--version", action="version", version=f"netintel {__version__}")
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON instead of formatted text",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="never contact the geolocation provider",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)
    _add_trace_parser(subparsers)
    _add_geo_parser(subparsers)
    _add_discover_parser(subparsers)
    _add_capture_parser(subparsers)
    _add_scope_parser(subparsers)
    return parser


def _add_trace_parser(subparsers: Any) -> None:
    trace = subparsers.add_parser(
        "trace", help="trace the network path to a host (needs raw-socket privileges)"
    )
    trace.add_argument("destination", help="hostname or IP address")
    trace.add_argument("--max-hops", type=int, default=30)
    trace.add_argument("--probes", type=int, default=3, help="probes per hop (default: 3)")
    trace.add_argument("--timeout", type=float, default=2.0, help="seconds per probe")
    trace.add_argument("--no-resolve", action="store_true", help="skip reverse DNS lookups")
    trace.add_argument("--geo", action="store_true", help="annotate each hop with its location")
    trace.add_argument("--interface", help="interface to send probes from")
    trace.set_defaults(handler=_cmd_trace)


def _add_geo_parser(subparsers: Any) -> None:
    geo = subparsers.add_parser("geo", help="locate one or more IP addresses or hosts")
    geo.add_argument("targets", nargs="+", help="hostnames or IP addresses")
    geo.add_argument(
        "--near",
        metavar="LAT,LON",
        help="also report the distance from this point",
    )
    geo.set_defaults(handler=_cmd_geo)


def _add_discover_parser(subparsers: Any) -> None:
    discover = subparsers.add_parser("discover", help="find live hosts in an address range")
    discover.add_argument(
        "targets", help="e.g. 192.168.1.0/24, 10.0.0.5-40, or a comma-separated list"
    )
    discover.add_argument("--timeout", type=float, default=1.0, help="seconds per host")
    discover.add_argument(
        "--backend",
        choices=("auto", "nmap", "tcp"),
        default="auto",
        help="discovery backend (default: auto)",
    )
    discover.add_argument("--geo", action="store_true", help="geolocate the hosts that respond")
    discover.add_argument("--near", metavar="LAT,LON", help="keep only hosts near this point")
    discover.add_argument(
        "--radius", type=float, metavar="KM", help="radius for --near, in kilometres"
    )
    discover.add_argument(
        "--authorized-scope",
        metavar="PREFIX",
        action="append",
        default=[],
        help=(
            "a prefix you are authorised to scan; repeatable. Required for any "
            "target outside private address space."
        ),
    )
    discover.add_argument(
        "--scope-file", help="path to a scope file (default: ./netintel-scope.json)"
    )
    discover.add_argument("--max-hosts", type=int, default=4096)
    discover.set_defaults(handler=_cmd_discover)


def _add_capture_parser(subparsers: Any) -> None:
    capture = subparsers.add_parser(
        "capture", help="capture packets on an interface (needs raw-socket privileges)"
    )
    capture.add_argument("--interface", "-i", help="interface name")
    capture.add_argument("--list-interfaces", action="store_true", help="list interfaces and exit")
    capture.add_argument(
        "--protocol",
        choices=[p.value for p in Protocol if p is not Protocol.OTHER],
    )
    capture.add_argument("--src-ip")
    capture.add_argument("--dst-ip")
    capture.add_argument("--src-port", type=int)
    capture.add_argument("--dst-port", type=int)
    capture.add_argument("--src-mac")
    capture.add_argument("--dst-mac")
    capture.add_argument("--count", "-c", type=int, help="stop after this many packets")
    capture.add_argument(
        "--print-filter",
        action="store_true",
        help="print the compiled BPF expression and exit",
    )
    capture.set_defaults(handler=_cmd_capture)


def _add_scope_parser(subparsers: Any) -> None:
    scope = subparsers.add_parser("scope", help="show the authorised scanning scope in effect")
    scope.add_argument("--scope-file", help="path to a scope file")
    scope.set_defaults(handler=_cmd_scope)


def _cmd_trace(args: argparse.Namespace, out: TextIO, token: CancellationToken) -> int:
    config = TraceConfig(
        max_hops=args.max_hops,
        probes_per_hop=args.probes,
        timeout_s=args.timeout,
        resolve_names=not args.no_resolve,
        geolocate=args.geo,
    ).validated()

    tracer = Tracer(
        build_probe_sender(interface=args.interface),
        build_resolver(enabled=not args.no_resolve),
        geoip=build_geoip_provider(offline=args.offline) if args.geo else None,
        config=config,
    )

    # Stream hops to a terminal, but not to a JSON consumer: interleaving
    # progress with the document would make the output unparseable.
    on_hop = None
    if not args.json:
        from netintel.core.traceroute import format_hop

        def on_hop(hop: Any) -> None:
            print(format_hop(hop), file=out, flush=True)

        print(f"traceroute to {args.destination}, max {config.max_hops} hops", file=out)

    result = tracer.trace(args.destination, token=token, on_hop=on_hop)

    if args.json:
        _dump(result, out)
    else:
        print(format_trace(result).splitlines()[-1], file=out)
    return EXIT_OK


def _cmd_geo(args: argparse.Namespace, out: TextIO, token: CancellationToken) -> int:
    resolver = build_resolver()
    provider = build_geoip_provider(offline=args.offline)
    origin = _parse_point(args.near) if args.near else None

    addresses = [
        resolver.resolve(target) if is_hostname(target) else str(parse_address(target))
        for target in args.targets
    ]
    located = provider.lookup_many(addresses, token=token)

    if args.json:
        payload = [
            {
                "target": target,
                "ip": ip,
                "location": to_json(located.get(ip)),
                "distance_km": _distance_km(origin, located.get(ip)),
            }
            for target, ip in zip(args.targets, addresses, strict=True)
        ]
        _dump(payload, out)
        return EXIT_OK

    for target, ip in zip(args.targets, addresses, strict=True):
        location = located.get(ip)
        if location is None:
            print(f"{target} ({ip}): no location available", file=out)
            continue
        line = (
            f"{target} ({ip}): {location.describe()} "
            f"[{location.latitude:.4f}, {location.longitude:.4f}]"
        )
        if location.autonomous_system:
            line += f" — {location.autonomous_system}"
        if origin:
            line += f" — {haversine_km(origin, location.coordinates):.0f} km away"
        print(line, file=out)
        if location.is_hosting or location.is_proxy:
            print(
                "  note: datacentre or proxy address; the coordinates describe "
                "the hosting facility, not a user",
                file=out,
            )
    return EXIT_OK


def _cmd_discover(args: argparse.Namespace, out: TextIO, token: CancellationToken) -> int:
    if args.authorized_scope:
        policy = ScopePolicy.from_prefixes(
            args.authorized_scope, note="scope supplied on the command line"
        )
    else:
        policy = ScopePolicy.load(args.scope_file)

    geo_filter = None
    if args.near or args.radius is not None:
        if not (args.near and args.radius is not None):
            raise NetIntelError("--near and --radius must be used together")
        latitude, longitude = _parse_point(args.near)
        geo_filter = GeoFilter(latitude, longitude, args.radius).validated()

    service = DiscoveryService(
        build_discovery_backend(prefer=args.backend),
        policy=policy,
        geoip=build_geoip_provider(offline=args.offline),
    )
    config = DiscoveryConfig(
        timeout_s=args.timeout,
        max_hosts=args.max_hosts,
        geolocate=args.geo,
        geo_filter=geo_filter,
    )

    on_host = None
    if not args.json:

        def on_host(host: Any) -> None:
            print(f"  up: {host.ip}", file=out, flush=True)

    report = service.discover(args.targets, config=config, token=token, on_host=on_host)

    if args.json:
        _dump(report, out)
    else:
        print(format_report(report), file=out)
    return EXIT_OK


def _cmd_capture(args: argparse.Namespace, out: TextIO, token: CancellationToken) -> int:
    criteria = CaptureFilter(
        protocol=Protocol(args.protocol) if args.protocol else None,
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        src_port=args.src_port,
        dst_port=args.dst_port,
        src_mac=args.src_mac,
        dst_mac=args.dst_mac,
    )

    if args.print_filter:
        print(compile_bpf(criteria) or "(no filter — capture everything)", file=out)
        return EXIT_OK

    source = build_packet_source()
    if args.list_interfaces:
        for name in source.interfaces():
            print(name, file=out)
        return EXIT_OK

    interface = args.interface
    if not interface:
        available = source.interfaces()
        raise NetIntelError(
            "specify an interface with --interface. Available: " + ", ".join(available)
        )

    session = CaptureSession(
        source=source,
        interface=interface,
        criteria=criteria,
        max_packets=args.count,
    )

    records = []
    for packet in session.stream(token=token):
        if args.json:
            records.append(packet)
        else:
            print(format_packet(packet), file=out, flush=True)

    if args.json:
        _dump({"stats": session.stats, "packets": records}, out)
    else:
        stats = session.stats
        print(
            f"\n{stats.captured} packet(s), {stats.bytes_seen} bytes captured",
            file=out,
        )
    return EXIT_OK


def _cmd_scope(args: argparse.Namespace, out: TextIO, token: CancellationToken) -> int:
    policy = ScopePolicy.load(args.scope_file)
    if args.json:
        _dump(
            {
                "note": policy.note,
                "allow_public": policy.allow_public,
                "max_hosts": policy.max_hosts,
                "allowed": [str(network) for network in policy.allowed],
            },
            out,
        )
    else:
        print(policy.describe(), file=out)
    return EXIT_OK


def _distance_km(origin: tuple[float, float] | None, location: GeoLocation | None) -> float | None:
    """Distance from ``origin``, or ``None`` when either end is unknown."""
    if origin is None or location is None:
        return None
    return haversine_km(origin, location.coordinates)


def _parse_point(text: str) -> tuple[float, float]:
    parts = text.split(",")
    if len(parts) != 2:
        raise NetIntelError("a coordinate must look like 51.5074,-0.1278")
    try:
        return (float(parts[0]), float(parts[1]))
    except ValueError as exc:
        raise NetIntelError(f"{text!r} is not a valid coordinate") from exc


def _dump(payload: Any, out: TextIO) -> None:
    json.dump(to_json(payload), out, indent=2, default=str)
    out.write("\n")


def main(argv: Sequence[str] | None = None, *, out: TextIO | None = None) -> int:
    """Entry point. Returns an exit code rather than calling ``sys.exit``.

    Keeping the process exit at the boundary is what makes the whole CLI
    callable from a test without spawning a subprocess.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    stream = out or sys.stdout
    token = CancellationToken()

    previous = _install_sigint_handler(token)
    try:
        handler: Callable[..., int] = args.handler
        return handler(args, stream, token)
    except NetIntelError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:  # pragma: no cover - interactive path
        print("\ninterrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    finally:
        if previous is not None:
            signal.signal(signal.SIGINT, previous)


def _install_sigint_handler(token: CancellationToken) -> Any:
    """Turn the first Ctrl-C into a clean cancellation.

    A capture or a scan holds a raw socket and worker threads; being torn down
    mid-syscall leaves the terminal and the interface in a worse state than
    unwinding does. A second Ctrl-C still hard-aborts, because a stuck process
    that ignores the user is its own kind of bug.
    """
    try:

        def handle(signum: int, frame: Any) -> None:
            token.cancel()
            signal.signal(signal.SIGINT, signal.default_int_handler)

        return signal.signal(signal.SIGINT, handle)
    except ValueError:  # pragma: no cover - not on the main thread
        return None


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
