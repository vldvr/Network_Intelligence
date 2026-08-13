# NetworkIntelligence

A network diagnostics toolkit: traceroute with per-hop latency, IP geolocation,
host discovery and packet capture — as a scriptable CLI and a Qt desktop app
over one shared engine.

```console
$ netintel trace example.com
traceroute to example.com, max 30 hops
 1  _gateway (192.168.1.1)  1.42 ms  1.38 ms  1.51 ms
 2  10.64.0.1  8.90 ms  9.12 ms  8.77 ms
 3  * * *
 4  ae-11.edge2.London.example.net (203.0.113.9)  12.04 ms  11.88 ms  24.31 ms  (33% loss)
 5  93.184.216.34  12.51 ms  12.44 ms  12.60 ms
destination reached in 5 hops

$ netintel --json geo 1.1.1.1 | jq -r '.[].location.country'
Australia

$ netintel discover 192.168.1.0/24 --backend tcp
```

## Why it is built this way

The domain logic does not know that a GUI exists, and it does not know which
library puts packets on the wire. It depends on the protocols in
[`netintel/ports.py`](netintel/ports.py); the concrete scapy, nmap and HTTP
implementations live in [`netintel/adapters/`](netintel/adapters/) and are
selected in one composition root.

That buys three concrete things:

- **The test suite runs anywhere.** 233 tests, about two seconds, no root, no
  network, no nmap, no PyQt5 — every backend is replaced by an in-memory fake
  at the port boundary. CI installs the package with *no* optional
  dependencies and the suite still passes.
- **The CLI and the GUI cannot drift.** Both call the same services and render
  the same result models. A fix to traceroute logic reaches both.
- **The tool degrades instead of failing.** No nmap installed? Discovery falls
  back to a built-in TCP connect sweep that needs neither root nor an external
  binary. No PyQt5? The CLI is unaffected.

Layering is enforced by [`tests/test_layering.py`](tests/test_layering.py)
rather than by convention: it fails the build if `core` imports Qt or a
backend library, if anything below the UI imports the UI, or if an adapter
imports its heavy dependency at module scope.

For the design in detail, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Install

```bash
pip install -e .            # core only — no dependencies at all
pip install -e ".[all]"     # everything: geolocation, capture, nmap, GUI
```

Extras are separate so you install what you will use: `geo` (requests),
`capture` (scapy), `nmap` (python-nmap plus the nmap binary), `gui` (PyQt5).

Traceroute and packet capture need raw sockets. Rather than telling everyone to
run the whole application as root:

```bash
# Linux — grant the capability once
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(which python3)")"

# macOS — the Wireshark installer's ChmodBPF helper does the equivalent
```

The GUI shows the current privilege state in its status bar, so this is visible
before you press a button rather than after a failure.

## Usage

```bash
netintel trace example.com --probes 5 --geo
netintel geo 1.1.1.1 8.8.8.8 --near 51.5074,-0.1278
netintel discover 192.168.1.0/24 --geo
netintel capture -i eth0 --protocol tcp --dst-port 443 -c 100
netintel scope                       # what am I authorised to scan?
netintel <command> --json            # machine-readable output, for any command
netintel-gui                         # the desktop app
```

`--print-filter` shows the BPF expression a capture filter compiles to without
capturing anything.

## Authorised scope

Active scanning is confined to private address space by default. Pointing it at
anything else takes a deliberate act:

```bash
netintel discover 203.0.113.0/24 --authorized-scope 203.0.113.0/24
```

or a `netintel-scope.json` in the working directory (see
[`netintel-scope.json.example`](netintel-scope.json.example)), which also
records *why* the scope exists:

```json
{
  "note": "engagement ACME-2026-03, authorised by ACME IT until 2026-04-01",
  "authorized_prefixes": ["203.0.113.0/24"],
  "max_hosts": 1024
}
```

The check runs before a single packet is sent, and a range expanding past the
host limit is refused outright. Unauthorised port scanning is a criminal
offence in many jurisdictions; the default being the safe one is not a
formality.

Note that "private" here means an explicit prefix list, not Python's
`ipaddress.is_private` — that predicate also covers carrier-grade NAT
(100.64.0.0/10), which reaches other people's devices.

Packet capture records headers only. Payloads are never decoded, displayed or
stored.

## Development

```bash
pip install -e ".[dev]"
pytest --cov          # 233 tests, ~2s, 89% coverage
ruff check netintel tests && ruff format --check netintel tests
mypy                  # strict
```

CI runs the suite on Linux, macOS and Windows against Python 3.11 and 3.12,
plus lint, strict type checking, and a smoke job that installs the package with
no extras and asserts that scanning outside the authorised scope fails closed.

## Layout

```
netintel/
  models.py        frozen result types shared by every layer
  ports.py         the protocols core depends on
  core/            traceroute, geoip, discovery, capture, scope, targets
  adapters/        scapy, nmap, requests, TCP-connect, system DNS
  cli/             argparse front end, text or JSON
  ui/              PyQt5 front end (presentation only)
```

## Licence

MIT.
