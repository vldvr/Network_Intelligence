# Architecture

## The shape

```
        ┌──────────────┐        ┌──────────────┐
        │ netintel.cli │        │ netintel.ui  │      front ends
        └──────┬───────┘        └──────┬───────┘
               │                       │
               └───────────┬───────────┘
                           ▼
                  ┌─────────────────┐
                  │  netintel.core  │                domain logic
                  │  traceroute     │                (pure Python)
                  │  discovery      │
                  │  capture        │
                  │  geoip · scope  │
                  └────────┬────────┘
                           │ depends on protocols, not libraries
                           ▼
                  ┌─────────────────┐
                  │ netintel.ports  │
                  └────────┬────────┘
                           ▲ implemented by
                  ┌────────┴────────┐
                  │netintel.adapters│                scapy · nmap · requests
                  │                 │                TCP connect · system DNS
                  └─────────────────┘
```

Dependencies point inwards. `core` imports `ports` and `models` and nothing
else; the adapters implement `ports`; the front ends compose them through
`adapters/factory.py`, the single composition root.

## Why a port/adapter split for a four-tab utility

It is not architecture for its own sake — it pays for itself in three places.

**Testability.** Every interesting behaviour in this tool involves the network,
privileges, or a third-party library. Faking those at a protocol boundary is
what makes 233 tests run in about two seconds with no root and no network. The
alternative — integration tests that need a lab — gets written once and then
skipped.

**Degradation.** `build_discovery_backend()` picks nmap when it is installed
and a built-in TCP connect sweep otherwise. The original tool could not start
without nmap on `PATH`.

**Two front ends, one behaviour.** The CLI is not a wrapper around the GUI or
vice versa. Both call the same services and render the same frozen result
models, so a fix lands in both at once.

## Concurrency

The single most serious defect in the original code was that worker threads
called Qt widget methods directly — `self.output_display.append(...)` from a
`threading.Thread`. Qt widgets may only be touched from the thread that owns
them; violating that is undefined behaviour that shows up as a corrupted
document, a hang, or a segfault, none of which reproduce on demand.

The rule now: **work happens in a worker, results arrive as signals.**

- `netintel/ui/workers.py` runs each operation as a `QRunnable` on a thread
  pool. A worker never holds a reference to a widget; it emits domain models
  through `WorkerSignals`, which Qt delivers on the UI thread.
- `WorkerHost` allows one in-flight worker per panel. The original re-enabled
  its Start button the instant Stop was pressed, so a second run could begin
  while the first thread was still writing into the same widget.
- Button state is restored in exactly one place — the `done` signal, which
  fires on success, failure and cancellation alike. No error path can leave a
  panel wedged.
- Capture pushes into a buffer that a 200 ms timer flushes into a table model
  in batches. Emitting `rowsInserted` per frame means one layout pass per
  packet, and the UI stops keeping up long before the capture does.

### Cancellation

`CancellationToken` wraps a `threading.Event` and is passed down the call
stack. Two properties matter:

- `wait(seconds)` returns early when cancelled, so Stop is immediate. Anything
  built on `time.sleep` makes the UI appear frozen for the length of the nap —
  and the original slept 1.5 s per host during geolocation.
- Backends receive `token.should_continue` as a plain callable, so nothing
  below `core` needs to know the token type.

`ScapyPacketSource` exists because `scapy.sniff()` only evaluates its
`stop_filter` when a packet arrives: on a quiet interface, Stop does nothing
until the next frame. `AsyncSniffer` plus a bounded queue makes stopping
immediate, and the generator's `finally` stops the sniffer even when the
consumer abandons it — otherwise a leaked raw socket and thread outlive the
capture.

## Data flow

`core` produces frozen dataclasses (`TraceResult`, `HostRecord`,
`PacketRecord`, `GeoLocation`). Workers emit *models*, never formatted strings;
formatting is a view concern, and a worker that emits text has already decided
what the result looks like. `models.to_json()` gives every front end the same
serialisation, so `--json` output and GUI tables cannot disagree.

`PacketRecord` deliberately does not wrap a live scapy packet: holding one
keeps whole buffers alive and couples the view to the capture backend.

## Safety properties

These are enforced in code, with tests, not documented as intentions.

| Property | Where | Test |
|---|---|---|
| Scanning is limited to declared scope, checked before any packet | `core/scope.py` | `tests/test_scope.py`, `test_discovery.py` |
| Targets are parsed into addresses before reaching a backend | `core/targets.py` | `tests/test_targets.py` |
| Capture filter values are validated before entering a BPF expression | `core/capture.py` | `tests/test_capture.py` |
| Provider responses are treated as untrusted input | `core/geoip.py` | `tests/test_geoip.py` |
| Buffers are bounded (capture ring, queue, output scrollback) | `core/capture.py`, `ui/` | `tests/test_capture.py` |
| `core` never imports Qt or a backend library | — | `tests/test_layering.py` |
| Payload bytes are never retained | `adapters/scapy_backend.py` | — |

Two details worth calling out:

*Local address space is an explicit prefix list*, not `ipaddress.is_private`.
That predicate also returns true for 100.64.0.0/10 (carrier-grade NAT) and the
documentation ranges — a guard built on it would quietly place a mobile
carrier's customers inside the default scanning scope.

*The BPF expression is an interpreted language.* Moving filtering from Python
into the kernel is a large performance win, and it means user input now reaches
a compiler. Every value is parsed as its actual type first: an IP as an IP, a
port as an integer in range, a MAC against a strict pattern.

## External API use

ip-api.com allows 45 requests per minute and blackholes the caller for an hour
after that. The original sent one request per host with `time.sleep(1.5)`
between them: geolocating a /24 was 254 requests and about six minutes.

- **Batched** — the batch endpoint takes 100 addresses per call. That /24 is
  now three requests.
- **Rate-limited** — a shared token bucket at 40/minute, below the documented
  ceiling. Bursts are allowed; blocking only happens when the budget is spent.
- **Cached** — a TTL cache keyed by address. Trace hops repeat, rescans repeat,
  and results are stable for hours.
- **Short-circuited** — private and reserved addresses are never sent at all.
  They have no meaningful geolocation, and the original printed an apology per
  host on every LAN scan.

The bucket and cache are process-wide, so a trace and a scan in one session
share both.

## Trade-offs and limits

- **IPv4-only probing.** Models and target parsing handle IPv6, but the
  traceroute sender is IPv4. The resolver prefers A records so the failure is
  a clear message rather than a confusing one further down.
- **ICMP-only traceroute.** No UDP or TCP probe modes, so paths that filter
  ICMP show as `*`. The trace gives up after five silent hops instead of
  walking all 30 TTLs.
- **The GUI has no automated tests.** The headless suite covers `core`, the
  adapters and the CLI; `netintel/ui` is excluded from coverage rather than
  papered over with a number. The logic worth testing was deliberately moved
  out of the widgets, which is what leaves the UI thin enough to check by hand.
- **GeoIP is inference, not measurement.** `GeoLocation` carries an
  `accuracy_note` and flags hosting and proxy addresses, and both front ends
  surface it. Presenting coordinates from a free GeoIP service as a fact is
  the most common way tools like this mislead people.
