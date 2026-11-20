# ADR-0015: Connection limits and idle timeouts

- Status: Accepted (2026-11-20)
- Date: 2026-11-20
- Deciders: @mogeko
- Related: ADR-0001, ADR-0003, ADR-0008, ADR-0012

## Context

`Instance` currently accepts TCP connections without a cap, and `relay` has no
post-handshake idle timeout. A peer can therefore hold file descriptors,
per-connection buffers, and relay tasks indefinitely with a silent connection
or a slow handshake. The fixed 10-second TLS handshake timeout covers only TLS;
SOCKS5, HTTP, Shadowsocks, Trojan, and VLESS protocol handshakes have no
deadline. The security audit records this as F-13/F-14/F-17.

Per-connection memory is not uniform: a plain TCP stream is small, while TLS,
HTTP/2, and WebSocket adapters reserve bounded but larger buffers before
authentication completes. The library cannot rely on an external supervisor to
enforce limits and must remain usable from a single-threaded embedder with only
`std.Io`.

The decision must define:

- how many TCP connections an `Instance` may own;
- when a handshake deadline applies and when it ends;
- what "idle" means for a duplex relay and for UDP sessions;
- how the limits are configured and observed;
- how expiry terminates work without leaking tasks or racing `close`.

## Reference behavior

Checked on 2026-11-20 against Xray-core 26.11.9, v2ray-core documentation,
sing-box source/docs, mihomo documentation, nginx, Envoy, and HAProxy.

- Xray/v2ray use a per-level policy with `handshake`, `connIdle`,
  `uplinkOnly`, and `downlinkOnly`. Xray's source default is 60s / 300s / 1s /
  1s; v2ray's documentation default is 4s / 300s / 2s / 5s. `connIdle` covers
  traffic in either direction, while the half-close timers are separate.
- A local Xray 26.11.9 experiment with 1s/2s/1s/1s measured idle close at
  2.01s, half-close close at 1.00s, and activity at 0.8s intervals kept the
  relay open. A completely silent connection that had not started the protocol
  handshake did not hit the 1s handshake timer before the 10s client timeout;
  a partial SOCKS greeting did close at 1.00s.
- sing-box exposes per-inbound `udp_timeout` (default 5m) and transport-level
  `idle_timeout`; no global TCP inbound connection cap was found.
- mihomo's `max-connections`/`min-streams`/`max-streams` are outbound
  multiplexing controls; TUIC/AnyTLS have protocol-level idle times. No global
  TCP inbound cap was found.
- nginx stream uses `proxy_timeout` (default 10m) between successive reads or
  writes; `worker_connections`/`max_conns` provide connection caps. Envoy TCP
  proxy `idle_timeout` defaults to 1h and its connection-limit filter provides
  a per-filter-chain `max_connections`. HAProxy exposes global/per-frontend
  `maxconn` and separate client/server timeouts.

Marmo chooses a library-level safety floor (global cap plus timeouts), starts
the handshake deadline at accept (stricter than Xray's observed behavior), and
adopts Xray's separate half-close grace timers.

## Decision

Add one global `limits` policy to `Config`, enforced by `Instance` and the
relay. It is one policy because the limits share lifecycle, configuration, and
metrics; individual values remain independent.

```json
{
  "limits": {
    "max_connections": 1024,
    "handshake_timeout_s": 10,
    "idle_timeout_s": 300,
    "uplink_only_s": 1,
    "downlink_only_s": 1
  }
}
```

All fields are optional. Defaults are `max_connections = 1024`,
`handshake_timeout_s = 10`, `idle_timeout_s = 300`, `uplink_only_s = 1`, and
`downlink_only_s = 1`.

### Validation and bounds

- `max_connections`: integer `0..65535`; `0` rejects every new TCP connection.
  This is useful for maintenance and is not an error.
- `handshake_timeout_s`: integer `1..600`; `0` is invalid, matching the
  existing per-inbound TLS rule.
- `idle_timeout_s`: integer `0..86400`; `0` disables the relay/UDP idle timer.
- `uplink_only_s` / `downlink_only_s`: integer `0..86400`; `0` closes the
  remaining direction immediately after the peer half-closes. These are
  absolute grace periods, not activity-extended timers.
- Unknown fields remain errors under the strict JSON policy.
- Per-inbound/per-outbound overrides are not part of this decision.

### Connection accounting

- One atomic counter per `Instance` counts accepted TCP streams from successful
  `accept` until the connection handler releases them. It includes TLS and
  protocol handshakes, relay, and connections waiting in a handshake.
- The accept loop reserves a slot before spawning the handler. If the counter
  is at the limit, the accepted socket is closed immediately, no task is
  spawned, and `connections_rejected` is incremented. There is no queue and no
  blocking accept.
- Reserve/release is balanced on every path, including TLS failure, routing
  rejection, spawn failure, and cancellation.
- UDP session tables keep their existing protocol-specific caps; this ADR does
  not fold UDP sessions into `max_connections`.

### Handshake deadline

- A per-connection deadline starts immediately after accept.
- It covers TLS (the earlier of this deadline and the existing per-inbound TLS
  timeout applies) and the protocol handshake through the point where routing
  selects an outbound and the connection enters the relay.
- The inbound handler marks the transition to "relay" explicitly. The deadline
  must not be inferred from wall-clock time alone.
- On expiry, both transports are shut down, the connection is closed, and
  `timeouts_handshake` is incremented. A peer that trickles bytes still expires
  because the deadline is absolute, not activity-based.
- If routing rejects the connection before relay, the deadline is irrelevant;
  cleanup still releases the connection slot.

### Idle and half-close timeouts

- While both directions are open, any successful payload read or write in
  either direction resets the idle deadline. Control traffic internal to a
  transport is not enough if no application bytes move.
- When the client half-closes (uplink FIN), start `downlink_only_s` for the
  remaining downlink. When the remote half-closes (downlink FIN), start
  `uplink_only_s` for the remaining uplink. These are absolute grace periods;
  continuing traffic does not extend them. The idle timer still applies if it
  expires earlier.
- On expiry of either timer, both streams are shut down, relay tasks are
  canceled, and `timeouts_idle` is incremented.
- UDP sessions reset the idle deadline per datagram in either direction.
  Existing bounded session tables remain the outer cap.
- `idle_timeout_s = 0` disables the idle timer; `uplink_only_s = 0` or
  `downlink_only_s = 0` closes the remaining direction immediately after the
  corresponding half-close. Handshake and connection caps still apply.

### Enforcement design

Use one watchdog task per accepted connection, owned by the connection
lifecycle:

- Shared state: an atomic monotonic timestamp of the last activity, the current
  phase (handshake, relay, uplink-only, or downlink-only), and the applicable
  timeout.
- The relay hot path performs one atomic store per read/write that moved
  payload; it does not allocate or lock.
- The watchdog sleeps in bounded slices (for example, at most one second or
  half the remaining deadline) and shuts down both transports when the deadline
  passes.
- The watchdog is canceled and joined when the relay/handler finishes, before
  the connection slot and arena are released.
- `Instance.stop` cancels the connection group; watchdog shutdown must be
  idempotent with normal close.

A single global reaper is not recommended for v1: it needs a locked registry,
scans every connection on each tick, and makes error attribution and shutdown
ordering harder.

### Observability

Add counters/gauges through `Metrics`:

- `connections_active` (gauge)
- `connections_rejected` (counter)
- `timeouts_handshake` (counter)
- `timeouts_idle` (counter; includes idle and half-close grace expiry)

Log at `debug` for per-connection rejection and at `info` for aggregate
timeouts if the embedder requests it; never log payloads or credentials.

## Alternatives

1. **Per-inbound limits and timeouts.** Better fairness and allows a public
   listener to be capped separately from a local one. Rejected for v1 because
   it multiplies config combinations and validation rules; a global cap is the
   safety floor and can be extended later without changing the global default.
2. **Only `max_connections`, no timeouts.** Bounds memory but still permits a
   slowloris or silent relay to hold every slot indefinitely. Rejected.
3. **Socket-level `SO_RCVTIMEO`/`SO_SNDTIMEO`.** Platform-specific, not exposed
   by `std.Io`, and a per-direction timeout misclassifies a healthy
   unidirectional transfer (for example a large download with no upload).
   Rejected.
4. **Timeout on every read/write via a per-operation race.** No watchdog task,
   but adds a timer race to the relay hot path and complicates half-close and
   cancellation. Rejected.
5. **Global reaper task.** One task per `Instance`, but requires a locked
   connection registry and periodic O(N) scans; shutdown/attribution is harder.
   Rejected for v1.
6. **Rely on the embedder.** Shifts a security invariant to every application
   and cannot protect library-owned buffers. Rejected.

## Consequences

Positive:

- File descriptors and per-connection memory are bounded by configuration.
- Silent handshakes and idle relays are closed without embedder involvement.
- The hot path gains only an atomic activity store; no lock or allocation.
- Limits are visible in JSON and metrics, and defaults are safe for a library.

Negative:

- One watchdog task per connection adds scheduling and teardown complexity.
- The relay/inbound handlers need an explicit handshake-to-relay transition.
- The defaults change behavior: connections idle for five minutes are closed.
- A global cap lets one inbound consume the whole budget until per-inbound
  limits are added.
- Handshake timeout semantics must be documented carefully because TLS already
  has a per-inbound timeout.

Tests:

- Loopback: accept exactly `max_connections`, assert the next connection is
  closed and `connections_rejected` increments; release slots on all failure
  paths.
- Silent SOCKS5/HTTP/Trojan/VLESS handshake expires at
  `handshake_timeout_s`; a byte-trickling peer still expires.
- Relay with both directions silent expires at `idle_timeout_s`; activity in
  either direction resets the deadline.
- Client half-close expires after `downlink_only_s`; remote half-close expires
  after `uplink_only_s`; continuing traffic does not extend the grace period.
- UDP session expires after no datagrams; a datagram in either direction
  resets it.
- Cancellation: `Instance.stop` and watchdog expiry are idempotent and do not
  leak tasks, buffers, or the connection slot.
- Run under both `Io.Threaded` and an `Io.Evented` implementation where the
  platform supports it.

## Approval

- [x] Accept the recommendation: global `limits` with
      `max_connections=1024`, `handshake_timeout_s=10`, `idle_timeout_s=300`,
      `uplink_only_s=1`, `downlink_only_s=1`; per-connection watchdog; UDP not
      counted in `max_connections`.
- [ ] Accept with different defaults: `max_connections = ____`,
      `handshake_timeout_s = ____`, `idle_timeout_s = ____`,
      `uplink_only_s = ____`, `downlink_only_s = ____`.
- [ ] Choose per-inbound limits instead (requires a revised ADR).
- [ ] Reject; keep resource limits outside the library.

## Amendment (2026-11-20)

Implementation uses one reaper task per `Instance`, not one watchdog task per
connection. `std.Io.Threaded` dispatches async tasks as blocking pool workers;
enough per-connection watchdogs sleeping in futex waits can starve the
connection tasks they are meant to police. The reaper scans a bounded registry
of active guards every 250 ms. The limit values, accounting, handshake
transition, idle/half-close semantics, and metrics are unchanged.
