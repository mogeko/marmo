# ADR-0006: Outbound groups and node selection

- Status: Accepted (2026-11-18)
- Date: 2026-11-18
- Deciders: @mogeko
- Related: ADR-0002, ADR-0003, ADR-0005

## Context

Users expect several nodes behind one logical outbound, with either manual
choice or automatic selection. Automatic selection needs a signal; the only
portable one is a probe (TCP connect or HTTP request), because proxy protocols
rarely expose server-side load. Probes generate traffic and can leak activity,
so they must be explicit and bounded.

An outbound group must also behave like an outbound for the router, and UDP
sessions must not flap between nodes mid-session.

## Decision

Implement outbound groups with five strategies and opt-in active health checks.

- `manual`: fixed node by tag.
- `round_robin`: rotate on each new TCP connection or UDP session.
- `random`: uniform choice.
- `fallback`: ordered list; start at the first healthy node, advance on connect
  failure, stay there until config reload or a health check marks it down.
- `least_latency`: EWMA of probe latency (`alpha = 0.2`), lowest wins; ties by
  list order.

Health checks:

- Per group, disabled by default.
- Probe types: `tcp_connect` (host:port) and `http_head` (URL, expected status).
- Config: interval, timeout, jitter, failure threshold, recovery threshold.
- Results update an atomic latency/failure state; probes run in a dedicated
  `Io.Group` owned by the instance.
- Failed probes exponentially back off up to a cap; they never block relays.

Selection:

- TCP: choose per connection.
- UDP: choose once per session; keep the node until the session expires.
- Config reload swaps the node list atomically; in-flight selections keep
  their concrete node.
- No cross-connection affinity (no target hashing) in v1.

## Alternatives

1. **No active checks; failover only on connect errors.** Cheaper and private,
   but cannot implement least-latency. Supported as `fallback`.
2. **Passive measurement only** (handshake/relay latency). Attractive, but
   noisy and hard to compare across idle nodes; keep as future signal.
3. **Weighted random / consistent hashing.** Useful for multi-server load
   spreading; defer until there is a concrete use case.
4. **Probe by default.** Rejected: unexpected traffic and privacy impact.

## Consequences

- Probes are visible traffic; docs must state that enabling checks contacts the
  configured target and can reveal activity.
- Least-latency quality depends on probe target choice; make it explicit.
- Selection state must be race-free under concurrent connects; use atomics for
  counters and a mutex only for list replacement.
- Metrics need per-node success rate and latency to make behavior debuggable.
- Groups are one level deep in v1; nested groups are rejected at validation.

## Approval

- [x] Accepted 2026-11-18 as recommended.
