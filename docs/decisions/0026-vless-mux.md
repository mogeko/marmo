# ADR-0026: VLESS inbound Mux.Cool

- Status: Accepted (2026-11-22, on direct implementation request)
- Date: 2026-11-22
- Deciders: @mogeko
- Related: ADR-0016, ADR-0022, ADR-0025

## Context

VLESS implements request command `3` (Mux) only for XUDP: one fixed UDP
destination, session id `0`, and New/Keep frames. The VLESS protocol note lists
"one request per stream and no multiplexing (Mux.Cool)" as a known gap, and the
inbound rejects TCP New frames and additional session ids.

ADR-0025 added a protocol-neutral Mux.Cool codec (`marmo_proto::mux`) and a
bounded inbound dispatcher for VMess. The dispatcher already handles TCP and
UDP sessions, multiple ids, XUDP session `0`, per-frame UDP targets, End, and
keep-alives. Xray 26.11.9 can enable the same Mux.Cool on a VLESS outbound, so
VLESS clients that multiplex currently fail against this inbound.

The change is inbound-only: the VLESS outbound keeps simple UoT by default and
XUDP via `"xudp": true`. Client-side mux pooling remains deferred.

## Decision (recommended)

Wire the VLESS Mux command to the shared Mux.Cool dispatcher:

- After the VLESS request header with command `3` and the synthetic
  `v1.mux.cool` target, send the empty VLESS response header and hand the
  stream plus any already-read bytes to `inbound::mux::serve`.
- Accept New/Keep/End/KeepAlive for TCP and UDP sessions, multiple nonzero
  session ids, and XUDP session `0` with an optional eight-byte GlobalID.
- Reuse the ADR-0025 bounds: 128 sessions, 16-frame per-session uplink queue,
  64 KiB frame data, 512-byte metadata, and the instance idle timeout.
- Change the dispatcher to take `BoxStream` plus a byte prefix instead of a
  VMess `ChunkStream`, so both protocols share one implementation. VMess boxes
  its chunk stream and passes an empty prefix.
- Keep the VLESS outbound unchanged: simple UoT, or XUDP when configured. No
  new configuration field and no new dependency.
- Remove the XUDP-only `handle_xudp` path from the VLESS inbound; its behavior
  is a subset of the dispatcher.

## Alternatives

1. **Keep the XUDP-only inbound.** Least work, but VLESS clients with mux
   enabled cannot carry TCP and cannot open a second session. Rejected because
   the request is to complete mux.
2. **Duplicate the dispatcher for VLESS.** Copies the session table, bounds,
   cancellation, and UDP reply logic. Rejected; one shared implementation is
   what ADR-0025 made possible.
3. **Implement client-side Mux.Cool pooling now.** Multiplexes outbound TCP and
   UDP over one VLESS connection. It needs connection ownership, pooling, and
   cancellation design of its own and is not required for inbound
   compatibility. Deferred to P5-13.
4. **Change the VLESS wire format.** Not possible: Mux.Cool frames are already
   defined and the outbound XUDP path uses them.

## Consequences

- VLESS inbounds terminate full Mux.Cool; the outbound still opens one stream
  per TCP connection (or one UoT/XUDP association per UDP target). Client-side
  pooling is recorded as P5-13.
- `docs/protocols/vless.md`, `docs/architecture.md`, `docs/roadmap.md`,
  `README.md`, `crates/marmo/README.md`, and `CHANGELOG.md` change.
- Tests: loopback TCP and UDP mux sessions on one VLESS connection, the
  existing XUDP loopback tests against the shared dispatcher, and Xray
  26.11.9 interop with a mux-enabled VLESS client.
- No public API, config schema, error model, or dependency change.

## Approval

- [x] Accept the recommendation (inbound full Mux.Cool, shared dispatcher).
