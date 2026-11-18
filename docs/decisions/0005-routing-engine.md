# ADR-0005: Routing engine

- Status: Accepted (2026-11-18)
- Date: 2026-11-18
- Deciders: @mogeko
- Related: ADR-0002, ADR-0003, ADR-0006

## Context

Routing must answer, per connection or UDP session: which outbound, reject, or
direct? Inputs include domain, IP/CIDR, GEOIP/GEOSITE, port, network, inbound
tag, sniffed protocol, and process. Rules come from JSON config and from large
public data sets; evaluation happens on the hot path and must not allocate.

Domains are not always available: SOCKS5/HTTP provide them, raw TCP does not.
TLS SNI or HTTP Host sniffing can recover them, but only by reading bytes.

## Decision

An ordered, first-match rule list compiled at startup into an immutable matcher
program.

- Rules: AND within a rule, OR across rules of the same list; last rule is an
  explicit default (`direct` or `reject`).
- Matchers v1: `domain` (exact/suffix/keyword), `domain_set`, `ip_cidr`,
  `geoip`, `port`/`port_range`, `network`, `inbound`, `process_name`/`path`,
  `protocol` (sniffed).
- No regular expressions in v1: backtracking cost and DoS risk. Add a
  linear-time engine later if needed.
- Domain sets compile to a trie; IP sets to sorted ranges (binary search) or a
  radix trie; both are read-only after startup.
- Rule sets use a versioned, checksummed binary format produced offline by a
  separate tool. The library memory-maps them; it never downloads data.
- Sniffing is opt-in per inbound with byte and time limits; inbound-provided
  domains always win. Buffered bytes are replayed to the relay.
- Process matching is best-effort and opt-in (Linux `/proc`, macOS
  `proc_pidpath`). Unknown process never fails a connection.
- Evaluation is allocation-free; lazily resolved fields (process, DNS) are
  filled only when a rule needs them.
- DNS: resolve only when a selected outbound needs an IP. No fake-IP until a
  TUN inbound exists.

## Alternatives

1. **Rule expression language** (Clash-style). Flexible but requires a parser,
   evaluator, and error reporting; more attack surface. Deferred.
2. **Script hooks** (Lua/WASM). Powerful, but adds a runtime dependency and
   sandboxing burden; not for v1.
3. **Last-match or priority-based rules.** Harder to reason about; first-match
   is the common mental model and easier to test.
4. **Embed GEOIP data in the binary.** Bloats builds and creates licensing
   questions; use external, memory-mapped files.

## Consequences

- A rule-set compiler tool and format specification are required work.
- Rule order is semantic; config validation should warn about unreachable rules
  where cheap.
- Rule-set data licensing (for example GeoLite2) must be documented by the tool,
  not assumed.
- Hot reload replaces the compiled program atomically; in-flight connections
  keep the old snapshot until they finish.
- Sniffing changes what rules can see; tests must cover both sniffed and
  unsniffed paths.

## Approval

- [x] Accepted 2026-11-18 as recommended.
