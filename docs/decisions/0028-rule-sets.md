# ADR-0028: Injected rule sets

- Status: Accepted (2026-11-22)
- Date: 2026-11-22
- Deciders: @mogeko
- Related: ADR-0005, ADR-0009, ADR-0018, ADR-0029

## Context

P2-9 adds GEOIP/GEOSITE-style routing data, `domain_keyword`, `port_range`, and
`inbound` matchers. Today every matcher is inline JSON: `domain`,
`domain_suffix`, `ip_cidr`, `port`, and `network`. A GEOIP or GEOSITE category
has tens of thousands of entries, so inline rules would exceed the 4 MiB
configuration cap and duplicate data across rules.

The first draft of this ADR proposed a library-owned `.mrs` format, a checksum,
a loader, and an offline compiler tool. Review rejected that direction for
three reasons:

1. **Library weight.** A format specification, checksum, bounded parser,
   compiler tool, golden fixtures, and a fuzz target are a large amount of
   routing-adjacent surface for an embeddable proxy library.
2. **Hot reload.** Data loaded at `build()` is immutable for the instance
   lifetime. Updating a GEOIP/GEOSITE category would require rebuilding the
   whole instance, even though the rule list did not change.
3. **Storage coupling.** Requiring one fixed byte format forces a CLI that
   stores rules in SQLite, a config service, or another format to translate
   everything into `.mrs` first. That translation is exactly the kind of
   environment-specific work the library should not own.

ADR-0005 still decides the routing shape: ordered first-match rules, compiled
matchers, no regular expressions, and no runtime downloads. Its requirement
for a versioned, checksummed binary format assumed the library owned the data
files. This ADR changes that delivery clause while keeping the matching
semantics.

The library boundary remains: no filesystem I/O, no network downloads, no
bundled rule data, and no storage format. The embedder owns data lifecycle,
storage, licensing, and reload.

## Decision (recommended)

Keep only the matching abstraction and the rule semantics in `marmo`; inject
the actual domain and IP set implementations.

### Public interface

Add `marmo::ruleset` with two object-safe traits:

```rust
pub trait DomainSet: Send + Sync {
    /// `domain` is ASCII-lowercased and has no trailing dot.
    /// Must be non-blocking, allocation-free, bounded, and panic-free.
    fn contains(&self, domain: &str) -> bool;
}

pub trait IpSet: Send + Sync {
    /// Must be non-blocking, allocation-free, bounded, and panic-free.
    fn contains(&self, address: IpAddr) -> bool;
}
```

- Add `InstanceBuilder::domain_set(tag, Arc<dyn DomainSet>)` and
  `InstanceBuilder::ip_set(tag, Arc<dyn IpSet>)`.
- Config references tags: `domain_set` names domain sets; `geoip` names IP
  sets. A referenced but unregistered tag is a `build()` error. Duplicate tags
  within one registry are a `build()` error; the same tag may exist in both
  registries. Supplied but unreferenced sets are allowed.
- The library holds stable `Arc` handles. It never inspects the data behind
  them, never versions it, and never reloads it.
- The embedder may implement a set over a trie, a sorted array, SQLite loaded
  into memory, or another store. SQLite is storage, not a per-connection query
  engine: `contains` must answer from an in-memory snapshot.

### Hot reload

- Set data is provider-owned. An implementation can hold an
  `ArcSwap`/`RwLock` snapshot and swap it atomically; `contains` reads one
  snapshot per call. No `Instance` rebuild is needed.
- The library does not own a refresh task, a timer, or a file watcher. The
  CLI/embedder owns update scheduling and failure handling.
- Changing the rule list or the config itself still requires rebuilding the
  instance; that is P5-3. This ADR only removes the rebuild requirement for
  set data.

### Matching

Add these fields to a rule; all matchers within a rule remain ANDed and the
first matching rule wins:

- `domain_keyword`: inline keyword list; ASCII case-insensitive
  `aho-corasick` match. No regular expressions. External domain sets may
  implement keyword semantics themselves through `DomainSet::contains`.
- `port_range`: array of `[start, end]` pairs, normalized and merged; a range
  with `start > end` is a config error.
- `inbound`: list of inbound tags, validated against `inbounds`; matches the
  existing `Metadata.inbound`.
- `domain_set`: list of registered domain-set tags; one call per set.
- `geoip`: list of registered IP-set tags; matches only when the destination
  is an IP, like `ip_cidr`.

`Router::route` stays synchronous and allocation-free in its own code. A rule
evaluates at most one `contains` call per referenced set. The provider contract
is what keeps that call cheap.

Domains are ASCII-lowercased and trailing dots are removed before routing, so
inline rules, injected sets, and sniffed domains agree. This is a small
behavior fix for existing `domain`/`domain_suffix` matching with regression
tests; no other matching semantics change.

### Bounds

- At most 256 domain-set tags and 256 IP-set tags per instance.
- The number of rules remains bounded by `MAX_CONFIG_BYTES`; each rule's
  `domain_set`/`geoip` arrays are non-empty and duplicate-free.
- A provider's internal memory and index size are the embedder's
  responsibility. The library bounds its own state (tags, rules, calls per
  route), not the provider's data structure.
- `contains` must return `false` on an internal error. A failed lookup is a
  non-match, never a connection failure. A provider panic is a contract
  violation; the library does not catch it.

### Dependencies

- Add `aho-corasick` to `marmo` for inline `domain_keyword` matching.
- Do not add `blake3`, `memmap2`, a rule-set compiler tool, or a fifth crate.
- The library retains `#![forbid(unsafe_code)]` and performs no filesystem or
  network access for rule sets.

## Alternatives

1. **Library-owned `.mrs` format with an offline tool.** The first draft. It
   gives a canonical, checksummed artifact, but makes the library heavy, makes
   data reload require an instance rebuild, and forces CLIs with other stores
   to translate. Rejected after review.
2. **Let the library read rule-set paths from config.** Breaks the
   no-filesystem-I/O boundary and moves path, permission, and file-format
   policy into the library. Rejected.
3. **Adopt sing-box SRS or v2ray `.dat` directly.** Avoids a converter for one
   ecosystem but couples the library to another project's schema and licensing,
   and still prevents SQLite or custom storage. Rejected.
4. **One generic `RuleSet` trait with a kind method.** Less type-safe than two
   traits; a domain set passed as an IP set becomes a runtime error instead of
   a compile-time one. Rejected.
5. **A generic connection classifier with arbitrary labels.** More general,
   but allocates or erases types on the routing path. The concrete need is
   domain/IP membership. Rejected for now.
6. **Keep rule sets inline in JSON.** No abstraction, but the 4 MiB cap and
   duplication make GEOIP/GEOSITE impractical. Rejected.
7. **No external sets at all.** Drops a committed P2-9 capability and pushes
   large tables into every rule. Rejected.

## Consequences

- The library stays small: two traits, two builder methods, and matcher wiring.
  There is no format parser, checksum, compiler tool, or rule-set fuzz target.
- CLIs can store rules in SQLite, JSON, a service, or a memory-mapped file and
  expose only `contains`; no `.mrs` translation step.
- Set data can be hot-swapped inside a provider without rebuilding `Instance`.
  Rule/config reload remains P5-3.
- The library can no longer verify data versioning, checksums, sort order, or
  memory bounds; those become provider responsibilities. The provider is
  trusted embedder code, documented as such.
- Route latency depends on the provider's `contains`; the contract requires an
  in-memory, allocation-free, non-blocking implementation. A slow provider is a
  performance bug in the CLI, not a library default.
- A provider error maps to non-match. A provider panic is not caught and is a
  contract violation; tests use a fake provider that follows the contract.
- Tests: fake domain/IP sets for exact, suffix, keyword and CIDR behavior;
  missing/duplicate tag errors; first-match and AND semantics; case
  normalization; a provider swap test that changes a route without rebuilding;
  a no-call test for unreferenced sets; all on Linux, macOS, and Windows.
- Docs: update architecture sections 10, 13, 19, and 21, roadmap P2-9, README
  examples, CHANGELOG, and the ADR index. No `docs/rulesets/format.md` and no
  compiler tool are added.
- Estimated 1-2 days for the traits, matchers, validation, and tests. P2-9's
  "versioned compiled format" exit criterion is delegated to the provider; the
  roadmap states the injected-set contract instead.

## Approval

- [x] Accept the recommendation (injected `DomainSet`/`IpSet`,
      `domain_keyword`/`port_range`/`inbound`, provider-owned data and reload).
- [ ] Keep the library-owned `.mrs` format despite the weight and reload cost.
- [ ] Let the library read configured paths or adopt an ecosystem format.
- [ ] Choose an alternative: ...
