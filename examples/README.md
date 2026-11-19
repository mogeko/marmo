# Examples

Standalone example programs. Each directory has its own `build.zig` and
`build.zig.zon`, depends on the root package through `../..`, and is not part
of the root library build.

## Index

| Example | Purpose |
| --- | --- |
| [vless](vless/) | VLESS server/client over TLS; includes local Xray interop notes |
| [shadowsocks2022](shadowsocks2022/) | Shadowsocks 2022 server/client |

## Commands

From the repository root:

```sh
zig build examples
```

Build or run one example from its directory:

```sh
cd examples/vless
zig build
zig build run -- client --help
```

Both the root `examples` step and the CI examples job discover the explicitly
listed examples in `build.zig`; add a new directory there when adding an
example.

## Contract

- Keep each example runnable on its own with `zig build`.
- Use a path dependency on the root (`../..`); do not import root internals.
- Do not add examples to the root library's dependency graph, to avoid a
  root -> example -> root cycle.
- Reference-implementation interop is local-only. Binaries, credentials, and
  test harnesses are never committed or run in CI.
- Add a row to this index when adding an example, rather than growing the root
  README link list.
