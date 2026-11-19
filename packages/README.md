# Packages

First-party packages live under `packages/<name>/`. They are consumed by the
root package through path dependencies declared in the root `build.zig.zon`.

## Index

| Package | Purpose |
| --- | --- |
| [tls13](tls13/) | In-tree TLS 1.3 client/server and ALPN |
| [http2](http2/) | HTTP/2 framing, HPACK, and one-stream transport |
| [ws](ws/) | RFC 6455 WebSocket handshake and framing |

## Required layout

```text
packages/<name>/
  build.zig
  build.zig.zon
  README.md
  src/root.zig      # public module surface
```

- `build.zig` exposes a `test` step: `zig build test` from the package
  directory must pass.
- `src/root.zig` must make every package test reachable from the module root
  (for example with `test { std.testing.refAllDecls(@This()); }`), so the root
  can run package tests with `addTest(package.module("<name>"))`.
- `build.zig.zon` declares `.name`, `.version`, `.minimum_zig_version`,
  `.dependencies`, and `.paths`. Keep `.paths` limited to files the package
  needs; do not include the root package.
- `README.md` documents the public API, the current backend or implementation
  status, and known gaps.

## Boundaries

- Packages import only `std` and their declared module dependencies. Do not
  import root files, examples, or paths above the package's `src/` directory.
- Root code imports a package only through its named module; it does not import
  `packages/<name>/src/...` directly.
- Packages must not depend on the root package or on examples.
- Examples may depend on root and, transitively, on packages.

Zig enforces part of this automatically: a module rooted at
`packages/<name>/src/root.zig` cannot import files outside that package path.

## Workspace commands

From the repository root:

```sh
zig build test       # root tests plus every package test
zig build check      # formatting check plus tests
zig build examples   # build every example
```

From a package directory:

```sh
zig build test
```

## Versions and releases

Packages version independently. Root and packages use `0.0.x` while the API is
unstable. When a package is published separately, use a
per-package tag (for example `tls13-v0.1.0`), keep a changelog, and switch
external consumers to a fetched dependency with a hash. Local development keeps
path dependencies.

New packages or changes to these boundaries need an ADR (see ADR-0010).
