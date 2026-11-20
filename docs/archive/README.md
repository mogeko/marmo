# Archive

Point-in-time records and implementation notes for code that no longer exists.
Nothing here is maintained, and nothing here is a current decision. Use it for
history, provenance, and regression context.

| File | What it is | Superseded by |
| --- | --- | --- |
| [architecture-zig.md](architecture-zig.md) | The Zig-era architecture | [`../architecture.md`](../architecture.md) |
| [security-audit-zig.md](security-audit-zig.md) | The 2026-11-20/21 audit of the Zig tree: threat model, 25 findings, six re-audit rounds plus two follow-ups | [`../security/audit.md`](../security/audit.md) |
| [protocols/tls.md](protocols/tls.md) | In-tree TLS 1.3 implementation notes (`packages/tls13`) | `rustls`; [`../architecture.md`](../architecture.md) §13 |
| [protocols/http2.md](protocols/http2.md) | In-tree HTTP/2 implementation notes (`packages/http2`) | `h2`; [`../architecture.md`](../architecture.md) §13 |
| [protocols/websocket.md](protocols/websocket.md) | In-tree WebSocket implementation notes (`packages/ws`) | `tokio-tungstenite`; [`../architecture.md`](../architecture.md) §13 |

## Rules

- Archived files are not edited except to fix a broken link or add a banner.
- A current document links to an archived file when it needs the history; the
  archived file never links back as if it were current.
- The decision record stays in [`../decisions/`](../decisions/); the archive is
  for documents, not ADRs.
- Protocol notes that remain language-neutral (Shadowsocks, Trojan, VLESS)
  stay in [`../protocols/`](../protocols/) and are updated, not archived.
