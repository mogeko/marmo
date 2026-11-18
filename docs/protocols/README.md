# Protocol notes

One file per protocol, named after the lower-case protocol
(`shadowsocks.md`, `vless.md`, ...). Create it when implementation starts, not
before.

Record:

- The specification or documentation used, with the revision or date consulted.
- Known ambiguities and how real clients behave.
- Cipher/auth details and the exact key schedule.
- TCP and UDP framing, including the maximum datagram size.
- Where captured fixtures live (`tests/fixtures/<protocol>/`) and their
  provenance and license.
- Interop results against self-hosted reference implementations.

Rules:

- Do not paste code from GPL/AGPL/MPL projects. Specs and behavior notes only
  (ADR-0009).
- Never commit credentials, UUIDs, private keys, or captures of real traffic.
- If behavior is inferred rather than specified, say so explicitly.
