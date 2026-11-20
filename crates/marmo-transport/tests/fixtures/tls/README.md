# TLS test fixtures

Synthetic credentials generated for this repository with OpenSSL 4.1.0; they
are not a capture and are not usable outside tests. The private keys are
committed deliberately so the loopback tests are self-contained.

| File | Purpose |
| --- | --- |
| `ca.pem` | Self-signed EC P-256 CA, used as the client-certificate trust anchor |
| `server.pem`, `server.key` | Leaf for `localhost` / `127.0.0.1`, EKU `serverAuth` |
| `client.pem`, `client.key` | Leaf with EKU `clientAuth` |

All certificates use ECDSA P-256 with SHA-256 and expire after 36500 days.
Regenerate with the commands in the PR that added them if they ever expire.
