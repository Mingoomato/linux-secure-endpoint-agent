# Architecture

The endpoint has a durable SQLite spool and a TLS 1.2-or-newer client. Synthetic event creation hashes the payload, assigns a durable sequence, writes the row before networking, sends bounded batches to a loopback mTLS endpoint, and removes only IDs explicitly accepted or identified as duplicates by the authenticated server. Queue size and byte quotas stop unbounded growth; retry uses bounded exponential delay with jitter.

The reference server verifies its client-certificate chain and maps the certificate common name to an explicit agent allowlist. It commits event IDs under a unique agent/event key before returning acknowledgements. The database contains only event metadata and payload hashes.

Policies are separately signed with Ed25519 over exact file bytes. Validation rejects unknown top-level/settings fields and unsafe actions, checks expiry/scope and monotonic revision, then commits the last-good document in a SQLite transaction. TLS authentication does not replace detached policy signature verification.

A C transport probe is limited to loopback TCP connectivity; TLS is implemented only in the C++ agent/server.
