# Threat model

## Trust boundaries

- The endpoint accepts only loopback endpoints by default and validates the server trust chain plus DNS/IP SAN.
- The server requires mTLS and checks the client CA chain. Agent identities and operator identities have separate local CN allowlists; event payload agent_id must match the agent certificate. Policy publication additionally requires an operator bearer token read from a mode-0600 file and compared in constant time.
- Policies are untrusted even after TLS and require an Ed25519 signature, expiry, monotonic revision, tenant scope, allowlisted actions, and root scope validation.
- SQLite spool and server DB are local; files are created with restrictive permissions.
- Both JSON parser copies cap input at 1 MiB, limit nesting, reject duplicate object keys, enforce JSON number grammar, and allow only JSON whitespace.

## Data minimization

Only synthetic health events are generated when an active policy allows them. A missing policy, expired policy, or disabled telemetry prevents new events and pauses sending while existing queued rows remain stored; `sample_rate` controls only creation. The server rejects common sensitive field names and does not accept file content, environment variables, tokens, or keys. `monitored_roots` are validated but are not watched or collected. Server logs contain generic request rejection summaries.

## Residual risks

The server is sequential. Its custom HTTP subset bounds headers to 16 KiB and bodies to 1 MiB, checks JSON media type and unambiguous framing, applies a 5 second per-I/O timeout, and enforces a configurable absolute HTTP header/body receive deadline after TLS peer and CN authorization. The TLS handshake and route handling are outside that deadline; the handshake has per-I/O timeout only. Rate limiting and broader availability controls are absent. Agent/server JSON parser implementations are duplicated and must stay in sync. Admin policy publication and conditional fetch are implemented for the local lab. Runtime gates apply `telemetry_enabled` and `sample_rate` to the synthetic channel, but there is no monitored-root file collector; revocation, certificate enrollment, production RBAC, and full runtime policy application remain incomplete. The allowlists are local text files, and CN is an identity mapping for this lab rather than a complete enrollment system. The server recomputes payload hashes from canonical compact JSON and rejects mismatches. The Agent requires HTTP 200 for event ACKs and accepts HTTP 200/304 for policy fetch. No HA, production PKI, public network service, or remote execution is provided.
