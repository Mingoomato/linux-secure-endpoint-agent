# Threat model

## Trust boundaries

- The endpoint accepts only loopback endpoints by default and validates the server trust chain plus DNS/IP SAN.
- The server requires mTLS, checks the client CA chain, and authorizes the certificate CN against a local allowlist. A payload agent_id must match that identity.
- Policies are untrusted even after TLS and require an Ed25519 signature, expiry, monotonic revision, tenant scope, allowlisted actions, and root scope validation.
- SQLite spool and server DB are local; files are created with restrictive permissions.
- Both JSON parser copies cap input at 1 MiB, limit nesting, reject duplicate object keys, enforce JSON number grammar, and allow only JSON whitespace.

## Data minimization

Only synthetic health events are generated. The server rejects common sensitive field names and does not accept file content, environment variables, tokens, or keys. Server logs contain generic request rejection summaries.

## Residual risks

The server is sequential. Its custom HTTP subset now bounds headers to 16 KiB and bodies to 1 MiB, rejects ambiguous framing, and uses a 5 second socket I/O timeout, but it has not been fuzzed and does not provide a total connection deadline or rate limiting. Availability is not hardened. Agent/server JSON parser implementations are duplicated and must stay in sync. Admin policy publication and revocation are disabled. The allowlist is a local text file, and CN is an identity mapping for this lab rather than a complete enrollment system. The server recomputes the payload hash from compact JSON with lexicographically sorted object keys and rejects mismatches. The reference server's policy fetch endpoint returns 304. No HA, production PKI, public network service, or remote execution is provided.
