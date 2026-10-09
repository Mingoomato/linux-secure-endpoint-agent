# Engineering Study Guide — Linux Secure Endpoint Agent Lab

## Learning objective and implementation status

This repository is a local educational agent/control-server pair. It demonstrates synthetic telemetry, durable SQLite spooling, TLS client/server authentication, per-event acknowledgements, server-side idempotency, privacy filtering, and detached Ed25519 policy verification. TLS proves transport peer identity; a separate policy signature proves the policy issuer's authority. Neither implies that the policy is safely applied to a production endpoint.

Release build and the loopback mTLS integration CTest passed; a separate ASan/UBSan smoke run is recorded as passed. The test covers authorized local TLS, one synthetic event delivery, acknowledgement/dequeue, duplicate behavior, conflicting event-ID rejection, an unregistered certificate, and valid/tampered/replayed policies. SRS-06 remains partially implemented: no production enrollment, revocation/deny-list lifecycle, server policy publishing/signing, offline restart test, event.v1 file input, 429/backpressure protocol, robust parser fuzzing, real metrics endpoint, or performance benchmark. The server is sequential with a minimal HTTP parser. Policy is validated and persisted as last-good state; no file-monitoring or enforcement module consumes it.

## Why each subsystem exists

| Subsystem | Purpose | Main code |
|---|---|---|
| Synthetic event producer | Makes a privacy-safe event without reading local user data. | `enqueue`, `run` command |
| Durable SQLite queue | Commits events before network I/O and removes only acknowledged IDs. | `open_queue`, `next_sequence`, `pending`, `delete_acked` |
| TLS client | Verifies CA chain and DNS/IP SAN, sends client certificate, and restricts the destination to loopback. | `client_context`, `connect_socket`, `send_batch` |
| ACK and retry logic | Keeps unacknowledged records after failure and bounds retry attempts/backoff. | `ack_ids`, `flush` |
| TLS reference server | Requires a client certificate, maps CN to local allowlist, accepts bounded batch requests. | `run_server`, `serve_one`, `read_request` |
| Idempotent ingestion | Stores a unique `(agent_id,event_id)` and compares duplicate sequence/hash before acknowledging. | `ingest`, SQLite schema |
| Policy signature validator | Separately verifies raw Ed25519 signatures, scope, expiry, allowlisted actions, and monotonic revision. | `validate_signed_policy` |
| C transport probe | Isolated POSIX socket exercise for loopback reachability. | `transport-c/src/sw_probe.c` |

## Data and control flow

### Agent queue and transport

1. `main` parses agent settings and checks loopback/certificate/key configuration for commands that need it.
2. `open_queue` creates a private store, enables SQLite WAL and full synchronous mode, and creates queue, sequence metadata, and last-good policy tables.
3. `next_sequence` commits a monotonic sequence increment. `enqueue` constructs a fixed synthetic health payload, computes its hash, enforces row/byte quota, and inserts the event before networking.
4. `pending` returns a bounded batch ordered by sequence. `send_batch` builds an OpenSSL client context, validates certificate/key permissions and client CN, resolves only loopback addresses, creates a TCP socket with timeouts, verifies the server chain and DNS/IP SAN, then sends a TLS-protected HTTP request.
5. `ack_ids` reads the response arrays. `flush` accepts only IDs that were in the submitted batch, deletes those inside a SQLite transaction, and leaves the rest queued. Network or parsing errors use bounded exponential delay with jitter; after retry exhaustion, the queue remains on disk.

### Server and ingestion

1. `run_server` rejects non-loopback bind values, loads TLS server cert/key/CA and an allowlist, opens the DB, creates a `SOCK_STREAM | SOCK_CLOEXEC` listener, binds to `INADDR_LOOPBACK`, and listens.
2. A sequential `accept4` loop passes one connection to `serve_one` at a time. `SSL_accept` verifies the client certificate chain. `peer_cn` maps the certificate common name to the local allowlist.
3. `read_request` accumulates a capped HTTP request and extracts `Content-Length`; `serve_one` routes health/status/telemetry/policy requests.
4. `ingest` parses `agent_batch.v1`, checks claimed agent ID against certificate identity and allowlist, bounds event count, rejects sensitive-looking keys, canonicalizes payload JSON, verifies SHA-256, and writes rows in a transaction.
5. The server commits before returning accepted/duplicate IDs. Same ID/sequence/hash is an idempotent duplicate; same ID with changed content is rejected.

### Policy path

`validate_signed_policy` reads a bounded policy and exact 64-byte signature, loads an Ed25519 public key, verifies the signature over the original file bytes, checks known fields/actions, expiry, tenant and root scope, then stores the strictly newer revision/document in a SQLite transaction. Whitespace edits change the signed bytes. This is a validation/last-good persistence path; it is not active policy rollout or runtime enforcement.

## Ownership, lifetime, and concurrency

- C++ `std::string`, containers, streams, and parser values own their buffers. Pending event vectors are copied from SQLite before statements are finalized.
- `SSL_CTX` and `SSL` are wrapped in `std::unique_ptr` in the client send path. Server `SSL*`, listener/client sockets, `sqlite3*`, statements, and OpenSSL keys/contexts use manual cleanup and need review on every error branch.
- `SSL_set_fd` associates an SSL object with a raw socket FD; the code performs TLS I/O through `SSL_read`/`SSL_write` and closes the FD after TLS shutdown/free.
- SQLite transactions coordinate sequence updates, event ingestion, ACK deletion, and policy revision persistence. WAL allows readers/writers to overlap but does not make the network and DB transaction one atomic operation.
- The agent loop is one thread. The reference server accepts one connection and processes it before accepting another; a slow TLS client or request can block every later client. There is no worker pool or request cancellation policy.

## Security assumptions and failure modes

The baseline trusts the local OS, private SQLite store, CA key, signing key, and administrator-managed allowlist. Generated private keys must remain outside the repository and use restrictive permissions. The client rejects non-loopback destinations; the server rejects non-loopback binds. Server hostname verification checks DNS/IP SAN, while server client identity is a lab CN-to-allowlist mapping.

Failures include invalid/private key permissions, wrong CA or SAN, expired cert/policy, TLS truncation, socket timeout, malformed/oversized HTTP/JSON, queue quota, DB commit error, wrong ACK IDs, duplicate conflict, sensitive-key rejection, policy replay, and process termination. The server commits before ACK, so a lost ACK is safely retried as a duplicate. The agent's sequence and queue are separate transactions; gaps can occur without violating event uniqueness. Queue restart/reconnect behavior is plausible by design but has not been integration-tested across process/server restart.

The minimal HTTP parser does not implement the full HTTP/1.1 grammar; chunked transfer encoding, robust header ambiguity rejection, rate limiting, and concurrent service are absent. The loopback restriction is a lab safety boundary, not a production network hardening claim.

## Alternative designs

- A mature **HTTP/TLS library** would reduce handwritten HTTP framing and parser risk, at the cost of another dependency and a less visible protocol exercise.
- A **Unix domain socket** could simplify local-only transport but would not teach certificate-based mutual TLS or hostname verification.
- A **message broker** could provide durable server-side ingestion and backpressure, but adds broker credentials, schema evolution, and operational state.
- A **concurrent server** with a bounded worker pool improves throughput but must bound file descriptors, TLS handshakes, queue depth, and DB transactions.
- A **device enrollment registry with certificate fingerprints/SAN URI** is stronger than a CN text allowlist, but needs issuance, rotation, revocation, and tenant lifecycle design.
- A policy **active configuration** requires prepare/commit/rollback with a consumer and audit trail. Persisting a signed document alone is not evidence of application.

## Study route

Read `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, and `docs/KEY_MANAGEMENT.md`. Trace one event from SQLite insert through TLS send, server transaction, ACK, and local delete. Then compare that path with a lost-ACK retry. Separately trace policy signature validation and explain why TLS authentication does not replace it. Use the walkthrough and internals guide before attempting an unsolved exercise.

## Official references

- [`socket(2)`](https://man7.org/linux/man-pages/man2/socket.2.html), [`connect(2)`](https://man7.org/linux/man-pages/man2/connect.2.html), [`accept(2)`](https://man7.org/linux/man-pages/man2/accept.2.html), [`bind(2)`](https://man7.org/linux/man-pages/man2/bind.2.html)
- [OpenSSL certificate verification](https://docs.openssl.org/3.0/man3/SSL_CTX_set_verify/), [hostname verification](https://docs.openssl.org/3.0/man3/SSL_set1_host/)
- [SQLite WAL](https://www.sqlite.org/wal.html), [SQLite Atomic Commit](https://www.sqlite.org/atomiccommit.html)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446), [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110)
- [systemd execution environment and hardening](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
