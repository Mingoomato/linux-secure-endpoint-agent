# Code Walkthrough — Linux Secure Endpoint Agent Lab

## 1. Agent setup and durable queue

The agent CLI in `agent/src/agent.cpp` builds a `Config` from endpoint, agent ID, trust/certificate/key, and store arguments. `is_loopback` rejects nonlocal hosts. `open_queue` creates a private directory, chmods it, opens `spool.sqlite`, enables WAL and `synchronous=FULL`, then creates queue, sequence, and policy-state tables.

`next_sequence` uses `BEGIN IMMEDIATE`, reads/increments the persisted sequence, updates metadata, and commits. `enqueue` builds only the fixed synthetic health payload, hashes it, checks row and byte quotas, and inserts a row. The event is durable before the network request begins.

## 2. TLS client and server identity

`client_context` requires loopback, creates `TLS_client_method`, enforces TLS 1.2 minimum, verifies peers, loads CA/client cert/private key, checks private-key mode and CN against `agent_id`. `send_batch` resolves only loopback IP addresses, connects a TCP socket with timeouts, configures `SSL_set1_host` or IP SAN verification, then performs `SSL_connect`.

The client sends an HTTP/1.1 batch over OpenSSL. `http_exchange` loops over SSL writes/reads with a 1 MiB response cap and parses `Content-Length`. `ack_ids` parses accepted and duplicate ID arrays. `flush` filters ACKs to IDs actually in its submitted batch, deletes them transactionally, and retries failures with bounded exponential delay and jitter.

## 3. Server request and ingestion

`server/src/server.cpp` loads a local allowlist, configures TLS server cert/key/CA and required client certificate verification, opens SQLite, and binds an IPv4 listener to `INADDR_LOOPBACK`. `accept4(..., SOCK_CLOEXEC)` accepts one FD; `serve_one` does TLS handshake, validates the peer chain, extracts its certificate CN, and checks the allowlist.

`read_request` reads at most 1 MiB and uses `Content-Length` for the body boundary. It is a small custom parser rather than a full HTTP implementation. Both JSON parser copies enforce strict number grammar, JSON whitespace, duplicate-key rejection, depth <=32, and a 1 MiB text limit. `ingest` checks batch version, claimed agent ID, registered certificate identity, count bound, sensitive-key names, event fields, sequence range, hash syntax, and the recomputed hash of canonicalized payload JSON. It inserts `(agent_id,event_id)` under a uniqueness constraint inside a transaction, verifies identical duplicate content, commits, then returns accepted/duplicate ID arrays.

## 4. Policy validation

`read_limited` loads the policy and signature. `validate_signed_policy` verifies the raw 64-byte Ed25519 signature over exact file bytes before parsing JSON. It rejects unknown top-level/settings fields and unsafe actions, checks expiry, tenant and root scope, then reads the prior revision and transactionally stores only a strictly newer policy for that issuer. No runtime watcher or enforcement component consumes it.

## 5. Error paths and resource ownership

`SSL_CTX`/`SSL` on the agent send path use `unique_ptr`; server SSL objects and raw sockets are manually freed/closed. SQLite handles/statements and OpenSSL key/context objects also use manual cleanup. When reviewing an error path, track ownership from allocation through every throw/return. Queue rows intentionally survive network failure and are removed only after a safe ACK. The current server handles clients sequentially and has no per-client timeout policy beyond TLS/socket behavior.

## 6. JSON parser and regression tests

`agent/include/agent/json.hpp` and `server/include/agent/json.hpp` each implement the same bounded parser. `number()` scans the JSON grammar (optional minus, no leading zero, optional nonempty fraction and exponent), then converts the isolated token with `std::from_chars` and rejects range/non-finite results. `ws()` accepts only space, tab, LF, and CR. Object insertion rejects duplicate keys. The same `tests/json_parser_test.cpp` is compiled twice so both copies receive matching valid/invalid token, duplicate-key, depth, and size cases. The duplicated headers can drift; tests reduce that risk but do not remove it.
