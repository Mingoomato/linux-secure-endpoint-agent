# Requirements traceability (SRS-06)

The previously recorded loopback integration verifies selected mTLS, an absolute TLS handshake deadline, separated operator authorization, policy publication/signing/fetch, ETag/304, agent sync, last-good recovery, synthetic and explicit `event.v1` queueing, path pseudonymization and scope, deduplication, fail-closed and sampling gates, and an HTTP receive deadline. A recursive inotify collector, file rename-cookie pairing, watch preflight before policy commit, and prepare-before-swap runtime reload were added after that recorded verification. SQLite agent enrollment, certificate fingerprint pinning, rotation, revocation, and re-enrollment routes were also added later. These changes have not been built or verified. Overflow history reconciliation, directory rename pairing, route-duration deadline, import fault/concurrency matrices, performance, resource-fault, and deployment matrices remain open. See `docs/TEST_RESULTS.md`; older passing evidence does not cover these additions.

| Requirement | Source / artifact | Verification | Status |
|---|---|---|---|
| SEA-FR-001 | server maps certificate CN/UUID to SQLite registry and SHA-256 certificate fingerprint; optional `--agents` bootstrap plus operator enrollment | Earlier smoke covered mTLS authorization; new fingerprint pinning/enrollment path has not been built or verified | IN_PROGRESS |
| SEA-FR-002 | agent TLS peer verification with DNS/IP SAN | SEA-T-002 pending | IMPLEMENTED |
| SEA-FR-003 | TLS minimum TLS 1.2 | protocol test pending | IMPLEMENTED |
| SEA-FR-004 | CLI TLS inputs and bounds; JSON parser number, whitespace, duplicate-key, depth, and record-size limits | tests/json_parser_test.cpp; invalid config tests pending | IN_PROGRESS |
| SEA-FR-005 | agent command dispatch | CLI smoke pending | IN_PROGRESS |
| SEA-FR-006 | synthetic event producer plus explicit one-record `event.v1` import | `tests/smoke.sh` verifies active-policy sample gating, path scope, HMAC path pseudonymization, pathless degraded coverage, import dedup, sensitive/unknown-field rejection, and successful server ACK | IMPLEMENTED |
| SEA-FR-007 | sequence, UUID, timestamp, payload hash | SEA-T-004 pending | IMPLEMENTED |
| SEA-FR-008 | SQLite WAL spool + per-ID ACK removal | tests/smoke.sh (acknowledgement and deduplication) | IMPLEMENTED |
| SEA-FR-009 | server unique key (agent,event) | SEA-T-005 pending | IMPLEMENTED |
| SEA-FR-010 | accepted/duplicate acknowledgement | SEA-T-005 pending | IMPLEMENTED |
| SEA-FR-011 | quotas and bounded retry | SEA-T-006/008 pending | IN_PROGRESS |
| SEA-FR-012 | allowlisted fields/actions and canonical monitored-root containment | tests/smoke.sh (traversal and external symlink rejection); malicious command-key test pending | IN_PROGRESS |
| SEA-FR-013 | Ed25519 detached signature + tenant scope + strict issued/expiry UTC timestamps; server signs exact policy bytes | tests/smoke.sh (operator publish/fetch, signature tamper, invalid calendar date); full expiry/wrong-scope matrix pending | IN_PROGRESS |
| SEA-FR-014 | positive integral safe revision, monotonic publish, and agent last-good DB | tests/smoke.sh (negative/fractional/unsafe revision rejection, invalid higher revision leaves prior state, next valid revision recovers); wrong-scope/expiry update matrix pending | IN_PROGRESS |
| SEA-FR-015 | validate policy then transactionally replace last-good document and write audit row; apply supported settings at runtime | Existing smoke covers last-good retention/recovery and policy gates. Code prepares a complete inotify watch tree before storing a collection-enabled policy and stages a separate watch FD before runtime replacement; failed preparation retains the previous active runtime state. These new paths remain unbuilt/unverified, and expiry-runtime coverage remains open | IN_PROGRESS |
| SEA-FR-016 | SQLite agent registry, certificate pin state, telemetry, heartbeat, status, health; operator-only policy publish and agent policy fetch | New admin enrollment/re-enrollment/rotation/revocation/status handlers and heartbeat registry data are implemented but not built or verified; prior policy/TLS paths were previously tested | IN_PROGRESS |
| SEA-FR-017 | strict `event.v1` allowlist, no target-file reads, per-store HMAC path pseudonyms, server sensitive-key rejection | `tests/smoke.sh` confirms raw path/content marker do not enter the queue, outside-root paths and unknown content fields are rejected, and pathless healthy file events fail closed | IMPLEMENTED |
| SEA-FR-018 | systemd units, PID stop, service controls | SEA-T-014 pending | IN_PROGRESS |
| SEA-FR-019 | logs omit key/token/payload values | source review pending | IN_PROGRESS |
| SEA-FR-020 | loopback-only bind/connect | SEA-T-016 pending | IMPLEMENTED |
| SEA-FR-021 | offline/restart/expiry/replay scenarios | `tests/smoke.sh` covers one offline queue + server restart + replay recovery; expiry and broader replay matrix pending | IN_PROGRESS |
| SEA-FR-022 | operator API supports pending certificate rotation, identity revocation, and re-enrollment | New registry routes use operator mTLS plus bearer token; zero-downtime lifecycle code has not been built or verified | IN_PROGRESS |
| SEA-FR-023 | JSON status/queue metrics | diagnostics pending | IN_PROGRESS |
| SEA-FR-024 | — | optional Go implementation | NOT_APPLICABLE |
| SEA-NFR-01..08 | docs/TEST_PLAN.md | selected integration paths only; throughput/resource/fault matrix not run | IN_PROGRESS |
