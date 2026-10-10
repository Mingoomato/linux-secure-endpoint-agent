# Requirements traceability (SRS-06)

The recorded loopback integration and parser tests verify selected mTLS, queue, deduplication, policy-signature, and strict JSON parsing paths. See `docs/TEST_RESULTS.md`; remaining SRS requirements are not implied by these tests.

| Requirement | Source / artifact | Verification | Status |
|---|---|---|---|
| SEA-FR-001 | server peer certificate CN + allowlist | tests/smoke.sh (mTLS authorization paths) | IN_PROGRESS |
| SEA-FR-002 | agent TLS peer verification with DNS/IP SAN | SEA-T-002 pending | IMPLEMENTED |
| SEA-FR-003 | TLS minimum TLS 1.2 | protocol test pending | IMPLEMENTED |
| SEA-FR-004 | CLI TLS inputs and bounds; JSON parser number, whitespace, duplicate-key, depth, and record-size limits | tests/json_parser_test.cpp; invalid config tests pending | IN_PROGRESS |
| SEA-FR-005 | agent command dispatch | CLI smoke pending | IN_PROGRESS |
| SEA-FR-006 | synthetic health event channel | SEA-T-004 pending | IMPLEMENTED |
| SEA-FR-007 | sequence, UUID, timestamp, payload hash | SEA-T-004 pending | IMPLEMENTED |
| SEA-FR-008 | SQLite WAL spool + per-ID ACK removal | tests/smoke.sh (acknowledgement and deduplication) | IMPLEMENTED |
| SEA-FR-009 | server unique key (agent,event) | SEA-T-005 pending | IMPLEMENTED |
| SEA-FR-010 | accepted/duplicate acknowledgement | SEA-T-005 pending | IMPLEMENTED |
| SEA-FR-011 | quotas and bounded retry | SEA-T-006/008 pending | IN_PROGRESS |
| SEA-FR-012 | allowlisted policy fields/actions | SEA-T-010 pending | IN_PROGRESS |
| SEA-FR-013 | Ed25519 detached signature + scope/expiry | tests/smoke.sh (signature tamper/replay) | IN_PROGRESS |
| SEA-FR-014 | monotonic revision and last-good DB | SEA-T-009 pending | IN_PROGRESS |
| SEA-FR-015 | validate then transactional last-good swap | SEA-T-011 pending | IN_PROGRESS |
| SEA-FR-016 | registry, telemetry, heartbeat, status, health routes; bounded HTTP/1.1 framing | `tests/smoke.sh` route subset + duplicate/invalid/oversized framing rejection | IN_PROGRESS |
| SEA-FR-017 | synthetic-only event schema; server sensitive-key rejection and strict JSON parsing | parser CTests; SEA-T-012 privacy tests pending | IN_PROGRESS |
| SEA-FR-018 | systemd units, PID stop, service controls | SEA-T-014 pending | IN_PROGRESS |
| SEA-FR-019 | logs omit key/token/payload values | source review pending | IN_PROGRESS |
| SEA-FR-020 | loopback-only bind/connect | SEA-T-016 pending | IMPLEMENTED |
| SEA-FR-021 | offline/restart/expiry/replay scenarios | `tests/smoke.sh` covers one offline queue + server restart + replay recovery; expiry and broader replay matrix pending | IN_PROGRESS |
| SEA-FR-022 | — | revocation not implemented | NOT_STARTED |
| SEA-FR-023 | JSON status/queue metrics | diagnostics pending | IN_PROGRESS |
| SEA-FR-024 | — | optional Go implementation | NOT_APPLICABLE |
| SEA-NFR-01..08 | docs/TEST_PLAN.md | not run | NOT_STARTED |
