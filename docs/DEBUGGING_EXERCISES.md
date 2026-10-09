# Debugging and Independent Reproduction Exercises

These exercises are unsolved. No answer key or complete patch is present. Use only the local loopback lab and throwaway credentials generated outside the repository.

## Exercise 1 — Lost ACK, server restart, and durable retry

**Goal:** Prove the queue survives a lost response and a server restart without losing or duplicating committed event content.

**Starting points:** `enqueue`, `pending`, `send_batch`, `ack_ids`, `flush`, server `ingest`, and `docs/TEST_PLAN.md`.

Create a test seam that lets the server commit an event and close the connection before writing the ACK. Stop/restart the local server, run `flush` again, and inspect queue/server DB rows and accepted/duplicate IDs.

**Constraints:** Keep the server on loopback. Do not delete the agent DB between attempts. Never acknowledge an ID that was not in the submitted batch.

**Acceptance:** The client retains the event after ambiguous ACK, resubmits it, the server confirms the identical duplicate, and the client removes only that row after the confirmed response.

## Exercise 2 — Certificate identity and SAN rejection matrix

**Goal:** Test chain trust, hostname/IP SAN, expiration, and client identity as separate checks.

**Starting points:** `client_context`, `send_batch`, server TLS verification, `peer_cn`, allowlist, `scripts/create-local-ca.sh`.

Generate local-only certificates for: trusted CA + correct DNS SAN, trusted CA + wrong SAN, untrusted CA, expired server certificate, registered client identity, and unregistered CN. Record handshake result separately from HTTP authorization result.

**Constraints:** Do not weaken hostname verification or disable client-certificate requirements. Keep generated key material in a temporary directory and remove it after the lab.

**Acceptance:** Wrong chain/SAN/expiry fails TLS; an unregistered but otherwise trusted client is not authorized; each outcome has a distinct expected layer.

## Exercise 3 — Signed policy last-good preservation

**Goal:** Verify that invalid policy input cannot replace the last valid revision.

**Starting points:** `validate_signed_policy`, `policy_state`, signature exact-byte semantics, `tests/smoke.sh`.

Install a valid revision, then test tampered bytes, expired policy, wrong tenant, root escape, unknown field/action, and rollback revision. Query the database after each attempt and confirm the last-good document/revision remains unchanged.

**Constraints:** Use a throwaway signing key. Never add command execution or filesystem-wipe actions. Do not confuse persistence with runtime policy enforcement.

**Acceptance:** Each invalid policy is rejected, the prior revision remains intact, and the test explicitly says the stored policy is not yet consumed by an enforcement hook.

## Owner attempt record

Record the chosen exercise, credential generation details without private key contents, logs/DB evidence, and unresolved risks in personal notes. Owner reproduction status is **not yet evidenced**.
