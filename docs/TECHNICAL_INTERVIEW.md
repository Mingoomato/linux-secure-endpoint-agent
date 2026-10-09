# Technical Defense — Linux Secure Endpoint Agent Lab

Questions only; no answer key is included. Defend identity, durability, and ACK behavior at each boundary.

## Code reading and data flow

1. Trace a synthetic heartbeat from `next_sequence`/`enqueue` to the `queue` row.
2. Which SQLite settings and transaction boundaries make the local queue durable?
3. How does `send_batch` select loopback addresses and configure DNS/IP SAN verification?
4. What does mutual TLS authenticate on the client and server sides?
5. How does `peer_cn` map a client certificate to an allowed agent, and what does the server compare with the batch `agent_id`?
6. Trace an event through `ingest` to the accepted or duplicate ACK. At what point is the server DB commit complete?
7. How does `flush` ensure the server cannot delete an event the agent did not send?
8. Which fields are included in stored telemetry, and which payload bytes are hashed?
9. Trace `validate_signed_policy` from raw-byte signature verification to policy-state transaction.

## Debugging and failure behavior

10. What happens when the server commits an event but the client does not receive its ACK?
11. If the server repeats an event ID with a changed sequence or payload hash, why is that not a harmless duplicate?
12. What happens when a response lacks `Content-Length`, exceeds the cap, or has malformed ACK JSON?
13. Which queue failure occurs when the row/byte quota is reached, and can the new event still be retained?
14. How can a process crash between sequence increment and event insert affect sequence values?
15. Which raw socket, `SSL*`, `SSL_CTX*`, SQLite handle, and statement cleanup paths would you review after an injected error?

## Security and privacy

16. Why is hostname/SAN verification needed even when the server certificate chain is trusted?
17. Why does server-side mTLS validation still require a local agent registry/allowlist?
18. Why does TLS authentication not replace an Ed25519 policy signature?
19. What does signing exact policy bytes imply for whitespace and canonicalization?
20. Which sensitive fields does the server reject, and why is a key-name blacklist not a complete privacy control?
21. What does a loopback-only bind prevent, and what attacks remain possible from local processes?
22. Which limitations follow from a sequential server and custom HTTP parser?

## Design tradeoffs

23. Compare CN allowlisting with certificate fingerprint, SAN URI identity, and managed enrollment.
24. How would a bounded concurrent worker pool affect socket pressure and SQLite contention?
25. What is the difference between durable policy storage and a successfully applied runtime policy?
26. Which tests are needed before claiming offline reconnect, certificate expiry handling, and key rotation?
27. Why do the current integration tests not establish production readiness or owner mastery?

Owner mastery requires direct evidence from an independently completed exercise and reasoned defense; build/test success alone is not proof.
