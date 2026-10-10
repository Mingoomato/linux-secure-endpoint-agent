# Test plan

- Build all three targets with GCC/Clang and inspect warnings.
- Run a loopback mTLS integration with the local CA; reject wrong CA, server SAN mismatch, expired certificate, unregistered CN, and claimed-ID mismatch.
- Stop the server before enqueue/flush; restart it and verify the durable queue is delivered.
- Replay a batch after commit and verify deduplication and per-ID queue deletion.
- Exercise malformed/oversized JSON, invalid number tokens, duplicate keys, non-JSON whitespace, depth limits, ambiguous HTTP framing, partial HTTP body timeout, invalid ACK, retry bounds, queue quota, database write failure, and sensitive-field rejection.
- Sign valid, expired, tampered, stale, wrong-tenant, unsafe-root, and run_command policies; check last-good revision survives failed updates.
- Confirm non-loopback bind/endpoint values are refused.
- Use static analysis and sanitizers on user-space code; record 10k-event throughput/RSS only after measurement.

GCC and Clang Release CTest suites and ASan/UBSan CTest suite have passed, including strict JSON parser tests against both copies and selected malformed HTTP framing cases. Clang static analysis reported no diagnostics. Certificate expiry, wrong-SAN, restart/offline, parser fuzzing, queue-failure, rate/backpressure, and performance scenarios remain pending.
