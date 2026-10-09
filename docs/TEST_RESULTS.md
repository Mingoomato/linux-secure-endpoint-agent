# Test results

Status: build and loopback integration smoke test passed on the current Linux host.

- Release configure/build: passed for the C17 probe and C++20 agent/server with OpenSSL and SQLite3.
- `ctest --test-dir build --output-on-failure`: 1/1 passed.
- Separate AddressSanitizer/UndefinedBehaviorSanitizer debug build and the same loopback smoke test: passed.
- The integration test generated local test credentials; completed an authorized mTLS health request; sent one synthetic agent event and confirmed its durable queue was acknowledged; checked server storage; verified same-ID/same-content deduplication and rejection of same-ID/different-content; confirmed an unregistered client did not receive a successful response; accepted a valid signed policy; rejected a tampered signature and a repeated policy revision.

Not run: production PKI/revocation, expired and wrong-SAN certificates, server restart/offline queue recovery, malformed/oversized HTTP bodies, disk-full and quota cases, extended sanitizer/static analysis, or throughput/RSS tests. The test service binds loopback and is not a production control plane.
