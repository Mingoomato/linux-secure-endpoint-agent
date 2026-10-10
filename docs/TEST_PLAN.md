# Test plan

- Build all three targets with GCC/Clang and inspect warnings.
- Run a loopback mTLS integration with the local CA; reject wrong CA, server SAN mismatch, expired certificate, unregistered CN, and claimed-ID mismatch.
- Stop the server before enqueue/flush; restart it and verify the durable queue is delivered.
- Replay a batch after commit and verify deduplication and per-ID queue deletion.
- Exercise malformed/oversized JSON, invalid number tokens, duplicate keys, non-JSON whitespace, depth limits, ambiguous HTTP framing, wrong/duplicate Content-Type, non-200 ACKs, partial HTTP body timeout, invalid ACK, retry bounds, queue quota, database write failure, and sensitive-field rejection.
- Sign valid, expired, tampered, stale, wrong-tenant, unsafe-root, and run_command policies; check last-good revision survives failed updates.
- Verify operator certificate plus bearer-token authorization, policy publish idempotency, ETag/304 fetch, invalid higher-revision rejection, and valid revision recovery.
- Confirm non-loopback bind/endpoint values are refused.
- Use static analysis and sanitizers on user-space code; record 10k-event throughput/RSS only after measurement.
- Build the isolated HTTP request parser with Clang libFuzzer, ASan, and UBSan; seed valid GET/POST and ambiguous Content-Length requests, then retain any minimized crash as a regression case.

GCC and Clang Release CTest suites and GCC/Clang ASan/UBSan CTest suites passed at 4/4 each, including strict JSON tests against both copies, direct bounded HTTP parser tests, and selected malformed HTTP framing cases. Policy smoke cases verify distinct agent/operator authentication, policy publish 201 and identical publish 200, exact ETag/304, end-to-end agent sync, `..` traversal, external symlink, invalid calendar expiry, negative/fractional/unsafe revisions, last-good retention after a rejected higher revision, and recovery to a valid later revision. Clang static analysis reported no diagnostics for agent, server, and HTTP parser tests. The isolated parser passed a seeded 100,000-run Clang libFuzzer+ASan+UBSan campaign. That short run does not cover full HTTP grammar or TLS/session state. Certificate expiry, wrong-SAN, queue-failure, rate/backpressure, and performance scenarios remain pending; restart/offline has one passing smoke path, not the extended matrix.

Fuzz build and replay commands:

```sh
cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=OFF -DSEA_BUILD_HTTP_FUZZER=ON
cmake --build build-fuzz --parallel
corpus_dir=$(mktemp -d)
cp -R tests/http_fuzz_corpus/. "$corpus_dir"/
./build-fuzz/sea-http-parser-fuzz -runs=100000 -max_len=16384 "$corpus_dir"
```
