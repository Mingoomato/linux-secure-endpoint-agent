# Test plan

- Build all three targets with GCC/Clang and inspect warnings.
- Run a loopback mTLS integration with the local CA; reject wrong CA, server SAN mismatch, expired certificate, unregistered CN, and claimed-ID mismatch.
- Stop the server before enqueue/flush; restart it and verify the durable queue is delivered.
- Replay a batch after commit and verify deduplication and per-ID queue deletion.
- Exercise malformed/oversized JSON, invalid number tokens, duplicate keys, non-JSON whitespace, depth limits, ambiguous HTTP framing, wrong/duplicate Content-Type, non-200 ACKs, partial HTTP body timeout, invalid ACK, retry bounds, queue quota, database write failure, and sensitive-field rejection.
- Sign valid, expired, tampered, stale, wrong-tenant, unsafe-root, and run_command policies; check last-good revision survives failed updates.
- Confirm non-loopback bind/endpoint values are refused.
- Use static analysis and sanitizers on user-space code; record 10k-event throughput/RSS only after measurement.
- Build the isolated HTTP request parser with Clang libFuzzer, ASan, and UBSan; seed valid GET/POST and ambiguous Content-Length requests, then retain any minimized crash as a regression case.

GCC and Clang Release CTest suites and ASan/UBSan CTest suite have passed at 4/4, including strict JSON tests against both copies, direct bounded HTTP parser tests, and selected malformed HTTP framing cases. Clang static analysis reported no diagnostics. The isolated parser passed a seeded 50,000-run Clang libFuzzer+ASan+UBSan campaign. That short run does not cover the full HTTP grammar or TLS/session state machine. Certificate expiry, wrong-SAN, queue-failure, rate/backpressure, and performance scenarios remain pending; restart/offline has one passing smoke path, not the extended matrix.

Fuzz build and replay commands:

```sh
cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=OFF -DSEA_BUILD_HTTP_FUZZER=ON
cmake --build build-fuzz --parallel
corpus_dir=$(mktemp -d)
cp -R tests/http_fuzz_corpus/. "$corpus_dir"/
./build-fuzz/sea-http-parser-fuzz -runs=50000 -max_len=16384 "$corpus_dir"
```
