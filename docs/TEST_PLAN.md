# Test plan

- Build all three targets with GCC/Clang and inspect warnings.
- Run a loopback mTLS integration with the local CA; reject wrong CA, server SAN mismatch, expired certificate, unregistered CN, and claimed-ID mismatch.
- Stop the server before enqueue/flush; restart it and verify the durable queue is delivered.
- Replay a batch after commit and verify deduplication and per-ID queue deletion.
- Exercise malformed/oversized JSON, invalid number tokens, duplicate keys, non-JSON whitespace, depth limits, ambiguous HTTP framing, wrong/duplicate Content-Type, non-200 ACKs, a trickle ClientHello against the absolute TLS handshake deadline, idle partial-body timeout, a slow trickle client against the absolute HTTP request deadline, invalid ACK, retry bounds, queue quota, database write failure, and sensitive-field rejection.
- Sign valid, expired, tampered, stale, wrong-tenant, unsafe-root, and run_command policies; check last-good revision survives failed updates.
- Verify operator certificate plus bearer-token authorization, policy publish idempotency, ETag/304 fetch, invalid higher-revision rejection, and valid revision recovery.
- Verify runtime fail-closed behavior with no stored policy, tenant mismatch rejection, disabled telemetry preserving queued rows, `sample_rate=0` suppressing new synthetic events while allowing existing rows to flush, and `sample_rate=1` generating an event. Add expired-policy runtime and concurrent policy-update tests before claiming the full runtime policy matrix.
- Import a valid `event.v1` record under an active policy. Check queue/server payloads contain an HMAC path ID but no raw path or target-file content; reject paths outside monitored roots, unknown sensitive fields, and pathless healthy file events; allow pathless degraded coverage events; verify duplicate import and `sample_rate=0` behavior.
- Exercise malformed event fields, invalid UUID/time/numeric bounds, path normalization edge cases, HMAC-key permission failures, concurrent import writers, 100,000-ID dedup-ledger capacity, and transactional rollback on queue/disk failures.
- Confirm non-loopback bind/endpoint values are refused.
- Reject TLS handshake deadline settings below 100 ms or above 60,000 ms; verify both inclusive boundaries before using them in a live server test.
- Use static analysis and sanitizers on user-space code; record 10k-event throughput/RSS only after measurement.
- Build the isolated HTTP request parser with Clang libFuzzer, ASan, and UBSan; seed valid GET/POST and ambiguous Content-Length requests, then retain any minimized crash as a regression case.

GCC and Clang Release CTest suites and GCC/Clang ASan/UBSan CTest suites passed at 4/4 each, including strict JSON tests against both copies, direct bounded HTTP parser tests, selected malformed HTTP framing cases, and the runtime policy cases listed above. The loopback integration rejects an incomplete trickle ClientHello under a 1-second absolute TLS handshake deadline, rejects configured handshake limits of 99 and 60,001 ms, and also passed three consecutive runs with a slow trickle HTTP client rejected under the configured 1.5-second request deadline. The handshake deadline begins immediately before the first `SSL_accept` on an accepted socket; the HTTP deadline starts after TLS peer and CN authorization. Neither deadline bounds application route processing. Policy smoke cases verify distinct agent/operator authentication, policy publish 201 and identical publish 200, exact ETag/304, end-to-end agent sync, `..` traversal, external symlink, invalid calendar expiry, negative/fractional/unsafe revisions, last-good retention after a rejected higher revision, and recovery to a valid later revision. They do not yet exercise an expired stored policy or concurrent sync during an in-flight request. Clang static analysis reported no diagnostics for agent, server, and HTTP parser tests. The isolated parser passed a seeded 100,000-run Clang libFuzzer+ASan+UBSan campaign. That short run does not cover full HTTP grammar or all TLS/session states. Certificate expiry, wrong-SAN, queue-failure, rate/backpressure, and performance scenarios remain pending; restart/offline has one passing smoke path, not the extended matrix.

Fuzz build and replay commands:

```sh
cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=OFF -DSEA_BUILD_HTTP_FUZZER=ON
cmake --build build-fuzz --parallel
corpus_dir=$(mktemp -d)
cp -R tests/http_fuzz_corpus/. "$corpus_dir"/
./build-fuzz/sea-http-parser-fuzz -runs=100000 -max_len=16384 "$corpus_dir"
```

## 추가 구현 후 실행할 collector 확인 항목

아래 항목은 recursive inotify collector 구현을 위한 미실행 계획이다. 구현 코드가 추가된 뒤 사용자 지시에 따라 빌드나 테스트를 수행하지 않았다.

- Policy root 안에서 create, close-write, attribute, delete, rename 이벤트가 path HMAC만 포함해 durable queue에 쌓이는지 확인한다. Queue와 서버 payload에 raw path나 file content가 없어야 한다.
- Root 외부 symlink, symlink directory, 다른 device mount, directory rename, permission loss, inotify watch cap/overflow를 각각 재현하고 coverage degraded 동작을 확인한다.
- Running agent에서 revision/root replacement, telemetry disable, expiry, sample-rate update를 적용하고 queue retention/flush 계약을 확인한다.
- Agent/service stop, restart, `sync-policy` 동시 실행과 quota/full-disk 상황에서 FD, PID file, SQLite transaction lifetime을 관찰한다.
- Watch preflight가 접근 불가 하위 디렉터리, watch limit, inotify 초기화 실패에서 정책 commit을 막고 직전 last-good row를 보존하는지 확인한다.
- Runtime reload 중 watch 준비 실패가 기존 collector FD와 기존 정책을 유지하는지, 이후 더 높은 정상 revision에서 교체되는지 확인한다.
- Watch preflight 완료 뒤 root 권한/마운트가 바뀌는 경쟁 조건과 process restart 후 stored policy 적용을 확인한다.
- 구현된 파일 rename-cookie pair/mismatch/timeout 경로, 4,096 pending cap, overflow 시 보류 이벤트 배출을 확인한다. 디렉터리 이동은 pair되지 않는다. 누락 event history 복구는 구현되지 않았으므로 별도 baseline 설계가 필요하다.

## 추가 구현 후 실행할 agent registry 확인 항목

아래 lifecycle 경로는 구현됐으나 아직 실행 검증하지 않았다.

- Optional bootstrap UUID의 첫 CA-valid mTLS certificate fingerprint pin과 같은 CN의 다른 인증서 거부를 확인한다.
- Operator mTLS와 독립 bearer token 조합으로 신규 enroll, status, revoke, 신규 fingerprint re-enroll을 확인한다.
- Rotation 도중 current/pending 인증서를 모두 허용하고, pending 인증서 첫 성공 접속 시 current 승격 및 old cert retirement를 확인한다.
- Server restart 후 enabled/revoked 상태와 certificate history가 SQLite에서 유지되는지 확인한다.
- Malformed UUID/fingerprint, 다른 agent가 이미 사용하는 fingerprint, 등록되지 않은 certificate, 만료/미등록 CA certificate를 거부하고 민감 값을 로그에 남기지 않는지 확인한다.
