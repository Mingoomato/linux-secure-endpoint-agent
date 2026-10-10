# Linux Secure Endpoint Agent Lab

[:kr: 한국어](#한국어) · [:us: English](#english)

## 한국어

이 저장소는 합성 상태 이벤트를 SQLite durable queue에 저장한 뒤, loopback mTLS로 제어 서버에 보내고 서버 ACK를 받은 이벤트만 큐에서 제거하는 학습용 endpoint agent/control server입니다. 운영자 전용 API는 별도 operator 인증서 allowlist와 bearer token을 확인하며, 서버는 제한된 정책을 Ed25519로 서명해 게시합니다. Agent는 조건부 정책 fetch(ETag/304), 서명·범위 검증, last-good 저장을 수행합니다. transport 인증(mTLS)과 정책 발급자 인증(분리된 Ed25519 서명)을 구분하고, 이벤트 중복 처리와 최소 수집 경계를 실습하도록 제작했습니다. 개인 파일 내용이나 임의 명령은 수집·실행하지 않습니다.

### 빌드 및 로컬 실습

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
./scripts/create-local-ca.sh /tmp/linuxsecurity-lab-certs
```

서버 시작 명령, 운영자 API 호출, `sync-policy` 예시는 아래 English 섹션을 참고하세요. 인증서와 개인 키는 저장소 밖의 전용 실습 디렉터리에 만들며, 다른 용도로 재사용하거나 커밋하지 않습니다. 서버와 client는 loopback만 허용합니다.

### 검증 및 한계

GCC와 Clang 21.1.8 Release 및 AddressSanitizer/UndefinedBehaviorSanitizer 빌드, 네 구성의 CTest 4/4, Clang 정적 분석이 통과했습니다. 시험은 로컬 mTLS, event 전송/ACK, deduplication, ID 재사용 충돌, 미등록 client, operator 인증 분리, 정책 게시 201/idempotent 200, 조건부 fetch 304, 에이전트 정책 동기화, 잘못된 후속 정책 거부와 last-good 복구, signature/경로/date/revision 오류, 양쪽 JSON parser, HTTP framing을 확인합니다. 1.5초 요청 기한 아래 byte를 조금씩 보내는 slow client가 종료되는지도 검사합니다. Agent는 활성 정책이 없거나 telemetry가 비활성화되었을 때 새 합성 이벤트를 만들지 않고, 전송을 멈추면서 기존 큐를 보존합니다. `sample_rate=0`은 새 이벤트 생성을 막지만, telemetry가 활성 상태면 이미 저장된 이벤트는 전송합니다. 서버 중단 중 event 보존 후 재시작/재전송도 확인합니다. HTTP parser는 seed corpus 기반 Clang libFuzzer+ASan+UBSan 100,000회 실행을 통과했지만 전체 HTTP grammar나 장시간 안정성을 증명하지 않습니다. `monitored_roots`는 검증·상태 보고만 하며 실제 파일 감시기는 없습니다. 인증서 폐기·운영 enrollment, 확장 offline/restart와 expiry/replay 행렬, disk-full/quota, 동시성·처리량은 검증하지 않았습니다.

서버는 단일 연결 순차 처리와 제한된 HTTP/1.1 parser를 사용합니다. HTTP header/body 상한은 각각 16 KiB/1 MiB이고, 개별 socket I/O는 5초로 제한합니다. TLS peer 인증서와 CN allowlist 확인 뒤 HTTP header/body 수신에 기본 10초 절대 deadline을 적용하며 `--request-deadline-ms`로 100–60,000 ms 범위에서 설정할 수 있습니다. 이 deadline은 TLS handshake와 route 처리 시간을 포함하지 않습니다. JSON parser는 RFC 8259 숫자 문법, JSON 공백, 중복 키 거부, 깊이와 1 MiB 크기 제한을 적용합니다. operator 권한은 lab용 인증서 allowlist와 bearer token 조합으로 제한되며, production RBAC·인증서 폐기·온라인 enrollment는 제공하지 않습니다. 정책은 서명·revision을 검증해 last-good 상태로 원자 저장하고, 실행 중에는 tenant·expiry·`telemetry_enabled`·`sample_rate`를 합성 이벤트 생성 및 큐 전송 게이트에 적용합니다. `monitored_roots`는 개수와 범위만 검증하며 실제 파일 감시기는 없습니다. 공개 네트워크 서비스와 실제 `event.v1` file input도 범위 밖입니다. 제작 의도, 코드 흐름, Linux 내부, 학습·독립 재현 과제와 기술 방어 질문은 아래 문서에 정리했습니다.

- [`docs/ENGINEERING_STUDY_GUIDE.md`](docs/ENGINEERING_STUDY_GUIDE.md)
- [`docs/CODE_WALKTHROUGH.md`](docs/CODE_WALKTHROUGH.md)
- [`docs/LINUX_INTERNALS_EXPLAINED.md`](docs/LINUX_INTERNALS_EXPLAINED.md)
- [`docs/DEBUGGING_EXERCISES.md`](docs/DEBUGGING_EXERCISES.md)
- [`docs/TECHNICAL_INTERVIEW.md`](docs/TECHNICAL_INTERVIEW.md)
- [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md)

## English

This project pairs a C++20 endpoint queue and TLS client with a C++20 loopback control server and a small C POSIX socket exercise. It was built as a contained learning lab for synthetic health telemetry, mutually authenticated TLS, SQLite durable spooling, per-event acknowledgements, server-side deduplication, strict bounded HTTP framing, and detached Ed25519 policy validation. It deliberately does not collect user files or execute remote commands.

## Build

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build --parallel

Dependencies are OpenSSL 3 development files, SQLite3 development files, CMake, and C17/C++20 compilers.

## Local lab

Generate credentials outside the source tree:

    ./scripts/create-local-ca.sh /tmp/linuxsecurity-lab-certs
    umask 077
    openssl rand -hex 32 > /tmp/linuxsecurity-lab-certs/admin.token
    ./build/sw-server run --bind 127.0.0.1 --port 8443 --ca /tmp/linuxsecurity-lab-certs/ca.crt --cert /tmp/linuxsecurity-lab-certs/server.crt --key /tmp/linuxsecurity-lab-certs/server.key --agents /tmp/linuxsecurity-lab-certs/agents.txt --operators /tmp/linuxsecurity-lab-certs/operators.txt --admin-token-file /tmp/linuxsecurity-lab-certs/admin.token --policy-key /tmp/linuxsecurity-lab-certs/policy-signing.key --tenant lab-tenant --request-deadline-ms 10000 --db /tmp/linuxsecurity-lab-certs/server.sqlite

Keep the server running in its terminal. The server refuses non-loopback binding, and the agent also restricts its destination to loopback. Keep all generated private keys and the bearer token outside the repository and remove them after the lab. The generated operator certificate alone is insufficient: the publish API requires that mTLS identity and the separately provisioned token.

In an operator-authorized terminal, prepare a minimal policy and create the allowed root:

    mkdir -p /tmp/allowed-root
    cat > /tmp/linuxsecurity-lab-certs/policy.json <<'JSON'
    {"schema_version":"policy.v1","policy_id":"local-lab","revision":1,"issuer":"local-operator","issued_at":"2026-10-10T00:00:00Z","expires_at":"2099-01-01T00:00:00Z","tenant_scope":"lab-tenant","allowed_actions":["telemetry.configure","monitor.roots.configure"],"settings":{"telemetry_enabled":true,"sample_rate":1,"monitored_roots":["/tmp/allowed-root"]}}
    JSON

Publish a policy from an operator-authorized terminal:

    curl --cacert /tmp/linuxsecurity-lab-certs/ca.crt --cert /tmp/linuxsecurity-lab-certs/operator.crt --key /tmp/linuxsecurity-lab-certs/operator.key -H "Authorization: Bearer $(cat /tmp/linuxsecurity-lab-certs/admin.token)" -H 'Content-Type: application/json' --data-binary @/tmp/linuxsecurity-lab-certs/policy.json https://127.0.0.1:8443/v1/admin/policies

The new policy returns `201`; an identical publication returns `200`. The server signs the exact policy bytes and stores one monotonic revision per configured tenant. Sync it on the agent:

    ./build/sw-agentd sync-policy --endpoint 127.0.0.1 --port 8443 --agent-id 00000000-0000-4000-8000-000000000001 --ca /tmp/linuxsecurity-lab-certs/ca.crt --cert /tmp/linuxsecurity-lab-certs/agent.crt --key /tmp/linuxsecurity-lab-certs/agent.key --store /tmp/linuxsecurity-agent-state --pubkey /tmp/linuxsecurity-lab-certs/policy-signing.pub --tenant lab-tenant --root /tmp/allowed-root

Agent fetch uses a SHA-256 ETag; an unchanged policy returns `304` and avoids reparsing. A new response must pass Ed25519, schema, expiry, tenant, monotonic revision, and canonical monitored-root checks before the last-good document and audit row are committed together.

Only after publishing and syncing an active policy, run the agent with the same tenant and store:

    ./build/sw-agentd run --endpoint 127.0.0.1 --port 8443 --agent-id 00000000-0000-4000-8000-000000000001 --ca /tmp/linuxsecurity-lab-certs/ca.crt --cert /tmp/linuxsecurity-lab-certs/agent.crt --key /tmp/linuxsecurity-lab-certs/agent.key --store /tmp/linuxsecurity-agent-state --tenant lab-tenant

Without a stored policy, or with an expired/telemetry-disabled policy, the agent fails closed: it does not generate a new synthetic event and pauses queue transmission while retaining queued rows. A policy with `sample_rate` set to `0` suppresses new events; if `telemetry_enabled` remains true, previously queued events may still be sent.

## Policy validation

The agent accepts only detached raw 64-byte Ed25519 signatures over the exact policy file bytes. It rejects unknown fields/actions, malformed or expired UTC timestamps, non-positive/fractional/unsafe JSON revisions, stale revisions, wrong tenant scope, and monitored roots outside the supplied root after resolving existing filesystem paths and symlinks. The operator-only server route validates the tenant and restricted policy schema, signs the exact bytes, and stores a monotonic revision. Agent fetch supports `200` and conditional `304`; a new valid last-good document and audit record are committed transactionally. Runtime reads recheck the stored tenant, revision, schema, expiry, settings, and allowed actions. `telemetry_enabled` gates both synthetic event creation and queue flushing; `sample_rate` gates only new synthetic events. `monitored_roots` are validated and counted but no file watcher consumes them, so this is not file-integrity monitoring. Path validation is not a race-free filesystem enforcement boundary.

Run `ctest --test-dir build --output-on-failure` for the mTLS/policy integration and three parser suites. They cover authorized local TLS, event delivery and acknowledgement, deduplication, conflicting event-ID rejection, unregistered client rejection, signed policy validation/tamper/rollback, no-policy fail-closed behavior, telemetry-disable queue retention, `sample_rate=0` suppression of new events while flushing existing rows, strict JSON parsing in both copies, direct HTTP request parsing, malformed HTTP framing, Content-Type rejection, a slow-client absolute request deadline, non-200 ACK rejection with queue retention, and one offline/server-restart recovery path. The HTTP header/body receive deadline starts after TLS peer and CN authorization; it does not include handshake or route processing. Payload hashes use compact JSON with lexicographically sorted object keys. GCC Release, Clang Release, and ASan/UBSan CTest runs are recorded in `docs/TEST_RESULTS.md`.

To build the optional isolated HTTP parser fuzzer with Clang, configure with `-DBUILD_TESTING=OFF -DSEA_BUILD_HTTP_FUZZER=ON`, copy `tests/http_fuzz_corpus` to a temporary directory, and run `./build-fuzz/sea-http-parser-fuzz -runs=100000 -max_len=16384 <temporary-corpus>`. libFuzzer adds interesting inputs to the corpus, so this keeps the checked-in seeds unchanged. The recorded run is a short development campaign, not a proof of parser completeness.

## Limitations

The server handles one client at a time and implements a limited HTTP/1.1 subset with 16 KiB headers, 1 MiB bodies, Content-Length-only framing, and JSON event batches. After TLS peer and CN authorization, receiving the full HTTP header/body has a 10 second absolute deadline by default (100–60,000 ms configurable); individual socket I/O is capped at 5 seconds. The TLS handshake and route processing are outside that receive deadline. The TLS handshake itself has only per-I/O limits. The agent accepts only HTTP 200 for event ACKs, while policy fetch accepts 200/304. This is not a general HTTP server. Operator auth is a local allowlist plus bearer token, not production RBAC. Runtime gating of synthetic telemetry is implemented for `telemetry_enabled` and `sample_rate`; actual `monitored_roots` file collection, certificate revocation, enrollment lifecycle, 429 backpressure, the extended offline/restart/expiry/replay matrix, and event.v1 file input remain unimplemented or unverified. A basic offline queue followed by restart/replay is covered by smoke tests. The batch accepts only small synthetic health events. There is no remote command or process execution path. See `docs/TEST_RESULTS.md`; no performance result is claimed.
