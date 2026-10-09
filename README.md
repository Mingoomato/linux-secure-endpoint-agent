# Linux Secure Endpoint Agent Lab

[:kr: 한국어](#한국어) · [:us: English](#english)

## 한국어

이 저장소는 합성 상태 이벤트를 SQLite durable queue에 저장한 뒤, loopback mTLS로 제어 서버에 보내고 서버 ACK를 받은 이벤트만 큐에서 제거하는 학습용 endpoint agent/control server입니다. transport 인증(mTLS)과 정책 발급자 인증(분리된 Ed25519 서명)을 구분하고, 이벤트 중복 처리와 최소 수집 경계를 실습하도록 제작했습니다. 개인 파일 내용이나 임의 명령은 수집·실행하지 않습니다.

### 빌드 및 로컬 실습

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
./scripts/create-local-ca.sh /tmp/linuxsecurity-lab-certs
```

서버와 agent 실행 예시는 아래 English 섹션을 참고하세요. 인증서와 개인 키는 저장소 밖의 전용 실습 디렉터리에 만들며, 다른 용도로 재사용하거나 커밋하지 않습니다. 서버와 client는 loopback만 허용합니다.

### 검증 및 한계

현재 Release 빌드와 loopback 통합 및 JSON 파서 CTest 3/3, 별도 ASan/UBSan CTest 3/3이 통과했습니다. 시험은 로컬 mTLS, synthetic event 전송/ACK, 동일 이벤트 중복, ID 재사용 충돌, 미등록 client, 서명 정책 검증/변조/rollback, 양쪽 JSON 파서의 숫자 문법·공백·중복 키·깊이·크기 제한을 확인합니다. 운영 PKI/폐기, 만료·잘못된 SAN 인증서, 오프라인 후 서버 재시작, disk-full/quota, HTTP parser fuzz, 처리량은 검증하지 않았습니다.

서버는 단일 연결 순차 처리와 제한된 HTTP/1.1 parser를 사용합니다. JSON 파서는 RFC 8259 숫자 문법, 네 가지 JSON 공백, 중복 키 거부, 깊이와 1 MiB 크기 제한을 양쪽 프로그램에서 동일하게 적용하도록 각각 테스트합니다. operator RBAC, 인증서 폐기, admin 정책 배포·서명, 공개 네트워크 서비스, 실제 `event.v1` file input은 제공하지 않습니다. 로컬 정책의 서명·revision을 검증해 last-good 문서를 저장하지만, 그 정책을 endpoint의 파일 감시 hook에 적용하지는 않습니다. 자세한 범위는 [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), [`docs/KEY_MANAGEMENT.md`](docs/KEY_MANAGEMENT.md), [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md)를 참고하세요.

## English

This project pairs a C++20 endpoint queue and TLS client with a C++20 loopback control server and a small C POSIX socket exercise. It demonstrates synthetic health telemetry, mutually authenticated TLS, SQLite durable spooling, per-event acknowledgements, server-side deduplication, and detached Ed25519 policy validation.

## Build

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build --parallel

Dependencies are OpenSSL 3 development files, SQLite3 development files, CMake, and C17/C++20 compilers.

## Local lab

Generate credentials outside the source tree:

    ./scripts/create-local-ca.sh /tmp/linuxsecurity-lab-certs
    ./build/sw-server run --bind 127.0.0.1 --port 8443 --ca /tmp/linuxsecurity-lab-certs/ca.crt --cert /tmp/linuxsecurity-lab-certs/server.crt --key /tmp/linuxsecurity-lab-certs/server.key --agents /tmp/linuxsecurity-lab-certs/agents.txt --db /tmp/linuxsecurity-lab-certs/server.sqlite

In another terminal:

    ./build/sw-agentd run --endpoint 127.0.0.1 --port 8443 --agent-id 00000000-0000-4000-8000-000000000001 --ca /tmp/linuxsecurity-lab-certs/ca.crt --cert /tmp/linuxsecurity-lab-certs/agent.crt --key /tmp/linuxsecurity-lab-certs/agent.key --store /tmp/linuxsecurity-lab-certs/agent-state

The server refuses non-loopback binding. The agent also restricts the destination to loopback. Keep all generated private keys outside the repository and remove them after the lab.

## Policy validation

The agent accepts only detached raw 64-byte Ed25519 signatures over the exact policy file bytes. It rejects unknown fields/actions, stale revisions, expiry, wrong tenant scope, and monitored roots outside the supplied root. A valid last-good policy is committed transactionally to the local SQLite store. The reference server returns no policy and disables the admin policy publishing route in this version.

Run `ctest --test-dir build --output-on-failure` for the mTLS/policy integration and two parser suites. They cover authorized local TLS, event delivery and acknowledgement, deduplication, conflicting event-ID rejection, unregistered client rejection, signed policy validation/tamper/rollback, plus strict JSON number/whitespace grammar, duplicate keys, nesting, and size limits in both agent and server parser copies. Payload hashes use compact JSON with lexicographically sorted object keys.

## Limitations

The initial server handles one client at a time, has a minimal HTTP/1.1 parser, and does not implement operator authentication/RBAC, certificate revocation, policy distribution/signing, rate limiting, 429 backpressure, or event.v1 file input. The batch accepts only small synthetic health events. There is no remote command or process execution path. See `docs/TEST_RESULTS.md`; no performance result is claimed.
