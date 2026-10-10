# 검증 보고서 — SRS-06 Secure Endpoint Agent Control Server

## 요약

- **구현 상태:** 부분 구현. 이 저장소는 교육용 loopback agent/control server이며 SRS 전체 기능을 구현했다고 주장하지 않습니다.
- **기술 검증 상태:** GCC/Clang Release·ASan/UBSan 통합 게이트와 선택한 policy/TLS/HTTP 회귀 경로 통과. 절대 TLS handshake deadline과 합성 telemetry의 `telemetry_enabled`·`sample_rate` gate는 검증했지만 실제 monitored-root collector, enrollment/revocation, 장애·성능·배포 행렬 등 SRS 게이트는 미완료입니다.
- **소유자 학습/독립 재현 상태:** 관찰되지 않음. 자동 테스트 성공은 개인 숙련도 증거가 아닙니다.

## 실행한 검증

| 검증 | 결과 |
|---|---|
| GCC C17/C++20 Release 빌드 | 통과 |
| GCC Release CTest | 4/4 통과 |
| Clang 21.1.8 Release 빌드와 CTest | 4/4 통과 |
| GCC 16.2 및 Clang 21.1.8 AddressSanitizer + UndefinedBehaviorSanitizer 빌드/CTest | 각각 4/4 통과 |
| Agent/Server JSON parser 각각의 CTest | 통과. 숫자 grammar, JSON whitespace, 중복 key, 깊이/크기 제한 포함 |
| loopback mTLS/policy/queue integration | 통과. event ACK/dedup/ID 충돌과 미등록 client 거부; operator certificate+bearer token 권한 분리; 새 policy 게시 201 및 동일 재게시 200; 정확한 ETag 조건부 fetch 304; agent `sync-policy`; 서명된 잘못된 higher revision의 path-scope 거부 뒤 last-good revision/audit 보존, 후속 valid revision 저장; signature tamper/replay, `..` path traversal·외부 symlink·잘못된 calendar expiry·음수/분수/unsafe revision 거부; offline queue와 재시작 후 replay 포함 |
| runtime policy gating | 통과. 정책 없는 store에서는 이벤트를 만들지 않고 상태가 `NO_POLICY`; tenant mismatch는 run을 거부; telemetry 비활성 정책은 queue 전송을 멈추고 행을 보존; telemetry 활성 + `sample_rate=0`은 새 이벤트를 만들지 않으면서 기존 행은 전송; `sample_rate=1`의 합성 이벤트 생성/전송 경로 포함 |
| absolute TLS handshake deadline | 통과. `--handshake-deadline-ms 1000`에서 불완전 ClientHello record를 조금씩 보내는 peer가 종료되며 이후 mTLS/정책 시험 요청은 계속 처리됨. 기본값 10초, 허용 범위 100–60,000 ms이고 99/60,001 ms 설정은 거부됨 |
| HTTP framing 및 media-type 음성 통합 | 통과. 중복/잘못된 Content-Length, 초과 body 길이, Transfer-Encoding, POST 길이 누락, HTTP/1.0, GET body, 중복 Host/Content-Type, 누락/잘못된 Content-Type, header 초과, 미완성 body timeout, 1.5초 전체 HTTP request deadline에 대한 slow-client 거부, HTTP 400 ACK 거부와 queue 보존 확인 |
| HTTP parser 직접 단위 테스트 | 통과. 정상 GET/POST, 불완전 head/body, line/header 오류, duplicate framing, 상한, 잘림·추가 바이트 확인 |
| Clang libFuzzer + ASan/UBSan | 기존 로컬 corpus 233개 seed를 시작점으로 `max_len=16384`에서 100,000회 완료, crash/sanitizer finding 없음. coverage 643, feature count 2,347로 끝난 짧은 개발 campaign |
| Clang 정적 분석 | agent, server, 분리 HTTP parser 시험 코드에서 진단 없음 |
| smoke script 구문과 `git diff --check` | 통과 |

TLS handshake는 accepted socket을 nonblocking으로 바꾸고 OpenSSL의 `SSL_ERROR_WANT_READ`/`WANT_WRITE`에 따라 `poll()`합니다. 기본 절대 기한은 10초이며 `--handshake-deadline-ms`로 100–60,000 ms 범위를 설정할 수 있고 범위 밖 99/60,001 ms는 거부됩니다. 1초 설정에서 incomplete ClientHello를 trickle하는 client가 기한 내 종료되는지 확인했고 server는 이후 연결을 계속 받았습니다. HTTP framing 시험은 TLS 연결 후 실제 server parser의 400 응답을 확인합니다. header 제한은 16 KiB, body 제한은 1 MiB, accepted socket 개별 I/O timeout은 5초입니다. 기본 HTTP header/body 수신 deadline은 TLS peer 및 CN allowlist 확인 뒤 시작하는 10초이며 CLI에서 100–60,000 ms로 조절합니다. 반복 slow-client는 1.5초 설정의 절대 deadline 안에 종료됐고, HTTP deadline은 handshake와 route 처리를 포함하지 않습니다. 두 deadline은 route 실행을 제한하지 않습니다. Agent의 정상 200 ACK와 실제 server의 400 response 거부·queue 보존도 GCC/Clang 및 sanitizer 통합 시험에 포함됩니다. Policy conditional GET은 실제 SHA-256 ETag에 대해 304와 빈 body를 확인합니다. 별도의 mock server status matrix는 아직 없습니다.

## 실행 재현 명령

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure

cmake -S . -B build-clang -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release
cmake --build build-clang --parallel
ctest --test-dir build-clang --output-on-failure

cmake -S . -B build-asan-clang -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
cmake --build build-asan-clang --parallel
ctest --test-dir build-asan-clang --output-on-failure

cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
cmake --build build-asan --parallel
ctest --test-dir build-asan --output-on-failure

cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=OFF -DSEA_BUILD_HTTP_FUZZER=ON
cmake --build build-fuzz --parallel
corpus_dir=$(mktemp -d)
cp -R tests/http_fuzz_corpus/. "$corpus_dir"/
./build-fuzz/sea-http-parser-fuzz -runs=100000 -max_len=16384 "$corpus_dir"
```

## 아직 검증하지 않은 항목

- 만료 server/client 인증서, 잘못된 SAN, 다른 CA, certificate rotation/revocation 및 enrollment lifecycle; malformed calendar expiry는 거부하지만 expired-policy matrix는 미검증
- 확장 server/agent 재시작 및 장시간 offline 행렬, expiry/replay 조합, ACK 유실 fault injection (기본 offline queue와 server restart 한 경로는 smoke에서 통과)
- full HTTP grammar, long-duration parser fuzzing, route-duration deadline, worker pool/동시 연결 부하
- event/file input, queue quota·disk-full·DB write failure와 retry/backpressure 429 계약
- production operator RBAC, certificate enrollment/rotation/revocation and denylist lifecycle
- `monitored_roots` applied to a real file watcher/collector; current behavior validates/counts roots only. Expired stored-policy runtime gating and concurrent update during an in-flight batch also need direct tests.
- 10k event 처리량, p95/p99, CPU/RSS, 장시간 soak, 여러 배포판/커널 행렬
- 전체 SRS NFR 검증 및 systemd 설치·실행·권한 경계의 실제 호스트 통합

상세 요구사항별 현황은 [`REQUIREMENTS_TRACEABILITY.md`](REQUIREMENTS_TRACEABILITY.md), 수행 예정인 검증은 [`TEST_PLAN.md`](TEST_PLAN.md), 구현·학습 설명은 [`ENGINEERING_STUDY_GUIDE.md`](ENGINEERING_STUDY_GUIDE.md)를 참고하세요.
