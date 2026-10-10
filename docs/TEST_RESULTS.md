# 검증 보고서 — SRS-06 Secure Endpoint Agent Control Server

## 요약

- **구현 상태:** 부분 구현. 이 저장소는 교육용 loopback agent/control server이며 SRS 전체 기능을 구현했다고 주장하지 않습니다.
- **기술 검증 상태:** 선택된 host-side 빌드·통합·정적 분석 게이트 통과. 운영 PKI, 재시작/offline, 고장 주입, fuzz, 처리량 등 SRS 행렬은 미완료입니다.
- **소유자 학습/독립 재현 상태:** 관찰되지 않음. 자동 테스트 성공은 개인 숙련도 증거가 아닙니다.

## 실행한 검증

| 검증 | 결과 |
|---|---|
| GCC C17/C++20 Release 빌드 | 통과 |
| GCC Release CTest | 3/3 통과 |
| Clang 21.1.8 Release 빌드와 CTest | 3/3 통과 |
| AddressSanitizer + UndefinedBehaviorSanitizer 빌드/CTest | 3/3 통과 |
| Agent/Server JSON parser 각각의 CTest | 통과. 숫자 grammar, JSON whitespace, 중복 key, 깊이/크기 제한 포함 |
| loopback mTLS/policy/queue integration | 통과. event ACK, 동일 내용 dedup, ID 내용 충돌 거부, 미등록 client 거부, policy signature/tamper/replay, offline queue 보존과 server 재시작 후 replay 포함 |
| HTTP framing 음성 통합 | 통과. 중복/잘못된 Content-Length, 초과 body 길이, Transfer-Encoding, POST 길이 누락, HTTP/1.0, GET body, 중복 Host, header 초과, 미완성 body timeout 확인 |
| Clang 정적 분석 | 두 C++ 프로그램 모두 진단 없음 |
| smoke script 구문과 `git diff --check` | 통과 |

HTTP framing 시험은 TLS 연결 후 실제 server parser의 400 응답을 확인합니다. header 제한은 16 KiB, body 제한은 1 MiB, accepted socket I/O timeout은 5초입니다. Agent의 정상 ACK 응답 경로도 GCC/Clang 및 sanitizer 통합 시험에 포함됩니다. 별도의 악성 응답을 주는 mock server 행렬은 아직 없습니다.

## 실행 재현 명령

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure

cmake -S . -B build-clang -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release
cmake --build build-clang --parallel
ctest --test-dir build-clang --output-on-failure

cmake --build build-asan --parallel
ctest --test-dir build-asan --output-on-failure
```

## 아직 검증하지 않은 항목

- 만료 server/client 인증서, 잘못된 SAN, 다른 CA, certificate rotation/revocation 및 enrollment lifecycle
- 확장 server/agent 재시작 및 장시간 offline 행렬, expiry/replay 조합, ACK 유실 fault injection (기본 offline queue와 server restart 한 경로는 smoke에서 통과)
- parser fuzzing, full HTTP grammar, slow-client 총 session deadline, worker pool/동시 연결 부하
- event/file input, queue quota·disk-full·DB write failure와 retry/backpressure 429 계약
- production operator RBAC, 정책 server-side signing/distribution, runtime policy apply/rollback hook
- 10k event 처리량, p95/p99, CPU/RSS, 장시간 soak, 여러 배포판/커널 행렬
- 전체 SRS NFR 검증 및 systemd 설치·실행·권한 경계의 실제 호스트 통합

상세 요구사항별 현황은 [`REQUIREMENTS_TRACEABILITY.md`](REQUIREMENTS_TRACEABILITY.md), 수행 예정인 검증은 [`TEST_PLAN.md`](TEST_PLAN.md), 구현·학습 설명은 [`ENGINEERING_STUDY_GUIDE.md`](ENGINEERING_STUDY_GUIDE.md)를 참고하세요.
