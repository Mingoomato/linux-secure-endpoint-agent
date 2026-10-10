# 엔지니어링 학습 가이드 — Linux Secure Endpoint Agent Lab

## 학습 목표와 현재 상태

이 저장소는 endpoint agent와 loopback control server가 합성 상태 이벤트를 주고받는 교육용 구현입니다. 이벤트를 SQLite에 먼저 저장하고, 상호 TLS(mTLS)로 전송한 뒤, 서버가 확정한 이벤트 ID만 로컬 큐에서 제거합니다. transport peer 인증과 정책 발급자 인증을 분리하고, 재시도·중복 처리·최소 수집 경계를 코드로 살펴보도록 제작했습니다. 파일 감시, 개인 파일 수집, 임의 명령 실행 기능은 없습니다.

GCC와 Clang 21.1.8 Release 빌드, 각 CTest 3/3, ASan/UBSan CTest 3/3, Clang 정적 분석, HTTP framing 음성 통합 사례가 통과했습니다. 이는 선택한 로컬 경로의 자동 검증 결과입니다. 전체 SRS는 부분 구현 상태입니다. production enrollment/revocation, 운영자 권한 관리, 서버 정책 배포, 재시작·오프라인 행렬, fuzzing, quota/disk fault, 성능 행렬은 아직 완결되지 않았습니다. 저장소 소유자의 학습·독립 재현 여부도 관찰되지 않았으며, 자동 빌드 성공은 개인 숙련도의 증거가 아닙니다.

## 각 하위 시스템이 필요한 이유

| 하위 시스템 | 목적 | 주요 코드 |
|---|---|---|
| 합성 이벤트 생성 | 실제 파일이나 사용자 데이터 없이 전달 경로를 재현합니다. | `enqueue`, `run` 명령 |
| 내구성 있는 agent 큐 | 서버 연결이 끊겨도 이벤트를 보존하고, 확인된 ID만 삭제합니다. | `open_queue`, `next_sequence`, `pending`, `delete_acked` |
| TLS client | 서버 인증서와 SAN을 검증하고 client 인증서를 제시합니다. | `client_context`, `connect_socket`, `send_batch` |
| ACK와 재시도 | 모호한 응답이나 전송 실패 뒤에도 데이터를 잃지 않게 합니다. | `ack_ids`, `flush` |
| TLS reference server | mTLS client와 allowlist를 확인하고 제한된 요청을 받습니다. | `run_server`, `serve_one`, `read_request` |
| HTTP framing 경계 | 바이트 스트림에서 하나의 요청·응답 경계를 모호하지 않게 정하고 자원 사용을 제한합니다. | 양쪽 `http_exchange`와 `read_request` |
| 제한된 JSON 파서 | 숫자 문법, 중복 키, 깊이와 입력 크기를 검증합니다. | `agent/include/agent/json.hpp`, `server/include/agent/json.hpp` |
| 멱등 ingestion | 같은 이벤트 재전송은 구분해 승인하고, 같은 ID의 다른 내용은 거부합니다. | `ingest`, SQLite 고유 키 |
| 정책 서명 검증 | TLS와 별개로 정책 작성자의 서명 및 범위를 검증합니다. | `validate_signed_policy` |
| C transport probe | POSIX loopback socket 동작을 TLS와 분리해 연습합니다. | `transport-c/src/sw_probe.c` |

## 데이터·제어 흐름

### Agent 큐와 전송

1. CLI가 endpoint, agent ID, 인증서 경로와 SQLite store를 읽습니다. 네트워크 명령은 loopback 대상만 허용합니다.
2. `open_queue`가 store 디렉터리 권한을 제한하고 SQLite WAL과 `synchronous=FULL`을 설정합니다. 큐, sequence, 정책 상태 테이블을 준비합니다.
3. `next_sequence`가 트랜잭션으로 증가된 sequence를 저장합니다. `enqueue`는 고정된 합성 payload를 만들고 hash를 계산한 뒤, 행·바이트 quota를 확인해 네트워크 작업 전에 저장합니다.
4. `pending`은 sequence 순서로 제한된 batch를 가져옵니다. `send_batch`는 CA, client 인증서, private-key 권한, CN, loopback 주소와 서버 DNS/IP SAN을 검증한 뒤 OpenSSL TLS 연결을 엽니다.
5. HTTP 요청은 정확한 `Content-Length`를 포함합니다. 응답 파서는 header 16 KiB·body 1 MiB 상한, 단일 `Content-Length`, `Transfer-Encoding` 거부, 완전한 본문 길이를 확인합니다. `ack_ids`는 accepted/duplicate ID를 읽고, `flush`는 실제 전송한 batch ID와 대조한 뒤 일치한 항목만 트랜잭션으로 삭제합니다.
6. 네트워크·파싱 실패는 bounded exponential backoff와 jitter 뒤 재시도합니다. 서버가 commit하고 ACK가 유실되면 다음 전송은 중복으로 판별됩니다.

### Server 수신과 ingestion

1. `run_server`는 loopback 이외의 bind를 거부하고, IPv4 loopback listener와 TLS 인증서를 준비합니다.
2. `accept4(..., SOCK_CLOEXEC)`로 연결을 받고 `serve_one`이 mTLS handshake, CA chain, client 인증서 CN과 allowlist를 확인합니다. 이 구현은 연결을 한 번에 하나씩 처리합니다.
3. `read_request`는 HTTP/1.1 request line과 header를 제한된 문법으로 읽습니다. header는 16 KiB, 본문은 1 MiB까지 허용하며 Host 한 개, POST의 Content-Length, 중복 Content-Length·Transfer-Encoding·GET 본문 거부를 적용합니다. 받은 socket의 read/write timeout은 5초입니다.
4. `serve_one`이 health, status, telemetry, heartbeat, policy 경로를 분기합니다. `ingest`는 JSON schema, 주장된 agent ID, 인증서 identity, 이벤트 수, 민감 키, payload hash를 확인합니다.
5. 서버는 `(agent_id,event_id)` 고유 키로 transaction에 기록하고 commit한 뒤에만 ACK를 보냅니다. 동일 sequence/hash의 재수신은 duplicate, 내용이 바뀐 ID 재사용은 오류가 됩니다.

### 서명 정책 경로

`validate_signed_policy`는 파일 크기를 제한해 정책과 서명을 읽고, JSON 파싱 전에 원본 바이트에 대한 64-byte Ed25519 detached signature를 검증합니다. 허용 필드·action, 만료, tenant/root scope를 확인하고 이전 revision보다 큰 값만 transaction으로 last-good DB 상태에 저장합니다. 이 프로젝트에는 저장된 정책을 적용하는 runtime watcher나 enforcement hook이 없습니다. 정책 저장 성공을 정책 적용 성공으로 해석하면 안 됩니다.

## Linux 인터페이스와 자원 수명

- TCP 경로는 `getaddrinfo(3)`, `socket(2)`, `setsockopt(2)`, `connect(2)`, 서버의 `bind(2)`, `listen(2)`, `accept4(2)`, 마지막 `close(2)`를 사용합니다. TCP는 메시지 경계가 없는 byte stream이므로 HTTP framing이 필요합니다.
- `SOCK_CLOEXEC`은 실행 파일을 새 프로세스로 바꿀 때 FD 누출을 줄입니다. `SO_RCVTIMEO`/`SO_SNDTIMEO`는 block I/O 대기를 제한하지만 전체 연결 처리의 절대 deadline, 동시성 한도, 서비스 rate limit을 제공하지는 않습니다.
- `SSL_CTX`는 TLS 설정과 신뢰 정보를 보유하고 여러 `SSL` 세션의 기반이 됩니다. `SSL*`는 socket FD에 연결되어 handshake와 record I/O를 수행합니다. Agent와 Server의 `SSL*`는 `unique_ptr`, 양쪽 connected FD는 `ScopedFd`가 관리합니다. SQLite DB와 statement는 수동 정리 분기가 있어 예외 경로를 함께 추적해야 합니다.
- C++ `std::string`, vector, map, parser `Value`는 자신이 소유한 메모리를 관리합니다. SQLite row를 읽을 때 statement가 유효한 동안 값을 복사해야 합니다. SQLite `sqlite3_stmt*`는 finalize 전까지 DB 자원을 점유합니다.
- `PRAGMA journal_mode=WAL`은 DB 옆 `-wal`/`-shm` 상태 파일과 checkpoint 동작을 수반합니다. DB 파일만 따로 복사하는 것은 일관된 백업이 아닐 수 있습니다. WAL에서도 동시에 쓰기는 하나의 writer로 직렬화됩니다.

## 동시성, 보안 가정, 실패

- Agent는 한 실행 흐름에서 queue를 처리합니다. Server accept loop도 순차 처리이므로 handshake 또는 느린 요청 하나가 뒤 연결을 지연시킬 수 있습니다. 5초 socket timeout과 byte cap은 일부 대기를 묶지만 worker pool이나 종단간 deadline을 대신하지 않습니다.
- 가정은 로컬 OS와 DB 디렉터리, CA·정책 signing key, allowlist가 신뢰되고 개인키가 저장소 밖에서 보호된다는 것입니다. loopback은 외부 네트워크 노출을 줄일 뿐, 같은 호스트의 다른 프로세스를 인증하거나 격리하지 않습니다.
- TLS chain 검증과 hostname/IP SAN 검증은 server identity를 확인합니다. Server는 client chain을 검증하고 CN allowlist로 로컬 권한을 확인합니다. 운영 enrollment, rotation, revocation, SAN URI 기반 identity는 구현되어 있지 않습니다.
- 오류는 인증서·SAN 오류, TLS truncation, framing 위반, JSON 오류, DB transaction 실패, quota, hash 불일치, 잘못된 ACK, policy signature·scope·revision 실패로 나뉩니다. 새 event는 network 전에 저장되므로 일시 실패에 보존되지만 queue quota 또는 disk full은 저장할 수 없습니다.
- 민감 키 이름 거부는 개인정보 보호의 보조 장치입니다. 완전한 정보 흐름 제어는 아니므로 schema, producer 제한, 권한, 로그 검토가 함께 필요합니다.

## 대안과 설계 교환

- 직접 만든 HTTP framing 파서는 학습에 적합하고 의존성이 적지만 RFC 전체를 구현하지 않습니다. 검증된 HTTP 라이브러리는 parser 표면을 줄여주지만 새 의존성과 통합 복잡성이 생깁니다.
- Unix domain socket은 로컬 전용 권한 모델을 단순하게 할 수 있지만 mTLS·SAN 연습을 제공하지 않습니다.
- bounded worker pool은 처리량을 높일 수 있지만 FD, handshake, queue, DB writer를 함께 제한해야 합니다.
- fingerprint 또는 SAN URI 기반 ID는 CN allowlist보다 명시적일 수 있지만 enrollment·rotation·revocation 수명주기가 필요합니다.
- 관리형 JSON 라이브러리는 직접 parser 유지보수와 Unicode edge case를 줄입니다. 반대로 현재 코드의 parser를 읽으면 입력 상한과 허용 문법을 공부할 수 있습니다. agent/server parser 사본이 분리되어 있어 drift 위험이 남습니다.
- 메시지 broker는 server-side buffering과 backpressure 선택지를 제공하지만 운영 자원과 credential이 늘어납니다. 실제 정책 적용은 validate/prepare/commit/rollback, audit, 실패 복구를 별도 설계해야 합니다.

## 권장 학습 순서

`docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/KEY_MANAGEMENT.md`를 먼저 읽습니다. 그다음 합성 event 하나를 SQLite insert부터 TLS, server commit, ACK, agent delete까지 추적하고, ACK 유실 시 재전송을 비교합니다. 마지막으로 정책 서명 검증에서 TLS identity와 issuer signature가 서로 대체할 수 없는 이유를 설명해 봅니다. `docs/DEBUGGING_EXERCISES.md`에는 정답 없이 세 개의 독립 구현 과제가 있습니다.

## 공식 문서

- Linux man-pages: [`socket(2)`](https://man7.org/linux/man-pages/man2/socket.2.html), [`connect(2)`](https://man7.org/linux/man-pages/man2/connect.2.html), [`accept(2)`](https://man7.org/linux/man-pages/man2/accept.2.html), [`socket(7)`](https://man7.org/linux/man-pages/man7/socket.7.html)
- OpenSSL: [`SSL_CTX_set_verify`](https://docs.openssl.org/3.0/man3/SSL_CTX_set_verify/), [`SSL_set1_host`](https://docs.openssl.org/3.0/man3/SSL_set1_host/), [`SSL_read`](https://docs.openssl.org/3.0/man3/SSL_read/), [`SSL_write`](https://docs.openssl.org/3.0/man3/SSL_write/)
- SQLite: [WAL](https://www.sqlite.org/wal.html), [Atomic Commit](https://www.sqlite.org/atomiccommit.html)
- IETF: [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446), [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110), [RFC 9112 — HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112), [RFC 8259 — JSON](https://www.rfc-editor.org/rfc/rfc8259)
- systemd: [`systemd.exec`](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
