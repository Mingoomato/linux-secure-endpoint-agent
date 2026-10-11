# 엔지니어링 학습 가이드 — Linux Secure Endpoint Agent Lab

## 학습 목표와 현재 상태

이 저장소는 합성 상태 이벤트, 수동 event.v1 import, 장기 실행 모드의 inotify metadata collector를 loopback control server로 보내는 교육용 endpoint agent입니다. durable queue, mTLS, Ed25519 정책, 제한된 관리자 API를 함께 구현해 transport 인증·정책 발급자 인증·재전송·최소 수집 경계를 학습하도록 제작했습니다. 수동 import와 collector는 활성 root를 검사하고 경로를 HMAC 가명화하며, file content나 임의 명령을 수집·실행하지 않습니다.

수집기 추가 직전 기록된 GCC/Clang Release와 GCC/Clang ASan/UBSan 네 구성에서 CTest가 각각 4/4 통과했고 해당 코드의 agent Clang 정적 분석도 진단이 없었습니다. 정책 시험은 operator 인증 분리, 게시·서명, 조건부 304 fetch, agent sync, 잘못된 higher revision 거부 후 last-good 보존과 뒤이은 valid revision 복구, no-policy 차단, telemetry 비활성 큐 보존, sample rate 적용을 확인합니다. 추가로 `event.v1` 입력은 활성 정책 root 안의 경로만 받아 HMAC ID로 바꾸고, sample suppression, 중복, pathless degraded coverage와 unknown/sensitive field 거부를 확인합니다. Smoke는 target file marker가 spool에 들어가지 않으며 server ACK까지 연결됨을 확인합니다. 그 외 `..` 경로, 외부 symlink, 달력상 유효하지 않은 만료일, 음수·소수·안전 범위 초과 revision, 1초 TLS handshake deadline 아래 incomplete ClientHello와 1.5초 HTTP request deadline 아래 slow-client 종료를 시험합니다. 분리한 HTTP request parser는 seed 입력 기반 Clang libFuzzer+ASan+UBSan 100,000회 실행에서도 실패를 찾지 못했습니다. 이는 선택한 로컬 경로의 자동 검증 결과이며, 전체 HTTP grammar나 장시간 fuzz 안전성을 증명하지 않습니다. 전체 SRS는 부분 구현 상태입니다. inotify collector, bounded file rename pairing, policy watch preflight와 runtime staging은 추가됐지만 새 변경 뒤 빌드·검증을 수행하지 않았습니다. Overflow 뒤 baseline reconciliation, directory rename pairing, production enrollment/revocation/RBAC, import key fault·경합·history exhaustion, 확장 restart/offline/expiry 행렬, quota/disk fault, 성능 행렬은 아직 완결되지 않았습니다. 저장소 소유자의 학습·독립 재현 여부도 관찰되지 않았으며, 자동 빌드 성공은 개인 숙련도의 증거가 아닙니다.

## 각 하위 시스템이 필요한 이유

| 하위 시스템 | 목적 | 주요 코드 |
|---|---|---|
| 합성 이벤트 생성 | 실제 파일이나 사용자 데이터 없이 전달 경로를 재현합니다. | `enqueue`, `run` 명령 |
| event.v1 importer | 별도 01–05 producer와 결합하지 않고 공통 event 계약을 통해 명시적으로 통합합니다. | `import_event`, `normalize_imported_event`, `pseudonymize_path` |
| inotify collector | 활성 root의 변경 메타데이터만 이벤트로 만들어 telemetry 설정을 실제 관측 경계에 적용합니다. | `InotifyCollector`, `enqueue_agent_event`, `active_policy` |
| 내구성 있는 agent 큐 | 서버 연결이 끊겨도 이벤트를 보존하고, 확인된 ID만 삭제합니다. | `open_queue`, `next_sequence_in_transaction`, `enqueue`, `pending`, `delete_acked` |
| TLS client | 서버 인증서와 SAN을 검증하고 client 인증서를 제시합니다. | `client_context`, `connect_socket`, `send_batch` |
| ACK와 재시도 | 모호한 응답이나 전송 실패 뒤에도 데이터를 잃지 않게 합니다. | `ack_ids`, `flush` |
| Runtime policy gate | 서명 정책을 읽어 합성 이벤트 생성과 저장 큐 전송을 fail-closed 방식으로 제어합니다. | `active_policy`, `enqueue_synthetic_if_enabled`, `flush` |
| TLS reference server | 절대 handshake deadline으로 느린 TLS peer가 순차 서버를 점유하는 시간을 제한하고, mTLS client와 allowlist를 확인합니다. | `run_server`, `accept_tls_with_deadline`, `serve_one`, `read_request` |
| HTTP framing 경계 | 바이트 스트림에서 하나의 요청·응답 경계를 모호하지 않게 정하고 자원 사용을 제한합니다. | Agent `http_exchange`, `server/include/agent/http.hpp`의 `parse_request_head`·`parse_request`, TLS adapter `read_request` |
| 제한된 JSON 파서 | 숫자 문법, 중복 키, 깊이와 입력 크기를 검증합니다. | `agent/include/agent/json.hpp`, `server/include/agent/json.hpp` |
| 멱등 ingestion | 같은 이벤트 재전송은 구분해 승인하고, 같은 ID의 다른 내용은 거부합니다. | `ingest`, SQLite 고유 키 |
| operator 정책 제어면 | agent client 권한과 분리된 operator CN allowlist와 bearer token을 검사하고, tenant별 monotonic policy를 서명·게시합니다. | `serve_one`, `valid_admin_authorization`, `publish_policy` |
| 정책 fetch와 last-good 저장 | 조건부 fetch 뒤 Ed25519 서명, scope, expiry, path와 revision을 확인하고 새 문서와 audit row를 함께 commit합니다. | `fetch_and_validate_policy`, `validate_policy_document`, `policy_audit` |
| C transport probe | POSIX loopback socket 동작을 TLS와 분리해 연습합니다. | `transport-c/src/sw_probe.c` |

## 데이터·제어 흐름

### Agent 큐와 전송

1. CLI가 endpoint, agent ID, 인증서 경로와 SQLite store를 읽습니다. 네트워크 명령은 loopback 대상만 허용합니다.
2. `open_queue`가 store 디렉터리 권한을 제한하고 SQLite WAL과 `synchronous=FULL`을 설정합니다. 큐, sequence, 정책 상태 테이블을 준비합니다.
3. `enqueue_synthetic_if_enabled`는 먼저 `active_policy`로 last-good 문서를 읽어 tenant, revision, schema, expiry, 설정과 action scope를 확인합니다. 정책이 없거나 만료·비활성 상태면 fail closed로 새 이벤트를 만들지 않습니다. 활성 정책에서는 `sample_rate=0`이면 생성하지 않고, 0과 1 사이 값이면 `RAND_bytes`에서 얻은 균등 53-bit 표본으로 생성 여부를 결정합니다. 선택된 경우 `enqueue`가 sequence, 직렬화한 합성 payload의 quota, row 삽입을 하나의 SQLite write transaction에 넣습니다. 포화로 거부되면 sequence도 rollback하며, 장기 실행 모드는 오류를 로그에 남기고 기존 큐의 전송을 계속 시도합니다.
4. `pending`은 sequence 순서로 제한된 batch를 가져옵니다. `send_batch`는 CA, client 인증서, private-key 권한, CN, loopback 주소와 서버 DNS/IP SAN을 검증한 뒤 OpenSSL TLS 연결을 엽니다.
5. `flush`는 전송할 때마다 `active_policy`를 다시 확인합니다. telemetry가 비활성·만료면 네트워크 전송을 멈추고 DB queue 행을 그대로 둡니다. `sample_rate=0`은 새 이벤트 생성만 막으므로, telemetry가 켜져 있으면 이전에 쌓인 행을 전송할 수 있습니다. HTTP 요청은 `application/json`과 정확한 `Content-Length`를 포함합니다. event 응답 파서는 header 16 KiB·body 1 MiB 상한, 단일 `Content-Length`, `Transfer-Encoding` 거부, HTTP 200 status와 완전한 본문 길이를 확인합니다. 그 외 status는 ACK로 처리하지 않습니다. 별도 policy fetch는 200/304만 허용합니다. `ack_ids`는 accepted/duplicate ID를 읽고, `flush`는 실제 전송한 batch ID와 대조한 뒤 일치한 항목만 트랜잭션으로 삭제합니다.
6. 네트워크·파싱 실패는 bounded exponential backoff와 jitter 뒤 재시도합니다. 서버가 commit하고 ACK가 유실되면 다음 전송은 중복으로 판별됩니다.

### event.v1 가져오기와 최소 수집

1. `import-event --file ... --tenant ... --store ...`는 최대 1 MiB의 단일 UTF-8 JSON 문서를 읽습니다. 입력은 producer가 만든 이벤트 메타데이터입니다. `target.path`가 있어도 그 파일을 열거나 읽지는 않습니다.
2. `normalize_imported_event`는 `event.v1`, UUID, UTC timestamp, source/kind 토큰, actor 숫자, coverage state와 nested allowlist를 검사합니다. 임의 필드는 거부됩니다. 정상 파일 이벤트는 absolute path가 필요하고, pathless 이벤트는 `coverage.*`이며 상태가 `healthy`가 아닐 때만 허용합니다. `host_id`는 확인하지만 mTLS agent identity가 authoritative이므로 forward하지 않습니다.
3. 경로가 있으면 `weakly_canonical`로 현재 보이는 symlink/`..`를 정규화하고 component 경계 기준으로 활성 policy의 monitored roots 안인지 검사합니다. 대상 파일은 열지 않습니다. 허용된 경우 per-store 32-byte 난수 key를 0600 파일에 생성하고 HMAC-SHA-256을 계산해 `hmac-sha256:<digest>`만 payload에 넣습니다. 원문 경로는 queue envelope, payload, server로 복사되지 않습니다.
4. JSON object map은 key 정렬 canonical serialization을 하고 payload SHA-256을 계산합니다. `sample_rate`가 0이거나 표본에서 제외되면 영속 row를 만들지 않습니다. 표본에 포함되면 `BEGIN IMMEDIATE` 안에서 sequence 갱신, queue insert, `imported_events` dedup ledger insert를 원자적으로 처리합니다. 같은 event ID와 같은 normalized payload 재가져오기는 `already_seen`, 다른 payload로 같은 ID를 재사용하면 오류입니다. 로컬 dedup ledger 상한은 100,000 ID이며 상한에 닿으면 명시적으로 거부합니다.
5. 이후 `flush`는 합성 이벤트와 같은 batch/ACK 경로를 사용합니다. 서버는 raw event document나 path를 저장하지 않고 agent/event identity, sequence, payload hash와 수신 시간을 보관합니다.

HMAC path ID는 익명화가 아닙니다. 같은 store에서는 동일 경로를 연결할 수 있고, 전체 store 접근 권한이 있는 공격자는 key를 읽어 후보 경로를 대조할 수 있습니다. store를 복제하면 같은 pseudonym이 유지되므로 이동·초기화 때의 privacy 선택도 고려해야 합니다. 정책 검사와 실제 filesystem 상태 사이에는 race가 있을 수 있지만 이 importer는 대상 파일을 열지 않아 race가 file read를 유도하지는 않습니다.

### Server 수신과 ingestion

1. `run_server`는 loopback 이외의 bind를 거부하고, IPv4 loopback listener와 TLS 인증서를 준비합니다.
2. `accept4(..., SOCK_CLOEXEC)`로 연결을 받고 `serve_one`은 accepted socket을 nonblocking으로 전환해 `SSL_accept`를 진행합니다. `SSL_get_error`가 `WANT_READ`/`WANT_WRITE`를 반환하면 남은 절대 deadline 동안 `poll`하고 같은 handshake를 재시도합니다. 기본 TLS handshake deadline은 10초이며 `--handshake-deadline-ms`로 100–60,000 ms 범위에서 설정합니다. 완료되면 원래 blocking flag를 복구한 뒤 CA chain, client 인증서 CN과 allowlist를 확인합니다. 이 구현은 연결을 한 번에 하나씩 처리합니다.
3. `read_request`는 TLS에서 읽은 byte 조각을 `raw` 문자열에 모읍니다. transport-independent `parse_request_head`는 header 끝을 찾고 header·body 경계를 검사해, header가 아직 불완전하면 `nullopt`를 반환합니다. `parse_request`는 선언 길이와 실제 길이가 정확히 일치할 때만 소유형 `Request`를 반환합니다. header는 16 KiB, 본문은 1 MiB까지 허용하며 Host 한 개, batch의 `application/json`, POST의 Content-Length, 중복 Content-Length/Content-Type·Transfer-Encoding·GET 본문 거부를 적용합니다. accepted socket의 개별 I/O timeout은 5초이며, TLS handshake가 끝난 뒤 시작하는 전체 HTTP request deadline은 기본 10초이고 `--request-deadline-ms`로 100–60,000 ms 범위에서 설정할 수 있습니다.
4. `serve_one`은 `/v1/admin/policies`에서 operator CN allowlist와 mode-0600 token을 모두 확인하고 새 JSON 정책을 제한된 schema로 검증한 뒤 Ed25519 서명과 monotonic tenant revision을 SQLite에 저장합니다. 같은 revision과 정확히 같은 문서의 재게시만 200 idempotent 응답이며, 새 정책은 201입니다. Agent policy GET은 서명 envelope를 200으로 주고 SHA-256 ETag가 일치하면 304로 본문 전송을 생략합니다. health, status, telemetry, heartbeat 경로도 역할별로 분기합니다. `ingest`는 JSON schema, 주장된 agent ID, 인증서 identity, 이벤트 수, 민감 키, payload hash를 확인합니다.
5. 서버는 `(agent_id,event_id)` 고유 키로 transaction에 기록하고 commit한 뒤에만 ACK를 보냅니다. 동일 sequence/hash의 재수신은 duplicate, 내용이 바뀐 ID 재사용은 오류가 됩니다.

### 서명 정책 게시·동기화 경로

Operator는 operator 인증서와 bearer token을 함께 사용합니다. server는 policy schema와 tenant, timestamp, allowed actions, 설정 상한, revision을 확인한 다음 원본 문서 bytes를 Ed25519로 서명하고 SQLite transaction에서 정책 revision·signature를 갱신합니다. 동일 revision·동일 bytes는 idempotent이고, 같은/낮은 revision의 변경 문서는 rollback으로 거부됩니다. Agent의 `sync-policy`는 이전 last-good document의 SHA-256을 `If-None-Match`에 보내며 ETag가 같으면 server가 304를 반환합니다. 새 문서를 받은 경우 envelope를 파싱하고 64-byte signature를 복원한 뒤 JSON 파싱 전에 원본 문서 bytes를 검증합니다. 이어서 allowed field/action, issuer·tenant scope, issued/expiry UTC 시각, safe integer revision, 허용 root와 canonical path component containment를 검사합니다. 유효한 새 revision만 SQLite `policy_state`와 `policy_audit`에 한 transaction으로 저장해 DB가 부분 갱신되는 것을 막습니다. 회귀 시험은 외부 root로 향하는 서명 정책을 거부하고 이전 revision·audit 값을 유지한 뒤 다음 valid revision이 저장되는 것을 확인합니다. 실행 경로의 `active_policy`는 저장 문서를 다시 parse하고 DB issuer·revision과 document를 대조한 뒤 `telemetry_enabled`와 expiry로 생성·전송을 게이트합니다. `sample_rate`는 새 합성 이벤트 생성에만 적용되고, 기존 큐 전송에는 영향을 주지 않습니다. `status`는 `NO_POLICY`, `STALE`, `ACTIVE`, `VALIDATED`와 revision, sample rate, root 개수, queue 크기를 보고합니다. Root 목록은 검증된 뒤 장기 `run` collector의 watch tree로 적용됩니다. collector 추가 뒤의 기술 검증은 아직 수행하지 않았습니다. 문서를 DB에서 읽을 때 statement가 유효한 동안 issuer·document bytes를 소유형 문자열로 복사한 뒤 finalize합니다. 미래에 실제 감시기를 추가할 때 경로 검증과 파일 열기 사이의 filesystem TOCTOU도 해결해야 합니다.

## Linux 인터페이스와 자원 수명

- TCP 경로는 `getaddrinfo(3)`, `socket(2)`, `setsockopt(2)`, `connect(2)`, 서버의 `bind(2)`, `listen(2)`, `accept4(2)`, 마지막 `close(2)`를 사용합니다. TCP는 메시지 경계가 없는 byte stream이므로 HTTP framing이 필요합니다.
- `SOCK_CLOEXEC`은 실행 파일을 새 프로세스로 바꿀 때 FD 누출을 줄입니다. `SO_RCVTIMEO`/`SO_SNDTIMEO`는 개별 block I/O 대기를 제한합니다. TLS handshake는 별도 nonblocking `SSL_accept` loop에서 `poll`과 `std::chrono::steady_clock` deadline을 사용합니다. HTTP request read에는 TLS/CN 확인 뒤 시작하는 별도 절대 deadline이 있습니다. 이 두 기한은 route 처리, 동시성 한도, 서비스 rate limit을 제한하지 않습니다.
- `SSL_CTX`는 TLS 설정과 신뢰 정보를 보유하고 여러 `SSL` 세션의 기반이 됩니다. `SSL*`는 socket FD에 연결되어 handshake와 record I/O를 수행합니다. Agent와 Server의 `SSL*`는 `unique_ptr`, 양쪽 connected FD는 `ScopedFd`가 관리합니다. SQLite DB와 statement는 수동 정리 분기가 있어 예외 경로를 함께 추적해야 합니다.
- C++ `std::string`, vector, map, parser `Value`는 자신이 소유한 메모리를 관리합니다. SQLite row를 읽을 때 statement가 유효한 동안 값을 복사해야 합니다. `active_policy`는 issuer·document bytes를 복사해 둔 뒤 `sqlite3_finalize`합니다. `sqlite3_stmt*`는 finalize 전까지 DB 자원을 점유합니다. CLI의 DB handle은 `unique_ptr` deleter로 command 예외 경로에서도 닫힙니다.
- HTTP parser의 내부 `std::string_view`는 입력 `raw`가 살아 있는 동안만 사용하고, 반환 전에 method/path/body/content-type을 `std::string`으로 복사합니다. 따라서 호출자는 TLS 수신 buffer를 덮어써도 `Request`가 dangling view를 갖지 않습니다. fuzz harness도 입력을 view로 전달하고 parser 반환 뒤에 어떤 입력 포인터도 보관하지 않습니다.
- `PRAGMA journal_mode=WAL`은 DB 옆 `-wal`/`-shm` 상태 파일과 checkpoint 동작을 수반합니다. DB 파일만 따로 복사하는 것은 일관된 백업이 아닐 수 있습니다. WAL에서도 동시에 쓰기는 하나의 writer로 직렬화됩니다.

## 동시성, 보안 가정, 실패

- Agent는 한 실행 흐름에서 queue를 처리합니다. 각 이벤트 생성과 각 flush batch 직전에 SQLite의 last-good policy를 다시 읽습니다. `sync-policy`가 다른 process에서 정책을 갱신하면 다음 검사에 반영되지만, 이미 시작한 TLS 요청을 취소하지는 않습니다. Server accept loop도 순차 처리이므로 handshake 또는 느린 요청 하나가 뒤 연결을 지연시킬 수 있습니다. HTTP request deadline은 slow-client의 본문 읽기 점유 시간을 제한하지만 TLS handshake에는 총 deadline이 없고 worker pool이나 rate limit도 없습니다.
- 동시에 여러 `import-event` process가 같은 store에 쓰면 SQLite `BEGIN IMMEDIATE`가 sequence·queue·dedup history write를 직렬화합니다. busy timeout을 넘거나 disk/DB write가 실패하면 transaction을 rollback하며 row, sequence update, dedup ID의 부분 조합을 남기지 않습니다. queue reader/flush는 WAL에서 진행될 수 있지만 SQLite writer는 한 번에 하나입니다.
- 가정은 로컬 OS와 DB 디렉터리, CA·정책 signing key, agent/operator allowlist, bearer-token 파일이 신뢰되고 개인키가 저장소 밖에서 보호된다는 것입니다. loopback은 외부 네트워크 노출을 줄일 뿐, 같은 호스트의 다른 프로세스를 인증하거나 격리하지 않습니다.
- TLS chain 검증과 hostname/IP SAN 검증은 server identity를 확인합니다. Server는 client chain을 검증하고 역할별 CN allowlist를 확인합니다. operator endpoint는 bearer token도 요구하지만 이는 lab 수준의 단순 RBAC입니다. 운영 enrollment, rotation, revocation, SAN URI 기반 identity는 구현되어 있지 않습니다.
- 오류는 인증서·SAN 오류, TLS truncation, framing 위반, JSON 오류, DB transaction 실패, quota, hash 불일치, 잘못된 ACK, policy signature·scope·revision 실패로 나뉩니다. 새 event는 network 전에 저장되므로 일시 실패에 보존되지만 queue quota 또는 disk full은 저장할 수 없습니다. 정책이 없거나 stale/비활성일 때는 전송을 멈추되 이미 저장된 queue를 삭제하지 않습니다. SQLite 정책 데이터 손상이나 tenant 불일치는 실행 명령을 실패시킵니다.
- 민감 키 이름 거부는 개인정보 보호의 보조 장치입니다. 완전한 정보 흐름 제어는 아니므로 schema, producer 제한, 권한, 로그 검토가 함께 필요합니다.
- imported/collected event의 allowlist, policy root, `telemetry_enabled`, `sample_rate`, local key permission이 실제 전송 경계입니다. `path_id`의 keyed HMAC은 일반 SHA-256보다 외부의 사전 대입을 어렵게 하지만 local key 탈취나 store 전체 열람에는 보호를 제공하지 않습니다. Collector는 no-follow dirfd traversal을 사용하지만 mount namespace와 모든 filesystem race를 차단하는 보안 경계는 아닙니다.

## 대안과 설계 교환

- 직접 만든 HTTP framing 파서는 학습에 적합하고 의존성이 적지만 RFC 전체를 구현하지 않습니다. 검증된 HTTP 라이브러리는 parser 표면을 줄여주지만 새 의존성과 통합 복잡성이 생깁니다.
- 순수 parser를 TLS adapter에서 분리하면 같은 framing 규칙을 단위 테스트와 coverage-guided fuzzing에서 재사용할 수 있습니다. 짧은 libFuzzer 실행은 실행된 입력에서의 sanitizer 결함을 찾는 데 도움을 주지만 무결점이나 RFC 완전성을 증명하지 않습니다.
- Unix domain socket은 로컬 전용 권한 모델을 단순하게 할 수 있지만 mTLS·SAN 연습을 제공하지 않습니다.
- raw path를 직접 전송하는 설계는 검색과 서버 상관 분석이 쉽지만 개인정보 노출이 크고, 일반 SHA-256은 후보 경로 사전 대입에 취약합니다. 랜덤 per-event ID는 상관을 어렵게 하지만 같은 파일 이벤트의 분석성을 낮춥니다. 이 lab은 per-store keyed HMAC으로 제한된 상관 가능성과 raw path 비전송을 절충합니다. 운영 환경에서는 키 분리·rotation·보존·사용자 동의에 대한 추가 설계가 필요합니다.
- bounded worker pool은 처리량을 높일 수 있지만 FD, handshake, queue, DB writer를 함께 제한해야 합니다.
- fingerprint 또는 SAN URI 기반 ID는 CN allowlist보다 명시적일 수 있지만 enrollment·rotation·revocation 수명주기가 필요합니다.
- 관리형 JSON 라이브러리는 직접 parser 유지보수와 Unicode edge case를 줄입니다. 반대로 현재 코드의 parser를 읽으면 입력 상한과 허용 문법을 공부할 수 있습니다. agent/server parser 사본이 분리되어 있어 drift 위험이 남습니다.
- 메시지 broker는 server-side buffering과 backpressure 선택지를 제공하지만 운영 자원과 credential이 늘어납니다. 현재 last-good 저장/audit transaction을 runtime 적용으로 확장하려면 validation과 staged config 준비, atomic swap, 실패 rollback, audit 의미를 먼저 정하고 concurrent reader의 관측 경계를 설계해야 합니다.

## 권장 학습 순서

`docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/KEY_MANAGEMENT.md`를 먼저 읽습니다. 그다음 합성 event 하나를 SQLite insert부터 TLS, server commit, ACK, agent delete까지 추적하고, ACK 유실 시 재전송을 비교합니다. 마지막으로 정책 서명 검증에서 TLS identity와 issuer signature가 서로 대체할 수 없는 이유를 설명해 봅니다. `docs/DEBUGGING_EXERCISES.md`에는 정답 없이 세 개의 독립 구현 과제가 있습니다.

## Agent registry와 인증서 lifecycle

Registry는 허용된 UUID, enabled/revoked 상태, last_seen, 인증서 fingerprint history를 관리합니다. mTLS chain 검증은 certificate가 trusted CA에서 발급되고 유효기간 안에 있는지 확인하고, SHA-256 pin은 같은 CN을 가진 certificate 교체/복제를 구별합니다. 명시 enroll은 operator mTLS identity와 bearer token을 모두 요구하며, offline pre-registration용 `--agents`는 UUID만 bootstrap합니다. Bootstrap UUID의 최초 인증서는 TOFU pin으로 저장됩니다.

Rotation에서는 current와 pending pin이 잠시 동시에 허용됩니다. 새 certificate가 first-use로 성공하면 SQLite transaction 안에서 old를 retired, pending을 current로 바꿉니다. Revoke는 agent를 disabled로 만들고 current/pending pin을 revoked 처리합니다. Re-enroll은 이전에 revoke된 UUID에 새 fingerprint를 연결하지만 과거 fingerprint 재사용은 허용하지 않습니다. Registry DB write가 실패하면 연결을 거부해야 합니다. 이 코드는 구현됐으나 새 코드의 build/test 검증은 미실행입니다.

## 장기 실행 inotify collector와 policy 적용

### 이 하위 시스템이 필요한 이유

정책의 `monitored_roots`가 값만 검증되고 관측 동작에는 연결되지 않으면 설정이 실제 기능을 제어하지 못합니다. 장기 `run --interval-seconds N` 경로는 signed last-good policy를 관찰 경계로 사용하고, 해당 루트의 파일시스템 메타데이터 변경을 로컬 event.v1로 바꿉니다. 사용자의 파일 내용은 열지 않습니다. inotify는 이벤트 기반이라 일정 간격으로 모든 파일을 읽는 polling보다 불필요한 입출력을 줄이지만, 이벤트 큐 overflow가 가능하므로 coverage 상태를 별도로 기록합니다.

### 데이터와 제어 흐름

1. `run`은 옵션이 있으면 Ed25519 정책을 받아 검증한 후 last-good 문서를 읽습니다. `telemetry_enabled`, `sample_rate`, expiry, tenant, revision, canonical monitored roots를 적용합니다.
2. 새 policy의 root watch tree를 임시 collector의 별도 inotify FD에서 먼저 준비합니다. 정책 저장 전 preflight가 실패하면 SQLite last-good row를 바꾸지 않습니다. Runtime reload에서도 candidate watcher가 ready일 때만 기존 collector와 policy를 교체하고, 실패하면 이전 active runtime state를 유지합니다. 실패한 동일 정책은 정책 sync 주기(미설정 시 60초) 뒤 다시 준비합니다. 각 root부터 디렉터리를 열고 watch를 등록한 다음 항목을 열거하여 자식 디렉터리를 감시합니다.
3. create, close-write, attribute, delete, move 알림은 file metadata event로 분류합니다. 이름은 정규화 경로의 HMAC ID로 바꾸고, device/inode 등 제한된 메타데이터와 함께 event.v1 allowlist를 거쳐 sequence를 배정하고 SQLite queue에 기록합니다.
4. queue의 bounded batch를 mTLS로 전송합니다. 인증된 server의 ACK/duplicate ID를 받은 항목만 제거합니다. 네트워크가 끊기면 queue row는 남습니다.
5. 파일·디렉터리 이동은 cookie로 최대 1초 동안 짝짓고, 디렉터리 이동 뒤에는 watch tree를 다시 구성합니다. overflow, 접근 실패, watch 한도 초과, 디렉터리 이동/삭제에 따른 감시 손실은 `coverage.watch_degraded`로 표현합니다. Overflow 사이에 실제로 놓친 변경은 baseline과 비교해 복구하지 않으므로 degraded 상태를 healthy로 과장하지 않습니다.

### Linux 인터페이스, 수명, 동시성

- `inotify_init1(IN_NONBLOCK | IN_CLOEXEC)`은 이벤트 FD를 생성하고 `inotify_add_watch`는 디렉터리 변경 mask를 등록합니다. `poll`은 bounded interval 내 readiness를 기다리고 `read`는 여러 `inotify_event` 레코드를 가져옵니다.
- 디렉터리 traversal은 `openat(O_DIRECTORY | O_NOFOLLOW)`, `fstatat(AT_SYMLINK_NOFOLLOW)`, `fdopendir(dup(fd))`, `readdir`를 사용합니다. 열린 directory FD의 `/proc/self/fd/N` 경로로 inotify watch를 붙여 path replacement race를 줄입니다. cross-device 하위 트리는 따라가지 않습니다.
- `InotifyCollector`가 inotify FD와 watch descriptor→directory map을 소유하고 소멸 시 FD를 닫습니다. traversal 중의 directory FD와 `DIR*`는 각 호출 안에서 닫습니다. SQLite connection은 daemon의 한 thread가 collector event와 queue flush를 순서대로 처리합니다. 내부 작업 thread는 없습니다.
- Directory watch 수는 4,096으로 제한됩니다. policy가 사라지거나 telemetry가 꺼지거나 expiry되면 collection을 멈춥니다. Sampling은 신규 이벤트에만 적용하고 이미 큐에 저장된 이벤트 전송은 별도 policy gate를 따릅니다.

### 보안 가정, 실패 모드, 대안

Collector는 서명 검증된 policy와 agent 계정의 directory search 권한을 전제로 합니다. symlink를 따라 디렉터리를 재귀하지 않고, file contents, xattrs, 임의 환경변수, process command line을 읽지 않습니다. HMAC pseudonym은 저장소별 secret key가 있어야 같은 경로의 반복을 연결할 수 있으며, 로컬 key가 유출되면 보호가 약해집니다. Inotify는 파일시스템/마운트 동작을 전부 포착하지 않습니다. bind mount, namespace, 권한 변동, kernel watch limit, overflow, 파일시스템별 지원 차이는 운영 coverage 한계입니다. Policy preflight와 staged reload는 구현됐지만 이 변경 뒤에는 빌드나 테스트를 수행하지 않았으므로 구현 상태와 기술 검증 상태를 분리해 기록합니다. Preflight와 commit 사이에 filesystem 권한/마운트가 변하는 경우와 restart 시점 적용은 아직 검증 대상입니다.

`fanotify`는 mount 단위 관측이나 permission event에 적합할 수 있으나 권한·capability와 운영 영향이 커서 이 권한 없는 endpoint lab의 기본값으로 삼지 않았습니다. `openat2`와 directory FD 기반 traversal은 scope traversal을 더 엄격히 구성하는 대안입니다. Periodic scanning은 inotify 유실 후 비교 기준을 제공하지만 비용이 더 크며, 커널 FIM agent나 BPF는 배포판 호환성과 권한 모델이 별도 과제입니다.

## 공식 문서

- Linux man-pages: [`socket(2)`](https://man7.org/linux/man-pages/man2/socket.2.html), [`connect(2)`](https://man7.org/linux/man-pages/man2/connect.2.html), [`accept(2)`](https://man7.org/linux/man-pages/man2/accept.2.html), [`fcntl(2)`](https://man7.org/linux/man-pages/man2/fcntl.2.html), [`openat(2)`](https://man7.org/linux/man-pages/man2/openat.2.html), [`fstatat(2)`](https://man7.org/linux/man-pages/man2/fstatat.2.html), [`fdopendir(3)`](https://man7.org/linux/man-pages/man3/fdopendir.3.html), [`readdir(3)`](https://man7.org/linux/man-pages/man3/readdir.3.html), [`poll(2)`](https://man7.org/linux/man-pages/man2/poll.2.html), [`inotify_init1(2)`](https://man7.org/linux/man-pages/man2/inotify_init1.2.html), [`inotify_add_watch(2)`](https://man7.org/linux/man-pages/man2/inotify_add_watch.2.html), [`inotify(7)`](https://man7.org/linux/man-pages/man7/inotify.7.html), [`socket(7)`](https://man7.org/linux/man-pages/man7/socket.7.html)
- OpenSSL: [`SSL_CTX_set_verify`](https://docs.openssl.org/3.0/man3/SSL_CTX_set_verify/), [`SSL_set1_host`](https://docs.openssl.org/3.0/man3/SSL_set1_host/), [`SSL_accept`](https://docs.openssl.org/3.0/man3/SSL_accept/), [`SSL_get_error`](https://docs.openssl.org/3.0/man3/SSL_get_error/), [`SSL_read`](https://docs.openssl.org/3.0/man3/SSL_read/), [`SSL_write`](https://docs.openssl.org/3.0/man3/SSL_write/)
- OpenSSL random API: [`RAND_bytes`](https://docs.openssl.org/3.0/man3/RAND_bytes/)
- OpenSSL keyed digest API: [`HMAC`](https://docs.openssl.org/3.0/man3/HMAC/)
- SQLite: [WAL](https://www.sqlite.org/wal.html), [Atomic Commit](https://www.sqlite.org/atomiccommit.html)
- IETF: [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446), [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110), [RFC 9112 — HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112), [RFC 8259 — JSON](https://www.rfc-editor.org/rfc/rfc8259)
- LLVM: [libFuzzer — coverage-guided fuzz testing](https://llvm.org/docs/LibFuzzer.html)
- systemd: [`systemd.exec`](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
