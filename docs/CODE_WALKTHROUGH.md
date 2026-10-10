# 코드 따라 읽기 — Linux Secure Endpoint Agent Lab

이 문서는 주요 기능이 어떤 순서로 실행되는지 소스 코드에서 따라가기 위한 안내입니다. 실제 line number는 버전에 따라 달라질 수 있으므로 아래 함수명을 기준으로 찾으세요.

## 1. Agent 설정과 내구성 큐

`agent/src/agent.cpp`의 `main`이 하위 명령을 고르고 `Config`를 구성합니다. `is_loopback`은 network command가 외부 host를 대상으로 하지 못하게 제한합니다. `open_queue`는 전용 디렉터리를 준비하고 `spool.sqlite`에서 WAL, `synchronous=FULL`, queue/sequence/imported-event/policy 테이블을 설정합니다.

`run`은 `enqueue_synthetic_if_enabled`를 호출합니다. 이 함수는 `active_policy`로 SQLite의 last-good 정책을 읽고 tenant·revision·schema·expiry·settings·action scope를 다시 확인합니다. 활성 정책이 없거나 만료·비활성이면 새 row를 만들지 않습니다. `sample_rate=0`이면 생성만 억제하고, 0과 1 사이면 OpenSSL `RAND_bytes`를 이용한 균등 53-bit 표본으로 새 이벤트를 선택합니다. 허용된 이벤트에 한해 `next_sequence`가 `BEGIN IMMEDIATE` transaction으로 sequence를 증가시키고, `enqueue`가 고정 합성 상태 payload와 UUID, timestamp, payload hash를 만들고 quota를 확인해 row를 기록합니다. 이 저장이 `send_batch`보다 먼저 일어나는 것이 전송 실패 시 보존의 근거입니다.

## 2. Client TLS와 HTTP 응답

`client_context`는 TLS client context를 준비하고 최소 TLS 버전, trust CA, client certificate/private key, key 권한, client identity를 확인합니다. `connect_socket`은 `getaddrinfo` 결과 중 loopback 주소만 연결합니다. `TlsClientConnection` 생성자는 `SSL_set1_host` 또는 IP 검증 설정 뒤 `SSL_connect`를 수행하고 TLS context, FD, session의 수명을 소유합니다.

요청은 `/v1/agents/self/events:batch`에 `application/json` body와 `Content-Length`를 포함합니다. `http_exchange`는 SSL write 전체를 보내고, 상태 줄과 각 header 문법을 확인합니다. 응답 header는 16 KiB, 본문은 1 MiB까지이고 Content-Length는 정확히 하나여야 합니다. 중복 길이, `Transfer-Encoding`, 잘못된 숫자, truncation, 선언 길이를 넘어온 바이트를 거부합니다. 이벤트 ACK는 HTTP 200이어야 하며 다른 status에서는 ID 배열을 처리하지 않습니다.

`ack_ids`는 accepted/duplicate 배열을 JSON으로 파싱합니다. `flush`는 각 batch 앞에서 다시 `active_policy`를 확인합니다. telemetry가 비활성·만료면 `flush_paused=policy_inactive`를 출력하고 큐를 삭제하지 않은 채 정상 종료합니다. `sample_rate=0`만으로는 flush가 멈추지 않습니다. 활성 telemetry라면 서버가 돌려준 값이 실제 보낸 ID인지 확인하고 확인된 항목만 SQLite transaction에서 제거합니다. 실패하면 남은 queue로 bounded retry를 반복합니다.

## 1a. `event.v1` 입력, 정규화와 큐 기록

`import-event --file FILE --tenant TENANT --store DIR`은 선택된 JSON event document만 읽습니다. 1 MiB 이상 입력은 거부됩니다. 입력은 producer가 만든 이벤트 메타데이터입니다. `target.path`가 있어도 해당 파일을 열거나 읽지는 않습니다.

`normalize_imported_event`는 `event.v1` 버전, UUID, UTC 초 timestamp, source/kind 토큰, actor 숫자, coverage state와 각 객체의 명시적 allowlist를 확인합니다. 임의 필드는 거부됩니다. 정상 파일 이벤트는 absolute path가 필요하고, pathless 이벤트는 `coverage.*`이며 상태가 `healthy`가 아닐 때만 허용합니다. `host_id`는 확인하지만 mTLS agent identity가 authoritative이므로 forward하지 않습니다.

경로가 있으면 `weakly_canonical`로 현재 보이는 symlink와 `..`를 정규화하고 component 경계 기준으로 활성 policy의 monitored roots 안인지 검사합니다. 허용된 경우 `load_or_create_path_key`가 store 아래 0600 key를 만들거나 읽고, `pseudonymize_path`가 HMAC-SHA-256으로 바꿉니다. 정규화 payload에는 `hmac-sha256:<digest>`만 들어갑니다. 이 importer는 대상 파일을 열지 않습니다.

Canonical JSON payload의 SHA-256을 batch payload hash로 사용합니다. 활성 `telemetry_enabled` 정책이 없으면 import는 실패하고, `sample_rate`에서 제외되면 `sampled_out`으로 반환되어 queue row를 만들지 않습니다. 통과하면 `enqueue_imported_event`의 `BEGIN IMMEDIATE` 안에서 dedup ledger 조회, queue quota 확인, sequence 증가, queue row와 imported ID/hash row를 함께 삽입합니다. 같은 ID와 같은 normalized payload 재가져오기는 `already_seen`, 내용이 다른 ID 재사용은 오류입니다. transaction 실패는 sequence·queue·dedup row를 함께 rollback합니다. local ledger는 100,000 ID로 제한됩니다.

## 3. Server의 수신부터 ACK까지

`server/src/server.cpp`의 `run_server`가 인증서와 allowlist, SQLite DB를 열고 loopback listener를 만듭니다. `accept4`가 연결마다 close-on-exec FD를 주며, 순차 accept loop가 `serve_one`을 호출합니다.

`serve_one`은 accepted socket에 5초 receive/send timeout을 두고 현재 FD flag를 저장한 뒤 `O_NONBLOCK`을 적용합니다. `accept_tls_with_deadline`는 기본 10초 기한 안에서 `SSL_accept`를 호출합니다. 결과가 `SSL_ERROR_WANT_READ` 또는 `SSL_ERROR_WANT_WRITE`면 `SSL_get_error`가 요구한 방향을 `poll`로 기다린 뒤 같은 handshake를 재시도하고, `--handshake-deadline-ms`는 100–60,000 ms 범위에서 기한을 설정합니다. 완료·실패·시간초과 경로에서 이전 FD flag 복원을 시도합니다. TLS 완료 뒤 client certificate chain을 확인하고 `peer_cn`의 CN이 agent 또는 operator allowlist 중 적절한 역할에 있는지 확인합니다. 따라서 mTLS 연결을 맺었다는 것만으로 애플리케이션 권한이 생기지 않습니다. TLS handshake와 CN allowlist 확인이 끝난 뒤 `std::chrono::steady_clock`으로 HTTP request header/body read deadline을 시작하며, 기본값은 10초이고 `--request-deadline-ms`로 100–60,000 ms 범위에서 조절합니다. HTTP request deadline은 handshake와 route 처리에는 적용되지 않습니다.

HTTP 문법은 `server/include/agent/http.hpp`에 있는 순수 함수로 분리되어 있습니다. `parse_request_head`는 header delimiter가 아직 도착하지 않았으면 `nullopt`를 반환하고, 완성되면 `RequestHead`에 header 크기와 선언 body 길이를 둡니다. `parse_request`는 framing 길이가 정확히 맞을 때 body를 복사해 소유형 `Request`를 만듭니다. `read_request`는 TLS `SSL_read` 조각을 누적하고 이 두 함수를 이용해 요청이 완성될 때까지 읽습니다. request line은 origin-form path와 HTTP/1.1만 허용합니다. header는 최대 16 KiB, body는 1 MiB이며 Host 한 개를 요구하고 POST에는 단일 Content-Length를 요구합니다. event batch endpoint는 `application/json` Content-Type 한 개를 확인합니다. Transfer-Encoding, 중복 Content-Length/Content-Type, GET body, 잘못된 header와 초과 바이트는 처리하지 않습니다.

`read_request`는 남은 deadline과 최대 5초 중 짧은 시간을 다음 socket read에 적용하고, 단조 시계 deadline을 넘기면 요청을 거부합니다. 테스트는 TLS와 CN allowlist 검증을 마친 client가 요청의 한 byte만 간격을 두고 보내도 1.5초 설정 deadline 뒤 연결이 종료되는지 확인합니다. 이 deadline은 HTTP header/body 수신만 제한하며 TLS handshake, route 처리, 전체 server connection lifecycle을 제한하지 않습니다. 경로 분기 뒤 event batch는 `ingest`로 갑니다. `ingest`가 JSON batch version, 인증서 identity와 body의 agent ID, 이벤트 수, 민감 키, payload hash를 검증합니다. SQLite transaction은 event ID 고유성으로 중복을 잡습니다. 같은 ID의 sequence와 hash가 동일하면 duplicate ACK에 추가하고, 내용이 다르면 rollback/error가 됩니다. DB commit이 끝난 뒤에만 응답을 작성합니다.

## 4. Policy 게시·fetch·검증·저장

Server 시작 시 `run_server`는 `--operators`, `--admin-token-file`, `--policy-key`, `--tenant`를 읽습니다. `read_admin_token`은 server process 소유 일반 파일과 제한된 권한을 확인하고, `load_policy_signing_key`는 Ed25519 private key의 종류와 권한을 검사합니다. `/v1/admin/policies` 요청은 operator mTLS identity와 bearer token을 모두 요구합니다. `valid_admin_authorization`은 길이를 먼저 확인한 뒤 `CRYPTO_memcmp`로 token을 비교합니다.

`publish_policy`는 먼저 `validate_publishable_policy`로 허용 필드·tenant·시간·revision·action·settings 크기를 확인하고 raw document를 Ed25519 서명합니다. `BEGIN IMMEDIATE` 안에서 현재 revision을 읽고 같은 revision과 동일 bytes인 재요청만 idempotent로 승인합니다. 더 낮거나 같은 revision의 다른 문서는 거부하고, 새 문서/서명은 `policies` 행으로 교체한 뒤 commit합니다. 새 publication은 201, 동일 재전송은 200입니다. Agent GET은 document SHA-256을 ETag로 돌려주며, `If-None-Match`가 일치하면 본문 없는 304를 반환합니다.

Agent의 `sync-policy`는 local last-good 문서가 있으면 그 SHA-256을 `If-None-Match`로 보냅니다. 304면 저장 상태를 변경하지 않습니다. 200 envelope면 signature hex를 64 raw bytes로 디코드하고 `validate_policy_document`를 호출합니다. 이 함수는 raw bytes signature를 JSON parse 전에 검증하고, 허용 schema·issuer/tenant scope·issued/expiry calendar time·safe integer revision·action·setting·canonical root containment를 검사합니다. `BEGIN IMMEDIATE` 뒤 monotonic revision을 재검사하고 `policy_state` 교체와 `policy_audit` 추가를 한 transaction에서 commit합니다. 실패하면 rollback되어 기존 last-good document와 audit가 그대로 남습니다. `validate-policy`는 파일 기반 동일 validator를 호출하는 독립 연습 경로입니다. 실행 시 `active_policy`가 저장된 telemetry 설정을 다시 읽어 synthetic event 생성과 queue flush를 제어합니다. `status` 명령은 정책 상태와 revision, sample rate, monitored root 개수, queue 크기를 출력합니다. monitored roots는 아직 실제 file watcher에 연결되지 않았으므로 저장·검증을 수집 적용으로 간주하지 마세요.

## 5. 예외와 소유권 추적

Agent와 Server의 `SSL_CTX`/`SSL*`는 `unique_ptr`를 사용하며 연결 socket FD는 `ScopedFd`가 정리합니다. SQLite handle/statement와 일부 policy OpenSSL 객체는 수동 정리하는 경로가 있습니다. 코드를 변경할 때 각 할당 이후 `throw`, 조기 `return`, TLS 실패가 발생하면 어떤 객체가 해제되는지 확인해야 합니다.

큐 row는 ACK 전까지 남아야 합니다. 반대로 statement는 사용 후 `sqlite3_finalize`, transaction은 commit/rollback, `SSL*`는 해제, FD는 `close`되어야 합니다. event sequence 증가와 row insert가 별도 transaction이므로 process crash가 sequence gap을 만들 수 있습니다.

## 6. 회귀 테스트

`tests/smoke.sh`는 임시 CA, operator token, operator/agent certificate를 만들고 loopback mTLS, 1초 absolute handshake deadline 아래 incomplete ClientHello trickle 차단, HTTP request deadline, 역할 분리, bearer token 누락, event ACK/deduplication, policy publication 201/idempotent 200, exact ETag 304, agent `sync-policy`를 검사합니다. `event.v1` import는 raw path 대신 HMAC ID가 저장되는지, 대상 파일 content marker를 읽지 않는지, monitored-root 밖 경로와 unknown content field를 거부하는지, pathless degraded coverage를 허용하고 pathless healthy file event를 거부하는지 확인합니다. 같은 ID 재가져오기는 중복 처리하고, sample rate zero에서는 새 import가 생성되지 않습니다. 서명된 higher revision에서 monitored root가 허용 범위를 벗어나면 sync가 거부되고 last-good/audit가 바뀌지 않는지 확인한 뒤 유효한 더 높은 revision으로 복구합니다. 그 밖에 signature tamper/replay, 음수·분수·unsafe revision, `..`와 symlink path, 잘못된 calendar date, malformed HTTP framing을 확인합니다. 또한 서버가 중단된 동안 agent event가 SQLite queue에 남고 server 재시작 뒤 같은 event가 전달되어 queue에서 제거되는 단일 recovery 경로를 실행합니다.

`tests/json_parser_test.cpp`는 같은 테스트를 Agent와 Server의 JSON parser 사본 각각에 컴파일합니다. `tests/http_parser_test.cpp`는 순수 HTTP parser의 정상·거부 경계와 크기 상한을 socket 없이 확인합니다. `tests/http_parser_fuzz.cpp`는 `-DSEA_BUILD_HTTP_FUZZER=ON`으로 별도 빌드하며, `tests/http_fuzz_corpus` seed로 libFuzzer 입력을 변형합니다. 이 구조는 두 JSON parser 사본의 drift를 줄이는 회귀 장치이지, 두 구현이 같음을 증명하거나 Unicode 전체를 처리한다는 뜻은 아닙니다. HTTP fuzz 입력은 짧은 개발 실행을 통과했지만 장기 fuzz campaign은 별도 검증입니다.
