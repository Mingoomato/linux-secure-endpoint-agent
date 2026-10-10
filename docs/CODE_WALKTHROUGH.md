# 코드 따라 읽기 — Linux Secure Endpoint Agent Lab

이 문서는 주요 기능이 어떤 순서로 실행되는지 소스 코드에서 따라가기 위한 안내입니다. 실제 line number는 버전에 따라 달라질 수 있으므로 아래 함수명을 기준으로 찾으세요.

## 1. Agent 설정과 내구성 큐

`agent/src/agent.cpp`의 `main`이 하위 명령을 고르고 `Config`를 구성합니다. `is_loopback`은 network command가 외부 host를 대상으로 하지 못하게 제한합니다. `open_queue`는 전용 디렉터리를 준비하고 `spool.sqlite`에서 WAL, `synchronous=FULL`, queue/sequence/policy 테이블을 설정합니다.

`next_sequence`는 `BEGIN IMMEDIATE` transaction으로 저장된 sequence를 읽고 증가시킵니다. `enqueue`는 고정 합성 상태 payload와 UUID, timestamp, payload hash를 만들고 quota를 확인해 row를 기록합니다. 이 저장이 `send_batch`보다 먼저 일어나는 것이 전송 실패 시 보존의 근거입니다.

## 2. Client TLS와 HTTP 응답

`client_context`는 TLS client context를 준비하고 최소 TLS 버전, trust CA, client certificate/private key, key 권한, client identity를 확인합니다. `connect_socket`은 `getaddrinfo` 결과 중 loopback 주소만 연결합니다. `send_batch`는 `SSL_set1_host` 또는 IP 검증 설정 뒤 `SSL_connect`를 수행합니다.

요청은 `/v1/agents/self/events:batch`에 JSON body와 `Content-Length`를 포함합니다. `http_exchange`는 SSL write 전체를 보내고, 상태 줄과 각 header 문법을 확인합니다. 응답 header는 16 KiB, 본문은 1 MiB까지이고 Content-Length는 정확히 하나여야 합니다. 중복 길이, `Transfer-Encoding`, 잘못된 숫자, truncation, 선언 길이를 넘어온 바이트를 거부합니다.

`ack_ids`는 accepted/duplicate 배열을 JSON으로 파싱합니다. `flush`는 서버가 돌려준 값이 실제 보낸 ID인지 확인하고 확인된 항목만 SQLite transaction에서 제거합니다. 실패하면 남은 queue로 bounded retry를 반복합니다.

## 3. Server의 수신부터 ACK까지

`server/src/server.cpp`의 `run_server`가 인증서와 allowlist, SQLite DB를 열고 loopback listener를 만듭니다. `accept4`가 연결마다 close-on-exec FD를 주며, 순차 accept loop가 `serve_one`을 호출합니다.

`serve_one`은 accepted socket에 5초 receive/send timeout을 설정하고 TLS handshake를 진행합니다. client certificate chain을 확인한 뒤 `peer_cn`의 CN이 allowlist에 있는지 확인합니다. 따라서 mTLS 연결을 맺었다는 것만으로 애플리케이션 권한이 생기지 않습니다.

`read_request`는 제한된 HTTP/1.1 parser입니다. request line은 origin-form path와 HTTP/1.1만 허용합니다. header는 최대 16 KiB, body는 1 MiB이며 Host 한 개를 요구하고 POST에는 단일 Content-Length를 요구합니다. Transfer-Encoding, 중복 Content-Length, GET body, 잘못된 header와 초과 바이트는 처리하지 않습니다.

경로 분기 뒤 event batch는 `ingest`로 갑니다. `ingest`가 JSON batch version, 인증서 identity와 body의 agent ID, 이벤트 수, 민감 키, payload hash를 검증합니다. SQLite transaction은 event ID 고유성으로 중복을 잡습니다. 같은 ID의 sequence와 hash가 동일하면 duplicate ACK에 추가하고, 내용이 다르면 rollback/error가 됩니다. DB commit이 끝난 뒤에만 응답을 작성합니다.

## 4. Policy 검증과 저장

CLI의 `validate-policy` 경로는 `read_limited`로 크기가 제한된 파일을 읽고 `validate_signed_policy`를 호출합니다. 이 함수는 JSON 해석 전에 원본 파일 bytes의 Ed25519 signature를 검증합니다. 이후 허용 필드, action, expiry, tenant 및 monitored root 범위, revision을 확인합니다. 유효한 새 revision만 DB transaction으로 last-good 상태에 저장합니다. server의 policy GET 경로는 현재 변경 없는 응답을 주며 실제 배포·적용 기능은 구현되지 않았습니다.

## 5. 예외와 소유권 추적

Agent와 Server의 `SSL_CTX`/`SSL*`는 `unique_ptr`를 사용하며 연결 socket FD는 `ScopedFd`가 정리합니다. SQLite handle/statement와 일부 policy OpenSSL 객체는 수동 정리하는 경로가 있습니다. 코드를 변경할 때 각 할당 이후 `throw`, 조기 `return`, TLS 실패가 발생하면 어떤 객체가 해제되는지 확인해야 합니다.

큐 row는 ACK 전까지 남아야 합니다. 반대로 statement는 사용 후 `sqlite3_finalize`, transaction은 commit/rollback, `SSL*`는 해제, FD는 `close`되어야 합니다. event sequence 증가와 row insert가 별도 transaction이므로 process crash가 sequence gap을 만들 수 있습니다.

## 6. 회귀 테스트

`tests/smoke.sh`는 임시 디렉터리에서 로컬 CA를 만들고 loopback mTLS 연결, event ACK, deduplication, 충돌 ID 거부, allowlist 거부, 정책 signature/tamper/replay를 확인합니다. HTTP 음성 사례는 duplicate Content-Length, Transfer-Encoding, 잘못된/초과 길이, 누락 길이, HTTP/1.0, GET body, 중복 Host, 초과 header와 incomplete body timeout을 검사합니다. 또한 서버가 중단된 동안 agent event가 SQLite queue에 남고 server 재시작 뒤 같은 event가 전달되어 queue에서 제거되는 단일 recovery 경로를 실행합니다.

`tests/json_parser_test.cpp`는 같은 테스트를 Agent와 Server의 JSON parser 사본 각각에 컴파일합니다. 이 구조는 두 사본의 drift를 줄이는 회귀 장치이지, 두 구현이 같음을 증명하거나 Unicode 전체를 처리한다는 뜻은 아닙니다.
