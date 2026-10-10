# Linux 내부 동작 설명 — Linux Secure Endpoint Agent Lab

## TCP socket과 파일 descriptor

Agent는 `getaddrinfo`로 주소를 찾고 loopback 주소만 남긴 뒤 `socket`, `setsockopt`, `connect`를 사용합니다. Server는 `socket`, `setsockopt(SO_REUSEADDR)`, `bind(INADDR_LOOPBACK)`, `listen`, `accept4(SOCK_CLOEXEC)` 순서로 연결을 받습니다. 각 FD는 세션이 끝날 때 `close`해야 합니다. `SOCK_CLOEXEC`은 `exec` 뒤 의도치 않은 FD 상속을 줄입니다.

TCP는 메시지 경계가 없는 순서 있는 byte stream입니다. 한 번의 `send`가 상대편 한 번의 `recv`로 대응한다고 가정할 수 없습니다. 이 프로젝트는 HTTP header 끝과 Content-Length로 application 메시지 경계를 만듭니다. Server는 header 16 KiB, body 1 MiB를 상한으로 두고 ambiguous framing을 거부합니다.

`SO_RCVTIMEO`와 `SO_SNDTIMEO`는 개별 block I/O 대기시간을 설정하는 socket option입니다. 현재 server는 accepted socket에 5초를 적용합니다. 이는 완전한 session deadline이 아니며, 여러 번의 부분 데이터가 시간 내 도착하면 총 처리시간이 더 길 수 있습니다. 순차 server의 느린 client 문제를 전부 해결하지도 않습니다.

## Socket 위의 TLS

OpenSSL의 `SSL*`는 `SSL_set_fd`로 socket에 연결되고 `SSL_accept`/`SSL_connect` handshake와 `SSL_read`/`SSL_write` record I/O를 처리합니다. TLS record와 HTTP body 경계는 서로 다른 계층입니다.

Agent는 CA chain과 DNS/IP SAN을 확인하고 client certificate를 제시합니다. Server는 CA를 확인하고 peer certificate의 CN을 local allowlist와 대조합니다. CN allowlist는 실습용 연결이며 enrollment, revocation, 자동 rotation을 갖춘 PKI는 아닙니다.

TLS는 전송 중 데이터 보호와 인증을 제공합니다. 정책 발급자 권한은 별도 Ed25519 signature로 검증합니다. 정책 서명은 원본 파일 bytes에 묶이므로 공백 한 글자만 바뀌어도 검증에 실패합니다.

## HTTP framing과 모호한 메시지 거부

Server와 Agent는 full HTTP implementation이 아니라 제한된 HTTP/1.1 subset을 처리합니다. Server는 한 Host, batch의 `application/json` Content-Type, POST Content-Length, decimal-only length를 요구하고 duplicate Content-Length/Content-Type과 모든 Transfer-Encoding을 거부합니다. Agent response parser도 Content-Length 하나만 허용하고 정확한 HTTP 200 status가 아닌 응답을 거부하며 길이 초과/잘림/추가 bytes를 검사합니다.

이 정책은 여러 proxy/parser가 같은 byte stream을 다른 길이로 해석하는 상황을 줄이기 위한 것입니다. RFC의 모든 헤더 규칙·상태코드별 body semantics·chunked encoding을 지원하지 않습니다. 그러므로 custom parser를 인터넷 노출 서버에 재사용하면 안 됩니다. 현재 loopback 제한과 테스트는 lab scope의 경계입니다.

## SQLite transaction과 ACK 의미

WAL은 변경을 `-wal` 파일에 기록하고 checkpoint를 통해 본 DB에 반영합니다. DB와 WAL은 실행 중 함께 상태의 일부이므로 DB 하나만 복사해 일관된 백업이라 가정하면 안 됩니다. WAL은 reader와 writer의 일부 동시 작업을 돕지만 한 번에 하나의 writer를 허용합니다.

Agent는 network 전에 event를 저장합니다. Server는 event transaction을 commit하고 그 뒤 ACK를 보냅니다. 응답이 유실되면 agent가 재전송할 수 있고 `(agent_id,event_id)`가 같은 행을 식별합니다. 같은 sequence/hash일 때만 duplicate로 처리되므로 이는 DB 경계의 멱등성이지 네트워크상 exactly-once 전송은 아닙니다.

Sequence 증가와 event 삽입은 별도 transaction이라 crash 후 sequence gap이 생길 수 있습니다. 보장하려는 것은 gap 없는 숫자가 아니라 저장된 이벤트의 식별성과 재시도 가능한 상태입니다.

## JSON 입력 경계

각 프로그램의 parser는 JSON 숫자 문법, JSON 공백 네 종류, duplicate object key 거부, 깊이 32, 입력 1 MiB 제한을 적용합니다. 숫자는 grammar를 먼저 확인하고 `std::from_chars`로 변환합니다. agent/server 헤더가 복제되어 있으므로 같은 테스트를 양쪽에 각각 빌드합니다. Unicode surrogate pair 등 완전한 Unicode 처리가 필요한 범용 parser라고 주장하지 않습니다.

## systemd와 프로세스 경계

예제 unit은 전용 사용자, `NoNewPrivileges`, 제한된 파일시스템 view, private temporary directory, 명시 writable 경로를 보여줍니다. 실제 설치·사용자 생성·key provisioning·uninstall은 구현되지 않았습니다. service sandbox는 TLS와 애플리케이션 인증 대신 사용할 수 없습니다.

## 공식 문서

- Linux man-pages: [`socket(2)`](https://man7.org/linux/man-pages/man2/socket.2.html), [`setsockopt(2)`](https://man7.org/linux/man-pages/man2/setsockopt.2.html), [`accept(2)`](https://man7.org/linux/man-pages/man2/accept.2.html), [`socket(7)`](https://man7.org/linux/man-pages/man7/socket.7.html), [`close(2)`](https://man7.org/linux/man-pages/man2/close.2.html)
- OpenSSL: [`SSL_CTX_set_verify`](https://docs.openssl.org/3.0/man3/SSL_CTX_set_verify/), [`SSL_set1_host`](https://docs.openssl.org/3.0/man3/SSL_set1_host/), [`SSL_read`](https://docs.openssl.org/3.0/man3/SSL_read/), [`SSL_write`](https://docs.openssl.org/3.0/man3/SSL_write/)
- IETF: [RFC 9112 — HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112), [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446), [RFC 8259 — JSON](https://www.rfc-editor.org/rfc/rfc8259)
- SQLite: [WAL](https://www.sqlite.org/wal.html), [Atomic Commit](https://www.sqlite.org/atomiccommit.html)
- systemd: [`systemd.exec`](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
