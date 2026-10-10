# Linux 내부 동작 설명 — Linux Secure Endpoint Agent Lab

## TCP socket과 파일 descriptor

Agent는 `getaddrinfo`로 주소를 찾고 loopback 주소만 남긴 뒤 `socket`, `setsockopt`, `connect`를 사용합니다. Server는 `socket`, `setsockopt(SO_REUSEADDR)`, `bind(INADDR_LOOPBACK)`, `listen`, `accept4(SOCK_CLOEXEC)` 순서로 연결을 받습니다. 각 FD는 세션이 끝날 때 `close`해야 합니다. `SOCK_CLOEXEC`은 `exec` 뒤 의도치 않은 FD 상속을 줄입니다.

TCP는 메시지 경계가 없는 순서 있는 byte stream입니다. 한 번의 `send`가 상대편 한 번의 `recv`로 대응한다고 가정할 수 없습니다. 이 프로젝트는 HTTP header 끝과 Content-Length로 application 메시지 경계를 만듭니다. Server는 header 16 KiB, body 1 MiB를 상한으로 두고 ambiguous framing을 거부합니다.

`SO_RCVTIMEO`와 `SO_SNDTIMEO`는 개별 block I/O 대기시간을 설정하는 socket option입니다. 현재 server는 accepted socket에 5초를 적용하고, TLS handshake에는 별도 기본 10초 absolute deadline을 적용합니다. HTTP request read는 TLS/CN 인증 뒤 시작하는 또 다른 10초 deadline을 가집니다. 두 deadline은 각각 `--handshake-deadline-ms`와 `--request-deadline-ms`에서 100–60,000 ms로 설정합니다. HTTP read마다 남은 전체 request deadline과 5초 중 짧은 timeout을 적용하므로, 조금씩 byte를 보내 개별 timeout을 계속 갱신하려는 client도 요청 수명을 무한히 늘릴 수 없습니다. 두 기한 모두 route 처리나 순차 server의 동시성·rate limit 문제를 해결하지는 않습니다.

## Socket 위의 TLS

OpenSSL의 `SSL*`는 `SSL_set_fd`로 socket에 연결되고 `SSL_accept`/`SSL_connect` handshake와 `SSL_read`/`SSL_write` record I/O를 처리합니다. TLS record와 HTTP body 경계는 서로 다른 계층입니다.

Server는 `SSL_accept` 동안 accepted socket을 nonblocking으로 둡니다. `SSL_accept`가 1을 반환하면 handshake가 끝났고, 그렇지 않으면 직후 `SSL_get_error`로 결과를 분류합니다. `SSL_ERROR_WANT_READ`는 socket을 읽을 수 있게 될 때까지, `SSL_ERROR_WANT_WRITE`는 쓸 수 있게 될 때까지 기다려야 한다는 뜻입니다. `accept_tls_with_deadline`는 요청된 이벤트를 `poll(2)`로 기다리며 매 회 `std::chrono::steady_clock`의 절대 종료 시각에서 남은 시간을 다시 계산합니다. `EINTR`이면 남은 budget으로 재평가하고, deadline이 지나면 handshake를 포기합니다. 종료 후 원래 `fcntl(F_GETFL)` flag를 복구해 기존 blocking `SSL_read` HTTP 경로로 이어집니다. 이 구조가 slow trickle ClientHello가 매번 I/O progress를 만들어도 전체 handshake 제한을 늘리지 않는 이유입니다. 서버는 여전히 단일 연결 처리이므로 만료된 handshake 하나가 최대 handshake budget만큼 accept loop를 점유할 수 있습니다.

Agent는 CA chain과 DNS/IP SAN을 확인하고 client certificate를 제시합니다. Server는 CA를 확인하고 peer certificate의 CN을 역할별 local allowlist와 대조합니다. Policy publication은 별도 operator 인증서와 bearer token을 둘 다 요구합니다. Token은 server-user 소유의 mode-0600 파일에서 읽으며 constant-time 비교로 검사합니다. CN allowlist는 실습용 연결이며 enrollment, revocation, 자동 rotation을 갖춘 PKI는 아닙니다.

TLS는 전송 중 데이터 보호와 인증을 제공합니다. 정책 발급자 권한은 별도 Ed25519 signature로 검증합니다. 정책 서명은 원본 파일 bytes에 묶이므로 공백 한 글자만 바뀌어도 검증에 실패합니다. 같은 호스트의 root/admin 프로세스나 키 파일 탈취를 token 비교 기법이 막아주지는 않습니다.

## HTTP framing과 모호한 메시지 거부

Server와 Agent는 full HTTP implementation이 아니라 제한된 HTTP/1.1 subset을 처리합니다. Server는 한 Host, batch의 `application/json` Content-Type, POST Content-Length, decimal-only length를 요구하고 duplicate Content-Length/Content-Type/Authorization/If-None-Match와 모든 Transfer-Encoding을 거부합니다. Agent event response parser는 정확한 HTTP 200만 ACK로 받고, policy fetch parser는 HTTP 200/304만 허용합니다. 둘 다 Content-Length와 본문 경계를 검사합니다. Policy route는 문서 SHA-256을 ETag로 사용하고 일치하는 `If-None-Match`에 본문 없는 304를 응답합니다.

이 정책은 여러 proxy/parser가 같은 byte stream을 다른 길이로 해석하는 상황을 줄이기 위한 것입니다. RFC의 모든 헤더 규칙·상태코드별 body semantics·chunked encoding을 지원하지 않습니다. 그러므로 custom parser를 인터넷 노출 서버에 재사용하면 안 됩니다. 현재 loopback 제한과 테스트는 lab scope의 경계입니다.

`SSL_read`는 TLS application bytes를 돌려주며 한 호출이 한 HTTP 요청과 대응하지 않습니다. `read_request`가 이를 `std::string`에 누적하고, `parse_request_head`가 CRLF delimiter를 찾은 뒤 Content-Length와 제한을 검사합니다. head가 끝나지 않은 상태는 `nullopt`로 표현되어 더 읽을 수 있고, 완성된 `Request`에는 입력 `string_view`를 남기지 않고 소유형 문자열을 복사합니다. 이 함수는 handshake 완료 뒤 만들어진 단조 시계 deadline을 매 read 전에 확인하고, socket receive timeout을 남은 시간에 맞춰 줄입니다. 따라서 view는 parser 호출 안에서만 유효하고, 이후 TLS buffer 재사용과 분리됩니다.

`tests/http_parser_test.cpp`는 TLS 연결 없이 경계 조건을 회귀 검사합니다. 선택형 libFuzzer harness는 parser에 임의 바이트를 직접 전달하고, malformed request의 예외는 정상적인 입력 거부로 취급합니다. Clang libFuzzer+ASan+UBSan 100,000회 개발 실행은 실패 없이 완료되었지만, 이는 특정 seed와 짧은 실행의 결과입니다. 전체 RFC 문법, 장시간 안정성, server concurrency나 TLS 상태 전이를 보증하지 않습니다.

## event.v1 import, 경로 가명화와 파일 자원

`import-event`는 1 MiB 제한 안에서 사용자가 지정한 JSON 파일을 읽습니다. C++ stream/`std::string`이 입력 buffer를 소유하고 parser `Value`가 분리된 문자열을 소유합니다. 이 값에서 허용 필드만 새 `Object`로 구성하므로 원본 `target.path`나 `host_id`는 normalized payload에 들어가지 않습니다. Raw path와 canonical path는 함수가 실행되는 동안 사용자 공간 메모리에 잠시 존재하고 종료 시 일반 C++ 객체로 해제되지만, `std::string` 소멸자가 메모리 zeroization을 보장하지는 않습니다. 대상 파일의 FD는 만들지 않으며 file content를 읽지 않습니다.

경로 검사에는 `std::filesystem::weakly_canonical`을 사용합니다. 존재하는 path 구성 요소와 symlink를 현재 파일시스템 상태에 맞게 정규화한 다음 root와 component 단위로 비교합니다. 마지막 파일이 없어도 기존 parent 기준으로 path를 검사할 수 있습니다. 이는 정책 scope를 적용하는 경계지만 descriptor 기반 확정 접근이 아니어서 symlink가 동시에 변경되는 race를 완전히 제거하지 않습니다. Importer가 target을 열지 않기 때문에 이 race가 외부 파일 내용을 읽게 하지는 않으나, 실제 collector로 재사용해서는 안 됩니다.

`path-pseudonym.key`를 처음 만들 때 `open(O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW, 0600)`으로 기존 파일을 덮지 않고 생성하고, `RAND_bytes`로 32 bytes를 채운 뒤 `write`, `fsync`, `close`합니다. 이미 있으면 `open(O_NOFOLLOW)` 후 `fstat`으로 일반 파일, 현재 euid 소유, group/other 권한 없음, 정확히 32 bytes인지 확인한 뒤 `read`합니다. key buffer는 HMAC 계산 후 `OPENSSL_cleanse`로 지웁니다. HMAC은 외부에 raw path를 보내지 않고 같은 store 내 경로 상관을 유지합니다. HMAC은 익명화가 아니며, store와 key 모두에 접근할 수 있는 사람은 알려진 후보 경로를 대조할 수 있습니다.

`enqueue_imported_event`는 SQLite `BEGIN IMMEDIATE` writer transaction 안에서 event ID dedup, queue quota, `next_sequence`, queue row와 `imported_events` hash tombstone을 처리합니다. `COMMIT` 전 실패는 `ROLLBACK`하여 sequence와 dedup만 남는 상태를 피합니다. `sqlite3_stmt`는 `ScopedStatement` 수명 동안만 존재하고 destructor에서 `sqlite3_finalize`합니다. SQLite WAL은 readers와 writer의 일부 동시 작업을 돕지만 writer는 단일 직렬화 자원입니다. 동시에 실행한 import process는 busy timeout을 공유하며, 경합/DB 장애에서 실패하면 importer를 다시 호출할 수 있습니다. HMAC key 파일 생성 직후 다른 process가 읽으면 부분 파일을 관찰할 수 있어 안전한 오류로 거부될 수 있으며, retry 동작은 별도 동시성 시험 대상입니다.

정책 revision 숫자는 JSON parser 안에서 `double`로 표현됩니다. 음수·분수 또는 binary64가 정확히 표현할 수 없는 큰 정수는 unsigned 정수나 SQLite `INTEGER`에 바로 변환하지 말고 먼저 거부해야 합니다. 이 구현은 양의 안전 정수만 저장 가능한 범위로 받고, 음수·소수·`2^53` revision과 기존 last-good 값의 보존을 smoke에서 확인합니다.

## 저장 정책의 runtime gate와 표본 추출

`active_policy`는 SQLite `policy_state`에서 마지막 문서와 issuer/revision을 읽습니다. SQLite column 포인터는 statement finalize 뒤 유효하지 않으므로, 코드가 issuer와 document bytes를 소유형 문자열로 복사한 뒤 `sqlite3_finalize`를 호출합니다. JSON 문서를 다시 parse해 DB revision·issuer, tenant, expiry, settings와 `allowed_actions`를 대조합니다. 문서가 손상되었거나 tenant가 다르면 실행 경로는 오류를 내고 멈춥니다. 정책이 없으면 telemetry는 기본 비활성입니다.

합성 이벤트 생성 경로는 `telemetry_enabled`가 false이거나 정책이 만료되면 새 이벤트를 저장하지 않습니다. `sample_rate`가 0이면 이벤트를 만들지 않고, 1이면 모두 만들며, 중간값이면 `RAND_bytes`가 제공한 64 random bit 중 상위 53 bit를 [0, 1) 범위 표본으로 사용해 설정 비율과 비교합니다. OpenSSL random API가 실패하면 표본을 추측해 계속하지 않고 오류 처리합니다. 표본 통과 후에만 sequence 증가·UUID 생성·SQLite enqueue를 진행하므로 제외된 샘플은 queue 용량을 차지하지 않습니다.

`flush`는 각 전송 batch 전에 정책을 다시 읽습니다. 정책이 없거나 stale/telemetry-disabled이면 전송을 멈추고 기존 queue row를 유지합니다. `sample_rate=0`은 생성만 제어하므로 telemetry가 활성 상태면 기존 queue를 전송할 수 있습니다. 이미 네트워크 요청을 시작한 batch는 뒤에서 정책이 바뀌어도 취소되지 않습니다. `status`는 `NO_POLICY`, `STALE`, `ACTIVE`, `VALIDATED`와 revision, telemetry flag, sample rate, monitored root 수, queue 크기를 보여줍니다. 장기 `run`은 active monitored roots를 재귀 inotify watch로 적용하며 변경은 event.v1 metadata event가 됩니다. collector 추가 이후의 빌드와 실행 검증은 하지 않았습니다.

## SQLite transaction과 ACK 의미

WAL은 변경을 `-wal` 파일에 기록하고 checkpoint를 통해 본 DB에 반영합니다. DB와 WAL은 실행 중 함께 상태의 일부이므로 DB 하나만 복사해 일관된 백업이라 가정하면 안 됩니다. WAL은 reader와 writer의 일부 동시 작업을 돕지만 한 번에 하나의 writer를 허용합니다.

Agent는 network 전에 event를 저장합니다. Server는 event transaction을 commit하고 그 뒤 ACK를 보냅니다. 응답이 유실되면 agent가 재전송할 수 있고 `(agent_id,event_id)`가 같은 행을 식별합니다. 같은 sequence/hash일 때만 duplicate로 처리되므로 이는 DB 경계의 멱등성이지 네트워크상 exactly-once 전송은 아닙니다.

Sequence 증가와 event 삽입은 별도 transaction이라 crash 후 sequence gap이 생길 수 있습니다. 보장하려는 것은 gap 없는 숫자가 아니라 저장된 이벤트의 식별성과 재시도 가능한 상태입니다.

## JSON 입력 경계

각 프로그램의 parser는 JSON 숫자 문법, JSON 공백 네 종류, duplicate object key 거부, 깊이 32, 입력 1 MiB 제한을 적용합니다. 숫자는 grammar를 먼저 확인하고 `std::from_chars`로 변환합니다. agent/server 헤더가 복제되어 있으므로 같은 테스트를 양쪽에 각각 빌드합니다. Unicode surrogate pair 등 완전한 Unicode 처리가 필요한 범용 parser라고 주장하지 않습니다.

## 정책 경로 정규화와 심볼릭 링크

정책의 monitored root를 사용자 입력 문자열의 접두사 비교만으로 제한하면 안 됩니다. `..` 구성 요소는 allowlist prefix가 문자열에 남아 있어도 다른 디렉터리를 가리킬 수 있고, 심볼릭 링크는 겉으로 보이는 위치와 실제 대상을 분리합니다. Agent는 설정된 허용 디렉터리와 각 요청 경로를 `std::filesystem::canonical`로 정규화해 기존 디렉터리 여부를 확인한 다음 경로 구성 요소를 비교합니다. `/safe/root2`는 `/safe/root`의 하위 경로가 아니므로 텍스트 prefix가 아니라 component 경계가 중요합니다.

정책 sync는 정책 root를 last-good DB에 저장하기 전에 검사하고, `import-event`는 가져온 이벤트 경로를 다시 검사합니다. 장기 `run` collector는 파일 내용을 읽지 않고 directory notification과 제한된 stat metadata만 수집합니다. Collector는 component별 `openat(O_NOFOLLOW)`로 directory FD를 확보한 뒤 watch를 설치하고, importer는 경로를 HMAC pseudonym으로 바꿉니다. 이 조합은 symlink traversal을 줄이지만 모든 mount/namespace race를 막는 descriptor policy가 아닙니다. Linux `openat2(2)`의 `RESOLVE_BENEATH`·`RESOLVE_NO_SYMLINKS`는 더 강한 path resolution을 제공하는 대안입니다.

## systemd와 프로세스 경계

예제 unit은 전용 사용자, `NoNewPrivileges`, 제한된 파일시스템 view, private temporary directory, 명시 writable 경로를 보여줍니다. 실제 설치·사용자 생성·key provisioning·uninstall은 구현되지 않았습니다. service sandbox는 TLS와 애플리케이션 인증 대신 사용할 수 없습니다.

## inotify collector의 syscall 흐름

`inotify_init1(IN_NONBLOCK | IN_CLOEXEC)`는 daemon이 소유할 FD 하나를 만들고, `inotify_add_watch`는 디렉터리별 create/close-write/attribute/delete/move mask를 등록합니다. 파일마다 FD를 열지 않습니다. `poll`은 250ms 이하로 readiness를 기다리고, `read`는 커널이 만든 `inotify_event` 레코드 배열을 비운 뒤 mask별 이벤트를 구분합니다. `IN_Q_OVERFLOW`는 어느 경로 이벤트가 빠졌는지 알 수 없으므로 degraded coverage로 취급합니다.

Tree traversal은 root에서 시작해 `openat(parent_fd, name, O_DIRECTORY|O_NOFOLLOW)`로 하위 디렉터리를 엽니다. `fstatat(..., AT_SYMLINK_NOFOLLOW)`는 symlink directory를 따라가지 않게 하고, `fdopendir(dup(fd))`/`readdir`는 이름 목록만 조회합니다. `inotify_add_watch`가 pathname 인자를 받으므로 `/proc/self/fd/N`을 사용해 이미 열린 directory object에 watch를 붙입니다. `fstat`의 `st_dev`가 root와 다른 하위 directory는 넘어갑니다. 이 방식도 mount namespace나 같은 device의 bind mount 경계를 완전하게 식별하지는 않습니다.

`InotifyCollector`는 장기 inotify FD와 watch descriptor map을 소유합니다. 루트 traversal의 각 FD는 즉시 닫히고, `DIR*`는 `closedir`가 닫습니다. 신호는 `sig_atomic_t` 종료 flag를 세워 poll loop가 자원을 정상 정리하도록 합니다. 하나의 event loop가 inotify 알림, SQLite transaction, queue flush를 처리하므로 이 구현에는 collector worker thread 경쟁이 없습니다.

알림은 파일 내용을 증명하지 않습니다. `IN_CLOSE_WRITE`는 write access가 닫혔다는 신호일 뿐, 내용이 안정됐거나 악성임을 의미하지 않습니다. Rename은 source와 destination directory에서 각각 보고될 수 있고 cookie로 쌍을 이루어야 한다는 제약이 남아 있습니다. Overflow 뒤에는 현재 디렉터리를 다시 watch하지만 놓친 변화의 history를 복구할 baseline scan은 하지 않으므로 degraded coverage를 유지합니다. 정확한 상태 복구가 필요하면 baseline/hash를 가진 FIM subsystem이나 fanotify 기반 설계를 따로 검토해야 합니다.

## 공식 문서

- Linux man-pages: [`socket(2)`](https://man7.org/linux/man-pages/man2/socket.2.html), [`setsockopt(2)`](https://man7.org/linux/man-pages/man2/setsockopt.2.html), [`accept(2)`](https://man7.org/linux/man-pages/man2/accept.2.html), [`socket(7)`](https://man7.org/linux/man-pages/man7/socket.7.html), [`close(2)`](https://man7.org/linux/man-pages/man2/close.2.html)
- Linux man-pages: [`open(2)`](https://man7.org/linux/man-pages/man2/open.2.html), [`read(2)`](https://man7.org/linux/man-pages/man2/read.2.html), [`write(2)`](https://man7.org/linux/man-pages/man2/write.2.html), [`fsync(2)`](https://man7.org/linux/man-pages/man2/fsync.2.html), [`fstat(2)`](https://man7.org/linux/man-pages/man2/fstat.2.html), [`openat(2)`](https://man7.org/linux/man-pages/man2/openat.2.html), [`fstatat(2)`](https://man7.org/linux/man-pages/man2/fstatat.2.html), [`fdopendir(3)`](https://man7.org/linux/man-pages/man3/fdopendir.3.html), [`readdir(3)`](https://man7.org/linux/man-pages/man3/readdir.3.html)
- Linux path resolution: [`path_resolution(7)`](https://man7.org/linux/man-pages/man7/path_resolution.7.html), [`openat2(2)`](https://man7.org/linux/man-pages/man2/openat2.2.html), [`realpath(3)`](https://man7.org/linux/man-pages/man3/realpath.3.html)
- OpenSSL: [`SSL_CTX_set_verify`](https://docs.openssl.org/3.0/man3/SSL_CTX_set_verify/), [`SSL_set1_host`](https://docs.openssl.org/3.0/man3/SSL_set1_host/), [`SSL_accept`](https://docs.openssl.org/3.0/man3/SSL_accept/), [`SSL_get_error`](https://docs.openssl.org/3.0/man3/SSL_get_error/), [`SSL_read`](https://docs.openssl.org/3.0/man3/SSL_read/), [`SSL_write`](https://docs.openssl.org/3.0/man3/SSL_write/)
- Linux man-pages: [`poll(2)`](https://man7.org/linux/man-pages/man2/poll.2.html), [`fcntl(2)`](https://man7.org/linux/man-pages/man2/fcntl.2.html), [`inotify_init1(2)`](https://man7.org/linux/man-pages/man2/inotify_init1.2.html), [`inotify_add_watch(2)`](https://man7.org/linux/man-pages/man2/inotify_add_watch.2.html), [`inotify(7)`](https://man7.org/linux/man-pages/man7/inotify.7.html)
- OpenSSL random API: [`RAND_bytes`](https://docs.openssl.org/3.0/man3/RAND_bytes/)
- OpenSSL keyed digest API: [`HMAC`](https://docs.openssl.org/3.0/man3/HMAC/)
- IETF: [RFC 9112 — HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112), [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446), [RFC 8259 — JSON](https://www.rfc-editor.org/rfc/rfc8259)
- LLVM: [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- SQLite: [WAL](https://www.sqlite.org/wal.html), [Atomic Commit](https://www.sqlite.org/atomiccommit.html)
- systemd: [`systemd.exec`](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
