# Linux Internals Explained — Linux Secure Endpoint Agent Lab

## TCP sockets and file descriptors

The client calls `getaddrinfo`, filters resolved IPv4/IPv6 addresses to loopback, creates a `SOCK_STREAM | SOCK_CLOEXEC` socket, sets send/receive timeouts, and calls `connect`. The server creates a stream socket, sets `SO_REUSEADDR`, binds to `INADDR_LOOPBACK`, calls `listen`, and accepts clients with `accept4(..., SOCK_CLOEXEC)`. A stream is a byte sequence, not a message transport; HTTP framing is built from headers and `Content-Length`.

Each accepted socket FD must be closed after the TLS session. `SOCK_CLOEXEC` avoids leaking descriptors into child processes after `exec`. `SO_RCVTIMEO`/`SO_SNDTIMEO` bound client blocking calls, but they are not a complete server slow-client timeout design.

## TLS sits above the socket

OpenSSL `SSL*` objects perform the TLS handshake and record I/O over the attached socket. The client verifies the server certificate chain and sets a DNS hostname or IP address check against the certificate SAN. It also presents a client certificate. The server requires a peer certificate and verifies it against its CA. The reference server then uses the certificate CN as an allowlist key; that is a lab identity mapping, not a complete PKI registration or revocation lifecycle.

TLS protects bytes in transit and authenticates the configured peers. It does not make a policy trustworthy by itself: the separate Ed25519 signature identifies the policy issuer and binds the exact policy bytes. A whitespace edit changes those bytes and invalidates the signature.

## SQLite transactions and ACK semantics

WAL plus `synchronous=FULL` persists queue/metadata changes locally. The event is inserted before networking. Server ingestion commits before returning an ACK. If the response is lost, the client retries; the server recognizes the `(agent_id,event_id)` duplicate and confirms it only when sequence and payload hash match. The client deletes only acknowledged IDs that it actually sent. This is idempotent at the database boundary, not magical exactly-once network delivery.

Sequence allocation and event insert happen in separate transactions, so a crash can leave a sequence gap. The invariant is uniqueness/order of committed queue rows, not gapless numbering.

## Systemd boundaries

The unit examples run under dedicated `swagent`/`swserver` users, `NoNewPrivileges`, restricted filesystem views, private temp directories, and explicit writable paths. These controls reduce service privilege but are examples only; installation, user creation, key provisioning, and uninstall behavior are not implemented here.

## Failure semantics

TLS handshake errors, wrong SAN, absent/invalid client certificate, unavailable server, malformed HTTP, oversized bodies, invalid JSON, queue quota, DB failure, invalid ACK, and policy signature/revision rejection are distinct failure classes. Queue retention protects against transient transport errors; disk exhaustion cannot retain new events and must be surfaced as degraded rather than silently claiming delivery.

## Official references

- [`socket(2)`](https://man7.org/linux/man-pages/man2/socket.2.html), [`connect(2)`](https://man7.org/linux/man-pages/man2/connect.2.html), [`bind(2)`](https://man7.org/linux/man-pages/man2/bind.2.html), [`accept(2)`](https://man7.org/linux/man-pages/man2/accept.2.html), [`close(2)`](https://man7.org/linux/man-pages/man2/close.2.html)
- [OpenSSL peer-certificate verification](https://docs.openssl.org/3.0/man3/SSL_CTX_set_verify/), [DNS/IP verification](https://docs.openssl.org/3.0/man3/SSL_set1_host/)
- [SQLite WAL](https://www.sqlite.org/wal.html) and [Atomic Commit](https://www.sqlite.org/atomiccommit.html)
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446), [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110)
- [systemd execution controls](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
