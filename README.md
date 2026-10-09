# Linux Secure Endpoint Agent Lab

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

Run `ctest --test-dir build --output-on-failure` to exercise local CA creation, authorized mTLS, synthetic event delivery and acknowledgement, deduplication, conflicting event-ID rejection, unregistered client rejection, and signed policy validation/tamper/rollback checks. Payload hashes use compact JSON with lexicographically sorted object keys.

## Limitations

The initial server handles one client at a time, has a minimal HTTP/1.1 parser, and does not implement operator authentication/RBAC, certificate revocation, policy distribution/signing, rate limiting, 429 backpressure, or event.v1 file input. The batch accepts only small synthetic health events. There is no remote command or process execution path. See `docs/TEST_RESULTS.md`; no performance result is claimed.
