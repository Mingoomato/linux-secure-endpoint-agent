# ADR-001: loopback mTLS and detached policy signatures

- Status: accepted for the lab baseline.
- Decision: restrict the reference server and client to loopback; require mutual TLS; validate policy using detached Ed25519 signatures over exact bytes.
- Reason: server transport identity and policy issuer authority are distinct trust checks.
- Consequence: private-network deployment and admin policy publication are disabled. The local allowlist is manual and policy fetch returns 304.
