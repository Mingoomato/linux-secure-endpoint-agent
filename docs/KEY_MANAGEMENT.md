# Key management

The lab script creates a local RSA CA, one server certificate with localhost and 127.0.0.1 SANs, one agent client certificate whose common name is the lab agent UUID, one separate operator client certificate, an operator CN allowlist, and an Ed25519 policy signing key. Generated material is written to a caller-selected directory outside this repository and uses a restrictive umask. The server also reads an independent bearer token from a server-user-owned file with mode 0600; create it with a restrictive umask and keep it outside source control.

The CA, server, agent, operator, policy private keys, and bearer token are lab-only. Do not copy them into source control or reuse them outside a disposable local exercise. The operator route requires both an allowlisted operator mTLS identity and the bearer token; the agent certificate alone cannot publish. This is a two-factor lab boundary, not production RBAC. Rotation, revocation, online enrollment, hardware-backed keys, and production PKI are not implemented.

The server signs raw policy bytes with Ed25519 and returns a detached raw 64-byte signature encoded as hex in the fetch envelope. Any whitespace change therefore changes the signed content. Keep the signing private key separate from the agent verification public key; mTLS authenticates the transport peer but does not replace policy signature verification.
