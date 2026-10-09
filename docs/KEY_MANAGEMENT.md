# Key management

The lab script creates a local RSA CA, one server certificate with localhost and 127.0.0.1 SANs, one client certificate whose common name is the lab agent UUID, and an Ed25519 policy signing key. Generated material is written to a caller-selected directory outside this repository and uses a restrictive umask.

The CA, server, client, and policy private keys are lab-only. Do not copy them into source control or reuse them outside a disposable local exercise. Rotation, revocation, online enrollment, hardware-backed keys, and production PKI are not implemented.

Policy signatures are raw 64-byte Ed25519 detached signatures over the exact bytes of the policy file. Any whitespace change therefore requires a new signature.
