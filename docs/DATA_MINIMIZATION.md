# Data minimization

The agent can generate a fixed synthetic health heartbeat or explicitly import one bounded `event.v1` JSON record. Importing reads only the selected event document; it never opens the event's target file. The importer validates an allowlist of source, kind, severity, actor, evidence, and coverage metadata. Unknown fields such as file content, environment, token, secret, and command output are rejected.

An imported target path must be absolute and resolve under an active policy monitored root. The agent stores a per-store 32-byte random HMAC key in `path-pseudonym.key` with mode 0600, then places only `hmac-sha256:<digest>` in the normalized payload. The raw target path is not added to the queue or sent to the server. `host_id` is validated but omitted; the mTLS agent identity is authoritative. Pathless input is allowed only for non-healthy `coverage.*` events. `telemetry_enabled` is required and `sample_rate` applies to imports as it does to synthetic events.

HMAC pseudonyms support within-store correlation, so they are not anonymous. An attacker with read access to both the store and key can test candidate paths. The local dedup ledger keeps event IDs and normalized payload hashes (not raw paths) and is bounded to 100,000 IDs.

The server stores only agent ID, event ID, sequence, payload hash, and receipt time. The server rejects batches that include common sensitive field names. Logs do not include the TLS key, certificate material, or raw event payload. No remote command, process execution, or target file content collection path exists.

## Long-running root collector

`run --interval-seconds N` watches only directories in the active signed policy. It reads directory entries and inode metadata needed to identify a notification; it does not open file contents, scan file bytes, collect arbitrary environment variables, or invoke commands. Each file event is normalized through the event.v1 allowlist and the raw path is replaced by a per-store HMAC identifier before durable queue storage. Directory traversal uses no-follow directory file descriptors, skips symlink directories and other-device subtrees, and a watch loss or inotify overflow becomes a degraded-coverage event. A policy revision change replaces the watch set. The collector implementation was added after the last recorded verification and remains technically unverified; its limits and failure paths must not be described as a complete file-integrity monitor.
