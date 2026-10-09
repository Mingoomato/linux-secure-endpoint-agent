# Data minimization

The agent generates a synthetic health heartbeat with a fixed non-sensitive payload. It does not read file contents, arbitrary environment variables, command output, tokens, or keys. File-system watcher plugins are not included.

The server stores only agent ID, event ID, sequence, payload hash, and receipt time. The server rejects batches that include common sensitive field names. Logs do not include the TLS key, certificate material, or raw event payload.
