#!/usr/bin/env python3
"""Exercise real inotify directory renames against an offline durable spool."""
import json
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

binary = Path(sys.argv[1]).resolve()
repo = Path(__file__).resolve().parents[1]

def run(*args):
    return subprocess.run(list(map(str, args)), check=True, capture_output=True, text=True, timeout=20)

with tempfile.TemporaryDirectory(prefix="sea-collector-") as tmp:
    base = Path(tmp)
    certs, monitored, store = base / "certs", base / "monitored", base / "store"
    (monitored / "before").mkdir(parents=True)
    run(repo / "scripts/create-local-ca.sh", certs)
    policy = {"schema_version": "policy.v1", "policy_id": "collector-test", "revision": 1,
              "issuer": "collector-test", "issued_at": "2026-10-10T00:00:00Z",
              "expires_at": "2099-01-01T00:00:00Z", "tenant_scope": "collector-tenant",
              "allowed_actions": ["telemetry.configure", "monitor.roots.configure"],
              "settings": {"telemetry_enabled": True, "sample_rate": 1, "monitored_roots": [str(monitored)]}}
    document, signature = base / "policy.json", base / "policy.sig"
    document.write_text(json.dumps(policy))
    run("openssl", "pkeyutl", "-sign", "-rawin", "-inkey", certs / "policy-signing.key",
        "-in", document, "-out", signature)
    run(binary, "validate-policy", "--store", store, "--file", document, "--signature", signature,
        "--pubkey", certs / "policy-signing.pub", "--tenant", "collector-tenant", "--root", monitored)
    # Reserve an offline loopback port so this test never contacts another service.
    with socket.socket() as offline, (base / "agent.log").open("w+") as log:
        offline.bind(("127.0.0.1", 0))
        process = subprocess.Popen(list(map(str, [binary, "run", "--store", store,
            "--tenant", "collector-tenant", "--agent-id", "00000000-0000-4000-8000-000000000001",
            "--endpoint", "127.0.0.1", "--port", offline.getsockname()[1],
            "--ca", certs / "ca.crt", "--cert", certs / "agent.crt", "--key", certs / "agent.key",
            "--interval-seconds", "60"])), stdout=log, stderr=log)
        def records():
            with sqlite3.connect(store / "spool.sqlite") as db:
                return [json.loads(row[0]) for row in db.execute("SELECT payload FROM queue ORDER BY sequence")]
        def await_kind(kind, after=0):
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    log.seek(0)
                    raise AssertionError(log.read())
                current = records()
                if any(row["kind"] == kind and row["sequence"] > after for row in current):
                    return current
                time.sleep(0.03)
            log.seek(0)
            raise AssertionError((kind, records(), log.read()))
        try:
            await_kind("health.heartbeat")
            (monitored / "before").rename(monitored / "after")
            current = await_kind("directory.renamed")
            current = await_kind("coverage.watch_degraded")
            last = max(row["sequence"] for row in current)
            (monitored / "after" / "new.txt").write_text("CONTENT_MARKER_NOT_TELEMETRY")
            current = await_kind("file.modified", after=last)
            encoded = json.dumps(current)
            assert str(monitored) not in encoded and "CONTENT_MARKER_NOT_TELEMETRY" not in encoded
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise
        assert process.returncode in (0, 1), process.returncode
print("offline collector directory rename, rebuilt watch and path privacy: PASS")
