#!/bin/sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bin_dir=${BIN_DIR:-"$root_dir/build"}
tmp=$(mktemp -d)
server_pid=
cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
    if [ "$status" -ne 0 ] && [ -f "$tmp/server.log" ]; then cat "$tmp/server.log" >&2; fi
    rm -rf "$tmp"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM
certs="$tmp/certs"
"$root_dir/scripts/create-local-ca.sh" "$certs" >/dev/null
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')

"$bin_dir/sw-server" run --bind 127.0.0.1 --port "$port" \
    --cert "$certs/server.crt" --key "$certs/server.key" --ca "$certs/ca.crt" \
    --agents "$certs/agents.txt" --db "$tmp/server.sqlite" >"$tmp/server.log" 2>&1 &
server_pid=$!
python3 - "$certs" "$port" <<'PY'
import socket, ssl, sys, time
certs, port = sys.argv[1], int(sys.argv[2])
ctx = ssl.create_default_context(cafile=certs + "/ca.crt")
ctx.load_cert_chain(certs + "/agent.crt", certs + "/agent.key")
last = None
for _ in range(100):
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=0.5)
        raw.settimeout(2)
        with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as sock:
            sock.sendall(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            response = sock.recv(4096)
        assert response.startswith(b"HTTP/1.1 200 "), response
        break
    except (OSError, ssl.SSLError):
        last = sys.exc_info()[1]
        time.sleep(0.05)
else:
    raise SystemExit("mTLS health check did not become ready: " + str(last))
PY

"$bin_dir/sw-agentd" run --endpoint 127.0.0.1 --port "$port" \
    --agent-id 00000000-0000-4000-8000-000000000001 --ca "$certs/ca.crt" \
    --cert "$certs/agent.crt" --key "$certs/agent.key" --store "$tmp/agent-store"
"$bin_dir/sw-agentd" status --store "$tmp/agent-store" >"$tmp/agent-status.json"
python3 - "$tmp/agent-status.json" "$tmp/server.sqlite" <<'PY'
import json, sqlite3, sys
status = json.load(open(sys.argv[1], encoding="utf-8"))
assert status["queued"] == 0, status
db = sqlite3.connect(sys.argv[2])
rows = db.execute("select count(*), min(sequence), min(length(payload_hash)) from events").fetchone()
assert rows == (1, 1, 64), rows
PY

python3 - "$certs" "$port" <<'PY'
import hashlib, json, socket, ssl, sys
certs, port = sys.argv[1], int(sys.argv[2])
agent_id = "00000000-0000-4000-8000-000000000001"
def post(event):
    ctx = ssl.create_default_context(cafile=certs + "/ca.crt")
    ctx.load_cert_chain(certs + "/agent.crt", certs + "/agent.key")
    body = json.dumps({"schema_version":"agent_batch.v1", "batch_id":"smoke-batch", "agent_id":agent_id, "events":[event]}, separators=(",", ":"))
    with ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname="127.0.0.1") as sock:
        sock.sendall(("POST /v1/agents/self/events:batch HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " + str(len(body)) + "\r\n\r\n" + body).encode())
        response = b""
        while True:
            try:
                chunk = sock.recv(8192)
            except ConnectionResetError:
                break
            if not chunk: break
            response += chunk
    head, body = response.split(b"\r\n\r\n", 1)
    return head.split(b"\r\n", 1)[0], json.loads(body)

payload = {"source":"test", "worker_count":1}
event = {"event_id":"duplicate-smoke-event", "sequence":99001, "observed_at":"2026-10-10T00:00:00Z", "kind":"health.heartbeat", "coverage":"healthy", "payload":payload, "payload_hash":hashlib.sha256(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()).hexdigest()}
status, first = post(event)
assert status.startswith(b"HTTP/1.1 200 ") and first["accepted_ids"] == [event["event_id"]], first
status, second = post(event)
assert status.startswith(b"HTTP/1.1 200 ") and second["duplicate_ids"] == [event["event_id"]], second
changed = dict(event, payload={"source":"changed"}, payload_hash=hashlib.sha256(b'{"source":"changed"}').hexdigest())
status, rejected = post(changed)
assert status.startswith(b"HTTP/1.1 400 ") and rejected["error"] == "request_rejected", (status, rejected)
PY

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$certs/rogue.key" >/dev/null 2>&1
openssl req -new -key "$certs/rogue.key" -subj "/CN=unauthorized-agent" -out "$certs/rogue.csr"
printf 'extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\n' >"$certs/rogue.ext"
openssl x509 -req -in "$certs/rogue.csr" -CA "$certs/ca.crt" -CAkey "$certs/ca.key" \
    -CAcreateserial -out "$certs/rogue.crt" -days 30 -sha256 -extfile "$certs/rogue.ext" >/dev/null 2>&1
chmod 600 "$certs/rogue.key"
python3 - "$certs" "$port" <<'PY'
import socket, ssl, sys
certs, port = sys.argv[1], int(sys.argv[2])
ctx = ssl.create_default_context(cafile=certs + "/ca.crt")
ctx.load_cert_chain(certs + "/rogue.crt", certs + "/rogue.key")
with ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname="127.0.0.1") as sock:
    sock.sendall(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
    response = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except ConnectionResetError:
            break
        if not chunk: break
        response += chunk
assert not response.startswith(b"HTTP/1.1 200 "), response
PY
python3 - "$tmp/server.sqlite" <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
assert db.execute("select count(*) from events").fetchone()[0] == 2
PY

mkdir "$tmp/allowed-root"
cat >"$tmp/policy.json" <<EOF
{"schema_version":"policy.v1","policy_id":"smoke-policy","revision":1,"issuer":"smoke-issuer","issued_at":"2026-10-10T00:00:00Z","expires_at":"2099-01-01T00:00:00Z","tenant_scope":"smoke-tenant","allowed_actions":["telemetry.configure","monitor.roots.configure"],"settings":{"telemetry_enabled":true,"sample_rate":1,"monitored_roots":["$tmp/allowed-root"]}}
EOF
openssl pkeyutl -sign -rawin -inkey "$certs/policy-signing.key" -in "$tmp/policy.json" -out "$tmp/policy.sig"
"$bin_dir/sw-agentd" validate-policy --store "$tmp/policy-store" --file "$tmp/policy.json" \
    --signature "$tmp/policy.sig" --pubkey "$certs/policy-signing.pub" --tenant smoke-tenant --root "$tmp/allowed-root" >"$tmp/policy-ok.json"
cp "$tmp/policy.json" "$tmp/policy-tampered.json"
printf ' ' >>"$tmp/policy-tampered.json"
set +e
"$bin_dir/sw-agentd" validate-policy --store "$tmp/policy-store" --file "$tmp/policy-tampered.json" \
    --signature "$tmp/policy.sig" --pubkey "$certs/policy-signing.pub" --tenant smoke-tenant --root "$tmp/allowed-root" >"$tmp/policy-bad.out" 2>&1
rc=$?
set -e
[ "$rc" -ne 0 ]
grep -q 'SEA_POLICY_BAD_SIGNATURE' "$tmp/policy-bad.out"
set +e
"$bin_dir/sw-agentd" validate-policy --store "$tmp/policy-store" --file "$tmp/policy.json" \
    --signature "$tmp/policy.sig" --pubkey "$certs/policy-signing.pub" --tenant smoke-tenant --root "$tmp/allowed-root" >"$tmp/policy-replay.out" 2>&1
rc=$?
set -e
[ "$rc" -ne 0 ]
grep -q 'SEA_POLICY_ROLLBACK' "$tmp/policy-replay.out"

kill "$server_pid"
wait "$server_pid" || true
server_pid=
echo "SEA mTLS/queue/dedup/signature smoke: PASS"
