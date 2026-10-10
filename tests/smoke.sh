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
printf '%s\n' 'smoke-admin-token-0123456789-abcdefghijklmnopqrstuvwxyz' >"$tmp/admin-token"
chmod 600 "$tmp/admin-token"
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')

for invalid_handshake_deadline in 99 60001; do
    if "$bin_dir/sw-server" run --handshake-deadline-ms "$invalid_handshake_deadline" \
        >"$tmp/invalid-handshake-deadline-$invalid_handshake_deadline.log" 2>&1; then
        echo "server accepted invalid TLS handshake deadline $invalid_handshake_deadline" >&2
        exit 1
    fi
    grep -q 'TLS handshake deadline must be between 100 and 60000 ms' \
        "$tmp/invalid-handshake-deadline-$invalid_handshake_deadline.log"
done

"$bin_dir/sw-server" run --bind 127.0.0.1 --port "$port" \
    --cert "$certs/server.crt" --key "$certs/server.key" --ca "$certs/ca.crt" \
    --agents "$certs/agents.txt" --operators "$certs/operators.txt" \
    --admin-token-file "$tmp/admin-token" --policy-key "$certs/policy-signing.key" \
    --tenant smoke-tenant --handshake-deadline-ms 1000 --request-deadline-ms 1500 \
    --db "$tmp/server.sqlite" >"$tmp/server.log" 2>&1 &
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

python3 - "$port" <<'PY'
import select, socket, sys, time
port = int(sys.argv[1])
sock = socket.create_connection(("127.0.0.1", port), timeout=1)
sock.settimeout(0.1)
start = time.monotonic()
sock.sendall(b"\x16\x03\x01\x00\x10\x01\x00\x10\x00\x03\x03" + b"\x00" * 10)
closed = False
while time.monotonic() - start < 3.0:
    ready, _, _ = select.select([sock], [], [], 0)
    if ready:
        try:
            if not sock.recv(4096):
                closed = True
                break
        except OSError:
            closed = True
            break
    try:
        sock.sendall(b"\x16\x03\x01\x00\x01\x00")
    except OSError:
        closed = True
        break
    time.sleep(0.04)
elapsed = time.monotonic() - start
sock.close()
assert closed and 0.7 <= elapsed < 2.5, (closed, elapsed)
PY
grep -q 'TLS handshake absolute deadline exceeded' "$tmp/server.log"

python3 - "$certs" "$port" <<'PY'
import select, socket, ssl, sys, time
certs, port = sys.argv[1], int(sys.argv[2])
ctx = ssl.create_default_context(cafile=certs + "/ca.crt")
ctx.load_cert_chain(certs + "/agent.crt", certs + "/agent.key")
with ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname="127.0.0.1") as sock:
    start = time.monotonic()
    response = bytearray()
    sock.sendall(b"G")
    while time.monotonic() - start < 3.0:
        ready, _, _ = select.select([sock], [], [], 0.05)
        if ready:
            try:
                chunk = sock.recv(4096)
            except (OSError, ssl.SSLError):
                break
            if not chunk: break
            response.extend(chunk)
        else:
            try:
                sock.sendall(b"G")
            except (OSError, ssl.SSLError):
                break
    elapsed = time.monotonic() - start
assert not response or response.startswith(b"HTTP/1.1 400 "), response
assert 1.0 <= elapsed < 3.0, elapsed
PY
grep -q 'HTTP request absolute deadline exceeded' "$tmp/server.log"

"$bin_dir/sw-agentd" run --endpoint 127.0.0.1 --port "$port" \
    --agent-id 00000000-0000-4000-8000-000000000001 --tenant smoke-tenant --ca "$certs/ca.crt" \
    --cert "$certs/agent.crt" --key "$certs/agent.key" --store "$tmp/no-policy-store"
"$bin_dir/sw-agentd" status --store "$tmp/no-policy-store" >"$tmp/no-policy-status.json"
python3 - "$tmp/no-policy-status.json" <<'PY'
import json, sys
status = json.load(open(sys.argv[1], encoding="utf-8"))
assert status["policy_status"] == "NO_POLICY" and not status["telemetry_enabled"] and status["queued"] == 0, status
PY
cat >"$tmp/no-policy-event.json" <<'EOF'
{"schema_version":"event.v1","event_id":"a66f9893-76b8-40de-9322-8a84c3d32476","source":"fim","observed_at":"2026-10-10T00:00:01Z","kind":"file.modified","target":{"path":"/tmp/not-imported.txt"},"actor":{"pid":null,"start_time_ticks":null,"attribution":"unknown"},"coverage":{"state":"healthy","reason":null}}
EOF
if "$bin_dir/sw-agentd" import-event --file "$tmp/no-policy-event.json" --tenant smoke-tenant --store "$tmp/no-policy-store" >"$tmp/no-policy-import.out" 2>&1; then
    echo "event.v1 import succeeded without active policy" >&2
    exit 1
fi
grep -q 'SEA_POLICY_INACTIVE: event import is disabled' "$tmp/no-policy-import.out"

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

def raw_status(request):
    ctx = ssl.create_default_context(cafile=certs + "/ca.crt")
    ctx.load_cert_chain(certs + "/agent.crt", certs + "/agent.key")
    raw = socket.create_connection(("127.0.0.1", port), timeout=8)
    raw.settimeout(8)
    with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as sock:
        sock.sendall(request)
        response = b""
        while b"\r\n\r\n" not in response:
            try:
                chunk = sock.recv(4096)
            except (ConnectionResetError, ssl.SSLError):
                break
            if not chunk:
                break
            response += chunk
    assert b"\r\n\r\n" in response, response
    return response.split(b"\r\n", 1)[0]

def expect_400(request):
    status = raw_status(request)
    assert status.startswith(b"HTTP/1.1 400 "), status

payload = {"source":"test", "worker_count":1}
event = {"event_id":"duplicate-smoke-event", "sequence":99001, "observed_at":"2026-10-10T00:00:00Z", "kind":"health.heartbeat", "coverage":"healthy", "payload":payload, "payload_hash":hashlib.sha256(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()).hexdigest()}
status, first = post(event)
assert status.startswith(b"HTTP/1.1 200 ") and first["accepted_ids"] == [event["event_id"]], first
status, second = post(event)
assert status.startswith(b"HTTP/1.1 200 ") and second["duplicate_ids"] == [event["event_id"]], second
changed = dict(event, payload={"source":"changed"}, payload_hash=hashlib.sha256(b'{"source":"changed"}').hexdigest())
status, rejected = post(changed)
assert status.startswith(b"HTTP/1.1 400 ") and rejected["error"] == "request_rejected", (status, rejected)

prefix = b"POST /v1/agents/self/events:batch HTTP/1.1\r\nHost: 127.0.0.1\r\n"
expect_400(prefix + b"Content-Length: 0\r\nContent-Length: 0\r\n\r\n")
expect_400(prefix + b"Transfer-Encoding: chunked\r\n\r\n")
expect_400(prefix + b"Content-Length: +1\r\n\r\n")
expect_400(prefix + b"Content-Length: 1048577\r\n\r\n")
expect_400(prefix + b"\r\n")
expect_400(b"GET /healthz HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
expect_400(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1\r\n\r\nx")
expect_400(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nHost: localhost\r\n\r\n")
expect_400(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Pad: " + b"a" * 17000 + b"\r\n\r\n")
expect_400(prefix + b"Content-Length: 1\r\n\r\n")
mime_payload = {"source":"mime-test", "worker_count":1}
mime_event = {"event_id":"content-type-smoke-event", "sequence":99002, "observed_at":"2026-10-10T00:00:00Z", "kind":"health.heartbeat", "coverage":"healthy", "payload":mime_payload, "payload_hash":hashlib.sha256(json.dumps(mime_payload, separators=(",", ":"), sort_keys=True).encode()).hexdigest()}
mime_body = json.dumps({"schema_version":"agent_batch.v1", "batch_id":"mime-smoke-batch", "agent_id":agent_id, "events":[mime_event]}, separators=(",", ":")).encode()
framed_body = b"Content-Length: " + str(len(mime_body)).encode() + b"\r\n\r\n" + mime_body
expect_400(prefix + framed_body)
expect_400(prefix + b"Content-Type: text/plain\r\n" + framed_body)
expect_400(prefix + b"Content-Type: application/json\r\nContent-Type: application/json\r\n" + framed_body)
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
assert db.execute("select count(*) from events").fetchone()[0] == 1
PY

mkdir "$tmp/allowed-root"
cat >"$tmp/policy.json" <<EOF
{"schema_version":"policy.v1","policy_id":"smoke-policy","revision":1,"issuer":"smoke-issuer","issued_at":"2026-10-10T00:00:00Z","expires_at":"2099-01-01T00:00:00Z","tenant_scope":"smoke-tenant","allowed_actions":["telemetry.configure","monitor.roots.configure"],"settings":{"telemetry_enabled":true,"sample_rate":1,"monitored_roots":["$tmp/allowed-root"]}}
EOF
openssl pkeyutl -sign -rawin -inkey "$certs/policy-signing.key" -in "$tmp/policy.json" -out "$tmp/policy.sig"
"$bin_dir/sw-agentd" validate-policy --store "$tmp/policy-store" --file "$tmp/policy.json" \
    --signature "$tmp/policy.sig" --pubkey "$certs/policy-signing.pub" --tenant smoke-tenant --root "$tmp/allowed-root" >"$tmp/policy-ok.json"

python3 - "$certs" "$port" "$tmp/admin-token" "$tmp/policy.json" <<'PY'
import hashlib, json, socket, ssl, sys
certs, port, token_file, policy_file = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
token = open(token_file, encoding="utf-8").read().strip()
document = open(policy_file, "rb").read()
def request(identity, method, path, body=b"", authorization=None, if_none_match=None):
    ctx = ssl.create_default_context(cafile=certs + "/ca.crt")
    ctx.load_cert_chain(certs + "/" + identity + ".crt", certs + "/" + identity + ".key")
    headers = ["Host: 127.0.0.1", "Connection: close"]
    if body:
        headers.extend(["Content-Type: application/json", "Content-Length: " + str(len(body))])
    if authorization:
        headers.append("Authorization: " + authorization)
    if if_none_match:
        headers.append("If-None-Match: " + if_none_match)
    raw = (method + " " + path + " HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n").encode() + body
    with ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname="127.0.0.1") as sock:
        sock.sendall(raw)
        response = b""
        while True:
            chunk = sock.recv(8192)
            if not chunk: break
            response += chunk
    head, body = response.split(b"\r\n\r\n", 1)
    status = int(head.split(b"\r\n", 1)[0].split()[1])
    return status, body
assert request("operator", "POST", "/v1/admin/policies", document)[0] == 403
assert request("agent", "POST", "/v1/admin/policies", document, "Bearer " + token)[0] == 403
status, body = request("operator", "POST", "/v1/admin/policies", document, "Bearer " + token)
assert status == 201, (status, body)
status, body = request("operator", "POST", "/v1/admin/policies", document, "Bearer " + token)
assert status == 200, (status, body)
status, body = request("agent", "GET", "/v1/agents/self/policy")
envelope = json.loads(body)
assert status == 200 and envelope["schema_version"] == "policy_envelope.v1"
assert envelope["policy_document"].encode() == document
assert len(envelope["signature_hex"]) == 128
etag = '"' + hashlib.sha256(document).hexdigest() + '"'
status, body = request("agent", "GET", "/v1/agents/self/policy", if_none_match=etag)
assert status == 304 and body == b"", (status, body)
PY

sync_policy() {
    store_path=$1
    "$bin_dir/sw-agentd" sync-policy --endpoint 127.0.0.1 --port "$port" \
        --agent-id 00000000-0000-4000-8000-000000000001 --ca "$certs/ca.crt" \
        --cert "$certs/agent.crt" --key "$certs/agent.key" --store "$store_path" \
        --pubkey "$certs/policy-signing.pub" --tenant smoke-tenant --root "$tmp/allowed-root"
}
publish_policy_update() {
    revision=$1
    telemetry_enabled=$2
    sample_rate=$3
    policy_file="$tmp/policy-runtime-$revision.json"
    signature_file="$tmp/policy-runtime-$revision.sig"
    python3 - "$tmp/policy.json" "$policy_file" "$revision" "$telemetry_enabled" "$sample_rate" <<'PY'
import json, sys
policy = json.load(open(sys.argv[1], encoding="utf-8"))
policy["revision"] = int(sys.argv[3])
policy["policy_id"] = "smoke-policy-runtime-" + sys.argv[3]
policy["settings"]["telemetry_enabled"] = sys.argv[4] == "true"
policy["settings"]["sample_rate"] = float(sys.argv[5])
with open(sys.argv[2], "w", encoding="utf-8") as stream:
    json.dump(policy, stream, separators=(",", ":"))
PY
    openssl pkeyutl -sign -rawin -inkey "$certs/policy-signing.key" -in "$policy_file" -out "$signature_file"
    python3 - "$certs" "$port" "$tmp/admin-token" "$policy_file" <<'PY'
import socket, ssl, sys
certs, port, token_file, policy_file = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
body = open(policy_file, "rb").read()
token = open(token_file, encoding="utf-8").read().strip()
ctx = ssl.create_default_context(cafile=certs + "/ca.crt")
ctx.load_cert_chain(certs + "/operator.crt", certs + "/operator.key")
headers = ("Host: 127.0.0.1\r\nContent-Type: application/json\r\nAuthorization: Bearer " + token +
    "\r\nContent-Length: " + str(len(body)) + "\r\nConnection: close\r\n\r\n").encode()
with ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname="127.0.0.1") as sock:
    sock.sendall(b"POST /v1/admin/policies HTTP/1.1\r\n" + headers + body)
    response = b""
    while True:
        chunk = sock.recv(8192)
        if not chunk: break
        response += chunk
assert response.startswith(b"HTTP/1.1 201 "), response
PY
}
sync_policy "$tmp/policy-sync-store" >"$tmp/policy-sync-first.json"
sync_policy "$tmp/policy-sync-store" >"$tmp/policy-sync-unchanged.json"
python3 - "$tmp/policy-sync-store/spool.sqlite" "$tmp/policy-sync-first.json" "$tmp/policy-sync-unchanged.json" <<'PY'
import json, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
row = db.execute("select revision, document from policy_state where issuer='smoke-issuer'").fetchone()
assert row is not None and row[0] == 1
assert db.execute("select count(*) from policy_audit").fetchone()[0] == 1
assert json.load(open(sys.argv[2], encoding="utf-8"))["policy_status"] == "stored_last_good"
assert json.load(open(sys.argv[3], encoding="utf-8"))["policy_status"] == "unchanged"
PY

sync_policy "$tmp/agent-store" >"$tmp/agent-policy-sync.json"
set +e
"$bin_dir/sw-agentd" run --endpoint 127.0.0.1 --port "$port" \
    --agent-id 00000000-0000-4000-8000-000000000001 --tenant other-tenant --ca "$certs/ca.crt" \
    --cert "$certs/agent.crt" --key "$certs/agent.key" --store "$tmp/agent-store" \
    >"$tmp/agent-wrong-tenant.log" 2>&1
rc=$?
set -e
[ "$rc" -eq 2 ]
grep -q 'stored policy tenant mismatch' "$tmp/agent-wrong-tenant.log"
"$bin_dir/sw-agentd" run --endpoint 127.0.0.1 --port "$port" \
    --agent-id 00000000-0000-4000-8000-000000000001 --tenant smoke-tenant --ca "$certs/ca.crt" \
    --cert "$certs/agent.crt" --key "$certs/agent.key" --store "$tmp/agent-store"
"$bin_dir/sw-agentd" status --store "$tmp/agent-store" >"$tmp/agent-status.json"
python3 - "$tmp/agent-status.json" "$tmp/server.sqlite" <<'PY'
import json, sqlite3, sys
status = json.load(open(sys.argv[1], encoding="utf-8"))
assert status["queued"] == 0 and status["policy_status"] == "ACTIVE", status
assert status["policy_revision"] == 1 and status["sample_rate"] == 1 and status["monitored_root_count"] == 1, status
db = sqlite3.connect(sys.argv[2])
rows = db.execute("select count(*), min(sequence), min(length(payload_hash)) from events").fetchone()
assert rows == (2, 1, 64), rows
PY

python3 - "$tmp/policy.json" "$tmp/policy-invalid-root.json" "$tmp/outside-root" <<'PY'
import json, sys
policy = json.load(open(sys.argv[1], encoding="utf-8"))
policy["policy_id"] = "smoke-policy-invalid-root"
policy["revision"] = 2
policy["settings"]["monitored_roots"] = [sys.argv[3]]
open(sys.argv[2], "w", encoding="utf-8").write(json.dumps(policy, separators=(",", ":")))
PY
openssl pkeyutl -sign -rawin -inkey "$certs/policy-signing.key" -in "$tmp/policy-invalid-root.json" -out "$tmp/policy-invalid-root.sig"
python3 - "$certs" "$port" "$tmp/admin-token" "$tmp/policy-invalid-root.json" <<'PY'
import socket, ssl, sys
certs, port, token_file, policy_file = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
body = open(policy_file, "rb").read()
token = open(token_file, encoding="utf-8").read().strip()
ctx = ssl.create_default_context(cafile=certs + "/ca.crt")
ctx.load_cert_chain(certs + "/operator.crt", certs + "/operator.key")
headers = ("Host: 127.0.0.1\r\nContent-Type: application/json\r\nAuthorization: Bearer " + token +
    "\r\nContent-Length: " + str(len(body)) + "\r\nConnection: close\r\n\r\n").encode()
with ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname="127.0.0.1") as sock:
    sock.sendall(b"POST /v1/admin/policies HTTP/1.1\r\n" + headers + body)
    response = b""
    while True:
        chunk = sock.recv(8192)
        if not chunk: break
        response += chunk
assert response.startswith(b"HTTP/1.1 201 "), response
PY
set +e
sync_policy "$tmp/policy-sync-store" >"$tmp/policy-sync-rejected.json" 2>"$tmp/policy-sync-rejected.err"
rc=$?
set -e
[ "$rc" -ne 0 ]
grep -q 'policy root outside configured allowlist' "$tmp/policy-sync-rejected.err"
python3 - "$tmp/policy-sync-store/spool.sqlite" <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
assert db.execute("select revision from policy_state where issuer='smoke-issuer'").fetchone()[0] == 1
assert db.execute("select count(*) from policy_audit").fetchone()[0] == 1
PY
python3 - "$tmp/policy.json" "$tmp/policy-valid-revision-3.json" <<'PY'
import json, sys
policy = json.load(open(sys.argv[1], encoding="utf-8"))
policy["policy_id"] = "smoke-policy-revision-3"
policy["revision"] = 3
open(sys.argv[2], "w", encoding="utf-8").write(json.dumps(policy, separators=(",", ":")))
PY
openssl pkeyutl -sign -rawin -inkey "$certs/policy-signing.key" -in "$tmp/policy-valid-revision-3.json" -out "$tmp/policy-valid-revision-3.sig"
python3 - "$certs" "$port" "$tmp/admin-token" "$tmp/policy-valid-revision-3.json" <<'PY'
import socket, ssl, sys
certs, port, token_file, policy_file = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
body = open(policy_file, "rb").read()
token = open(token_file, encoding="utf-8").read().strip()
ctx = ssl.create_default_context(cafile=certs + "/ca.crt")
ctx.load_cert_chain(certs + "/operator.crt", certs + "/operator.key")
headers = ("Host: 127.0.0.1\r\nContent-Type: application/json\r\nAuthorization: Bearer " + token +
    "\r\nContent-Length: " + str(len(body)) + "\r\nConnection: close\r\n\r\n").encode()
with ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname="127.0.0.1") as sock:
    sock.sendall(b"POST /v1/admin/policies HTTP/1.1\r\n" + headers + body)
    response = b""
    while True:
        chunk = sock.recv(8192)
        if not chunk: break
        response += chunk
assert response.startswith(b"HTTP/1.1 201 "), response
PY
sync_policy "$tmp/policy-sync-store" >"$tmp/policy-sync-recovered.json"
python3 - "$tmp/policy-sync-store/spool.sqlite" <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
assert db.execute("select revision from policy_state where issuer='smoke-issuer'").fetchone()[0] == 3
assert db.execute("select count(*) from policy_audit").fetchone()[0] == 2
PY

publish_policy_update 4 false 1
sync_policy "$tmp/agent-store" >"$tmp/agent-policy-disabled.json"
python3 - "$tmp/agent-store/spool.sqlite" <<'PY'
import hashlib, json, sqlite3, sys
payload = {"source":"runtime-retention-test", "worker_count":1}
payload_text = json.dumps(payload, separators=(",", ":"), sort_keys=True)
event = {"event_id":"runtime-retained-event", "sequence":2, "observed_at":"2026-10-10T00:00:01Z",
    "kind":"health.heartbeat", "coverage":"healthy", "payload":payload,
    "payload_hash":hashlib.sha256(payload_text.encode()).hexdigest()}
db = sqlite3.connect(sys.argv[1])
db.execute("insert into queue(event_id,sequence,observed_at,payload,payload_hash) values(?,?,?,?,?)",
    (event["event_id"], event["sequence"], event["observed_at"], json.dumps(event, separators=(",", ":")), event["payload_hash"]))
db.execute("update meta set value='2' where key='next_sequence'")
db.commit()
PY
"$bin_dir/sw-agentd" run --endpoint 127.0.0.1 --port "$port" \
    --agent-id 00000000-0000-4000-8000-000000000001 --tenant smoke-tenant --ca "$certs/ca.crt" \
    --cert "$certs/agent.crt" --key "$certs/agent.key" --store "$tmp/agent-store"
"$bin_dir/sw-agentd" status --store "$tmp/agent-store" >"$tmp/agent-disabled-status.json"
python3 - "$tmp/agent-disabled-status.json" "$tmp/server.sqlite" <<'PY'
import json, sqlite3, sys
status = json.load(open(sys.argv[1], encoding="utf-8"))
assert status["policy_status"] == "VALIDATED" and not status["telemetry_enabled"] and status["queued"] == 1, status
db = sqlite3.connect(sys.argv[2])
assert db.execute("select count(*) from events").fetchone()[0] == 2
PY

publish_policy_update 5 true 0
sync_policy "$tmp/agent-store" >"$tmp/agent-policy-sampled-out.json"
cat >"$tmp/sampled-out-event.json" <<EOF
{"schema_version":"event.v1","event_id":"d6a70c30-d41e-4cc4-8a61-8e93d75e01a1","source":"fim","observed_at":"2026-10-10T00:00:02Z","kind":"file.modified","target":{"path":"$tmp/allowed-root/sampled.txt"},"actor":{"pid":null,"start_time_ticks":null,"attribution":"unknown"},"coverage":{"state":"healthy","reason":null}}
EOF
"$bin_dir/sw-agentd" import-event --file "$tmp/sampled-out-event.json" --tenant smoke-tenant --store "$tmp/agent-store" >"$tmp/import-sampled-out.json"
python3 - "$tmp/import-sampled-out.json" "$tmp/agent-store/spool.sqlite" <<'PY'
import json, sqlite3, sys
assert json.load(open(sys.argv[1], encoding="utf-8"))["status"] == "sampled_out"
db = sqlite3.connect(sys.argv[2])
counts = (db.execute("select count(*) from queue").fetchone()[0],
          db.execute("select count(*) from imported_events").fetchone()[0])
assert counts == (1, 0), counts
PY
"$bin_dir/sw-agentd" run --endpoint 127.0.0.1 --port "$port" \
    --agent-id 00000000-0000-4000-8000-000000000001 --tenant smoke-tenant --ca "$certs/ca.crt" \
    --cert "$certs/agent.crt" --key "$certs/agent.key" --store "$tmp/agent-store"
"$bin_dir/sw-agentd" status --store "$tmp/agent-store" >"$tmp/agent-sampled-status.json"
python3 - "$tmp/agent-sampled-status.json" "$tmp/server.sqlite" <<'PY'
import json, sqlite3, sys
status = json.load(open(sys.argv[1], encoding="utf-8"))
assert status["policy_status"] == "ACTIVE" and status["telemetry_enabled"] and status["sample_rate"] == 0 and status["queued"] == 0, status
db = sqlite3.connect(sys.argv[2])
assert db.execute("select count(*) from events").fetchone()[0] == 3
PY

publish_policy_update 6 true 1
sync_policy "$tmp/agent-store" >"$tmp/agent-policy-import-enabled.json"

mkdir "$tmp/allowed-root/nested" "$tmp/outside-root"
ln -s "$tmp/outside-root" "$tmp/allowed-root/external-link"
printf 'private-file-content-marker\n' >"$tmp/allowed-root/nested/example.txt"
cat >"$tmp/event-v1.json" <<EOF
{"schema_version":"event.v1","event_id":"c7e9b53b-4644-42e3-9ccc-1fb8bcf76a65","source":"fim","host_id":"local-demo-id","observed_at":"2026-10-10T00:00:03Z","kind":"file.modified","severity":"info","target":{"path":"$tmp/allowed-root/nested/example.txt","device":2049,"inode":18201},"actor":{"pid":null,"start_time_ticks":null,"attribution":"unknown"},"evidence":{"source_event":"IN_CLOSE_WRITE"},"coverage":{"state":"healthy","reason":null}}
EOF
"$bin_dir/sw-agentd" import-event --file "$tmp/event-v1.json" --tenant smoke-tenant --store "$tmp/agent-store" >"$tmp/import-event.json"
python3 - "$tmp/import-event.json" "$tmp/agent-store/spool.sqlite" "$tmp/allowed-root/nested/example.txt" <<'PY'
import json, sqlite3, sys
result = json.load(open(sys.argv[1], encoding="utf-8"))
assert result["status"] == "queued" and result["event_id"] == "c7e9b53b-4644-42e3-9ccc-1fb8bcf76a65", result
db = sqlite3.connect(sys.argv[2])
row = db.execute("select payload from queue where event_id=?", (result["event_id"],)).fetchone()
assert row, "imported event missing from queue"
stored = row[0]
assert sys.argv[3] not in stored and '"path"' not in stored and "hmac-sha256:" in stored, stored
assert "private-file-content-marker" not in stored
envelope = json.loads(stored)
assert envelope["kind"] == "file.modified" and envelope["coverage"] == "healthy"
assert envelope["payload"]["source"] == "fim"
assert envelope["payload"]["target"]["path_id"].startswith("hmac-sha256:")
assert db.execute("select count(*) from imported_events").fetchone()[0] == 1
PY
"$bin_dir/sw-agentd" import-event --file "$tmp/event-v1.json" --tenant smoke-tenant --store "$tmp/agent-store" >"$tmp/import-event-repeat.json"
python3 - "$tmp/import-event-repeat.json" "$tmp/agent-store/spool.sqlite" <<'PY'
import json, sqlite3, sys
assert json.load(open(sys.argv[1], encoding="utf-8"))["status"] == "already_seen"
db = sqlite3.connect(sys.argv[2])
assert db.execute("select count(*) from queue").fetchone()[0] == 1
PY
cat >"$tmp/coverage-event.json" <<'EOF'
{"schema_version":"event.v1","event_id":"55f4d29c-fb4b-4fd7-b74f-0db8317ed7af","source":"fim","observed_at":"2026-10-10T00:00:04Z","kind":"coverage.degraded","severity":"warning","target":{},"actor":{"pid":null,"start_time_ticks":null,"attribution":"unknown"},"coverage":{"state":"degraded","reason":"watcher_restarting"}}
EOF
"$bin_dir/sw-agentd" import-event --file "$tmp/coverage-event.json" --tenant smoke-tenant --store "$tmp/agent-store" >"$tmp/import-coverage-event.json"
python3 - "$tmp/import-coverage-event.json" "$tmp/agent-store/spool.sqlite" <<'PY'
import json, sqlite3, sys
assert json.load(open(sys.argv[1], encoding="utf-8"))["status"] == "queued"
db = sqlite3.connect(sys.argv[2])
row = db.execute("select payload from queue where event_id=?", ("55f4d29c-fb4b-4fd7-b74f-0db8317ed7af",)).fetchone()
assert row and json.loads(row[0])["payload"]["target"]["path_id"] is None
assert db.execute("select count(*) from imported_events").fetchone()[0] == 2
PY
python3 - "$tmp/event-v1.json" "$tmp/out-of-scope-event.json" "$tmp/sensitive-event.json" "$tmp/allowed-root/external-link/outside.txt" <<'PY'
import json, sys
event = json.load(open(sys.argv[1], encoding="utf-8"))
outside = dict(event)
outside["event_id"] = "cd7eeb36-d596-4cd8-a2df-e50b2b0ee962"
outside["target"] = dict(event["target"], path=sys.argv[4])
json.dump(outside, open(sys.argv[2], "w", encoding="utf-8"), separators=(",", ":"))
sensitive = dict(event)
sensitive["event_id"] = "f2bc8527-7972-4c30-a86b-228e998ad8e5"
sensitive["content"] = "must not enter telemetry"
json.dump(sensitive, open(sys.argv[3], "w", encoding="utf-8"), separators=(",", ":"))
PY
if "$bin_dir/sw-agentd" import-event --file "$tmp/out-of-scope-event.json" --tenant smoke-tenant --store "$tmp/agent-store" >"$tmp/import-out-of-scope.out" 2>&1; then
    echo "event outside monitored roots was imported" >&2
    exit 1
fi
grep -q 'event target outside active monitored roots' "$tmp/import-out-of-scope.out"
python3 - "$tmp/event-v1.json" "$tmp/pathless-healthy-event.json" <<'PY'
import json, sys
event = json.load(open(sys.argv[1], encoding="utf-8"))
event["event_id"] = "6d435b39-64cf-4467-988d-a04a25bba5fb"
event["kind"] = "file.modified"
event["target"] = {}
json.dump(event, open(sys.argv[2], "w", encoding="utf-8"), separators=(",", ":"))
PY
if "$bin_dir/sw-agentd" import-event --file "$tmp/pathless-healthy-event.json" --tenant smoke-tenant --store "$tmp/agent-store" >"$tmp/import-pathless-healthy.out" 2>&1; then
    echo "healthy event without a scoped target path was imported" >&2
    exit 1
fi
grep -q 'event target path is required outside non-healthy coverage events' "$tmp/import-pathless-healthy.out"
if "$bin_dir/sw-agentd" import-event --file "$tmp/sensitive-event.json" --tenant smoke-tenant --store "$tmp/agent-store" >"$tmp/import-sensitive.out" 2>&1; then
    echo "event with unapproved content field was imported" >&2
    exit 1
fi
grep -q 'event field rejected: content' "$tmp/import-sensitive.out"
python3 - "$tmp/agent-store/spool.sqlite" <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
assert db.execute("select count(*) from imported_events").fetchone()[0] == 2
assert db.execute("select count(*) from queue").fetchone()[0] == 2
PY
"$bin_dir/sw-agentd" flush --endpoint 127.0.0.1 --port "$port" \
    --agent-id 00000000-0000-4000-8000-000000000001 --tenant smoke-tenant --ca "$certs/ca.crt" \
    --cert "$certs/agent.crt" --key "$certs/agent.key" --store "$tmp/agent-store" >"$tmp/import-flush.out"
python3 - "$tmp/agent-store/spool.sqlite" "$tmp/server.sqlite" <<'PY'
import sqlite3, sys
agent = sqlite3.connect(sys.argv[1])
assert agent.execute("select count(*) from queue").fetchone()[0] == 0
server = sqlite3.connect(sys.argv[2])
assert server.execute("select count(*) from events").fetchone()[0] == 5
PY

expect_policy_rejected() {
    label=$1
    monitored_root=$2
    expiry=$3
    revision=$4
    expected=$5
    store=${6:-"$tmp/policy-store-$label"}
    policy_file="$tmp/policy-$label.json"
    signature_file="$tmp/policy-$label.sig"
    cat >"$policy_file" <<EOF
{"schema_version":"policy.v1","policy_id":"smoke-policy-$label","revision":$revision,"issuer":"smoke-issuer","issued_at":"2026-10-10T00:00:00Z","expires_at":"$expiry","tenant_scope":"smoke-tenant","allowed_actions":["telemetry.configure","monitor.roots.configure"],"settings":{"telemetry_enabled":true,"sample_rate":1,"monitored_roots":["$monitored_root"]}}
EOF
    openssl pkeyutl -sign -rawin -inkey "$certs/policy-signing.key" -in "$policy_file" -out "$signature_file"
    if "$bin_dir/sw-agentd" validate-policy --store "$store" --file "$policy_file" \
        --signature "$signature_file" --pubkey "$certs/policy-signing.pub" --tenant smoke-tenant \
        --root "$tmp/allowed-root" >"$tmp/policy-$label.out" 2>&1; then
        echo "policy validation unexpectedly accepted $label" >&2
        exit 1
    fi
    grep -q "$expected" "$tmp/policy-$label.out"
}
expect_policy_rejected traversal "$tmp/allowed-root/../outside-root" 2099-01-01T00:00:00Z 1 \
    'policy root outside configured allowlist'
expect_policy_rejected symlink "$tmp/allowed-root/external-link" 2099-01-01T00:00:00Z 1 \
    'policy root outside configured allowlist'
expect_policy_rejected invalid-date "$tmp/allowed-root/nested" 2099-02-30T00:00:00Z 1 \
    'policy expires_at invalid'
expect_policy_rejected negative-revision "$tmp/allowed-root" 2099-01-01T00:00:00Z -1 \
    SEA_POLICY_REVISION_INVALID "$tmp/policy-store"
expect_policy_rejected fractional-revision "$tmp/allowed-root" 2099-01-01T00:00:00Z 1.5 \
    SEA_POLICY_REVISION_INVALID
expect_policy_rejected unsafe-revision "$tmp/allowed-root" 2099-01-01T00:00:00Z 9007199254740992 \
    SEA_POLICY_REVISION_INVALID
python3 - "$tmp/policy.json" "$tmp/policy-unauthorized-action.json" <<'PY'
import json, sys
policy = json.load(open(sys.argv[1], encoding="utf-8"))
policy["allowed_actions"] = ["monitor.roots.configure"]
open(sys.argv[2], "w", encoding="utf-8").write(json.dumps(policy, separators=(",", ":")))
PY
openssl pkeyutl -sign -rawin -inkey "$certs/policy-signing.key" -in "$tmp/policy-unauthorized-action.json" \
    -out "$tmp/policy-unauthorized-action.sig"
if "$bin_dir/sw-agentd" validate-policy --store "$tmp/policy-store-unauthorized-action" \
    --file "$tmp/policy-unauthorized-action.json" --signature "$tmp/policy-unauthorized-action.sig" \
    --pubkey "$certs/policy-signing.pub" --tenant smoke-tenant --root "$tmp/allowed-root" \
    >"$tmp/policy-unauthorized-action.out" 2>&1; then
    echo "policy with unauthorized telemetry setting was accepted" >&2
    exit 1
fi
grep -q 'requires telemetry.configure' "$tmp/policy-unauthorized-action.out" || {
    cat "$tmp/policy-unauthorized-action.out" >&2
    exit 1
}
python3 - "$tmp/policy-store/spool.sqlite" "$tmp/policy.json" <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
row = db.execute("select revision, document from policy_state where issuer='smoke-issuer'").fetchone()
assert row is not None and row[0] == 1
with open(sys.argv[2], "rb") as policy:
    assert row[1] == policy.read()
PY

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

# A non-success HTTP status must never be interpreted as an event acknowledgement.
sync_policy "$tmp/conflict-agent-store" >/dev/null
"$bin_dir/sw-agentd" status --store "$tmp/conflict-agent-store" >/dev/null
python3 - "$tmp/conflict-agent-store/spool.sqlite" <<'PY'
import hashlib, json, sqlite3, sys
payload = {"source":"conflict-test", "worker_count":1}
payload_text = json.dumps(payload, separators=(",", ":"), sort_keys=True)
event = {"event_id":"duplicate-smoke-event", "sequence":99002, "observed_at":"2026-10-10T00:00:01Z", "kind":"health.heartbeat", "coverage":"healthy", "payload":payload, "payload_hash":hashlib.sha256(payload_text.encode()).hexdigest()}
db = sqlite3.connect(sys.argv[1])
db.execute("insert into queue(event_id,sequence,observed_at,payload,payload_hash) values(?,?,?,?,?)", (event["event_id"], event["sequence"], event["observed_at"], json.dumps(event, separators=(",", ":")), event["payload_hash"]))
db.commit()
PY
set +e
"$bin_dir/sw-agentd" flush --endpoint 127.0.0.1 --port "$port" \
    --agent-id 00000000-0000-4000-8000-000000000001 --tenant smoke-tenant --ca "$certs/ca.crt" \
    --cert "$certs/agent.crt" --key "$certs/agent.key" --store "$tmp/conflict-agent-store" \
    >"$tmp/conflict-agent.log" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'SEA_HTTP_STATUS: expected 200, received 400' "$tmp/conflict-agent.log"
"$bin_dir/sw-agentd" status --store "$tmp/conflict-agent-store" >"$tmp/conflict-status.json"
python3 - "$tmp/conflict-status.json" <<'PY'
import json, sys
status = json.load(open(sys.argv[1], encoding="utf-8"))
assert status["queued"] == 1, status
PY

# Keep an event durable while the server is offline, then deliver it after restart.
sync_policy "$tmp/offline-agent-store" >/dev/null
kill "$server_pid"
wait "$server_pid" || true
server_pid=
set +e
"$bin_dir/sw-agentd" run --endpoint 127.0.0.1 --port "$port" \
    --agent-id 00000000-0000-4000-8000-000000000001 --tenant smoke-tenant --ca "$certs/ca.crt" \
    --cert "$certs/agent.crt" --key "$certs/agent.key" --store "$tmp/offline-agent-store" \
    >"$tmp/offline-agent.log" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'queue retained:' "$tmp/offline-agent.log"
"$bin_dir/sw-agentd" status --store "$tmp/offline-agent-store" >"$tmp/offline-before-restart.json"
python3 - "$tmp/offline-before-restart.json" <<'PY'
import json, sys
status = json.load(open(sys.argv[1], encoding="utf-8"))
assert status["queued"] == 1, status
PY

"$bin_dir/sw-server" run --bind 127.0.0.1 --port "$port" \
    --cert "$certs/server.crt" --key "$certs/server.key" --ca "$certs/ca.crt" \
    --agents "$certs/agents.txt" --operators "$certs/operators.txt" \
    --admin-token-file "$tmp/admin-token" --policy-key "$certs/policy-signing.key" \
    --tenant smoke-tenant --request-deadline-ms 1500 --db "$tmp/server.sqlite" >"$tmp/server-restart.log" 2>&1 &
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
    raise SystemExit("restarted mTLS server did not become ready: " + str(last))
PY
"$bin_dir/sw-agentd" flush --endpoint 127.0.0.1 --port "$port" \
    --agent-id 00000000-0000-4000-8000-000000000001 --tenant smoke-tenant --ca "$certs/ca.crt" \
    --cert "$certs/agent.crt" --key "$certs/agent.key" --store "$tmp/offline-agent-store"
"$bin_dir/sw-agentd" status --store "$tmp/offline-agent-store" >"$tmp/offline-after-restart.json"
python3 - "$tmp/offline-after-restart.json" "$tmp/server.sqlite" <<'PY'
import json, sqlite3, sys
status = json.load(open(sys.argv[1], encoding="utf-8"))
assert status["queued"] == 0, status
db = sqlite3.connect(sys.argv[2])
assert db.execute("select count(*) from events").fetchone()[0] == 6
PY

kill "$server_pid"
wait "$server_pid" || true
server_pid=
echo "SEA mTLS/queue/restart/dedup/signature/HTTP framing smoke: PASS"
