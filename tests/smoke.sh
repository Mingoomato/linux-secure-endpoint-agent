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

"$bin_dir/sw-server" run --bind 127.0.0.1 --port "$port" \
    --cert "$certs/server.crt" --key "$certs/server.key" --ca "$certs/ca.crt" \
    --agents "$certs/agents.txt" --operators "$certs/operators.txt" \
    --admin-token-file "$tmp/admin-token" --policy-key "$certs/policy-signing.key" \
    --tenant smoke-tenant --db "$tmp/server.sqlite" >"$tmp/server.log" 2>&1 &
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
assert db.execute("select count(*) from events").fetchone()[0] == 2
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
    "$bin_dir/sw-agentd" sync-policy --endpoint 127.0.0.1 --port "$port" \
        --agent-id 00000000-0000-4000-8000-000000000001 --ca "$certs/ca.crt" \
        --cert "$certs/agent.crt" --key "$certs/agent.key" --store "$tmp/policy-sync-store" \
        --pubkey "$certs/policy-signing.pub" --tenant smoke-tenant --root "$tmp/allowed-root"
}
sync_policy >"$tmp/policy-sync-first.json"
sync_policy >"$tmp/policy-sync-unchanged.json"
python3 - "$tmp/policy-sync-store/spool.sqlite" "$tmp/policy-sync-first.json" "$tmp/policy-sync-unchanged.json" <<'PY'
import json, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
row = db.execute("select revision, document from policy_state where issuer='smoke-issuer'").fetchone()
assert row is not None and row[0] == 1
assert db.execute("select count(*) from policy_audit").fetchone()[0] == 1
assert json.load(open(sys.argv[2], encoding="utf-8"))["policy_status"] == "stored_last_good"
assert json.load(open(sys.argv[3], encoding="utf-8"))["policy_status"] == "unchanged"
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
sync_policy >"$tmp/policy-sync-rejected.json" 2>"$tmp/policy-sync-rejected.err"
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
sync_policy >"$tmp/policy-sync-recovered.json"
python3 - "$tmp/policy-sync-store/spool.sqlite" <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
assert db.execute("select revision from policy_state where issuer='smoke-issuer'").fetchone()[0] == 3
assert db.execute("select count(*) from policy_audit").fetchone()[0] == 2
PY

mkdir "$tmp/allowed-root/nested" "$tmp/outside-root"
ln -s "$tmp/outside-root" "$tmp/allowed-root/external-link"
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
    --agent-id 00000000-0000-4000-8000-000000000001 --ca "$certs/ca.crt" \
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
kill "$server_pid"
wait "$server_pid" || true
server_pid=
set +e
"$bin_dir/sw-agentd" run --endpoint 127.0.0.1 --port "$port" \
    --agent-id 00000000-0000-4000-8000-000000000001 --ca "$certs/ca.crt" \
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
    --tenant smoke-tenant --db "$tmp/server.sqlite" >"$tmp/server-restart.log" 2>&1 &
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
    --agent-id 00000000-0000-4000-8000-000000000001 --ca "$certs/ca.crt" \
    --cert "$certs/agent.crt" --key "$certs/agent.key" --store "$tmp/offline-agent-store"
"$bin_dir/sw-agentd" status --store "$tmp/offline-agent-store" >"$tmp/offline-after-restart.json"
python3 - "$tmp/offline-after-restart.json" "$tmp/server.sqlite" <<'PY'
import json, sqlite3, sys
status = json.load(open(sys.argv[1], encoding="utf-8"))
assert status["queued"] == 0, status
db = sqlite3.connect(sys.argv[2])
assert db.execute("select count(*) from events").fetchone()[0] == 3
PY

kill "$server_pid"
wait "$server_pid" || true
server_pid=
echo "SEA mTLS/queue/restart/dedup/signature/HTTP framing smoke: PASS"
