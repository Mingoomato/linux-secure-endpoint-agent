#!/usr/bin/env python3
"""Exercise operator enrollment, certificate rotation, revocation and re-enrollment."""

import hashlib
import json
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import sys

certs = Path(sys.argv[1])
port = int(sys.argv[2])
token = Path(sys.argv[3]).read_text().strip()
database = Path(sys.argv[4])
agent_id = "00000000-0000-4000-8000-000000000002"


def create_certificate(name):
    key = certs / f"{name}.key"
    csr = certs / f"{name}.csr"
    crt = certs / f"{name}.crt"
    commands = (
        ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-out", str(key)],
        ["openssl", "req", "-new", "-key", str(key), "-subj", f"/CN={agent_id}",
         "-out", str(csr)],
        ["openssl", "x509", "-req", "-in", str(csr), "-CA", str(certs / "ca.crt"),
         "-CAkey", str(certs / "ca.key"), "-CAcreateserial", "-out", str(crt),
         "-days", "30", "-sha256", "-extfile", str(certs / "agent.ext")],
    )
    for command in commands:
        subprocess.run(command, check=True, capture_output=True, timeout=10)
    key.chmod(0o600)
    der = ssl.PEM_cert_to_DER_cert(crt.read_text())
    return hashlib.sha256(der).hexdigest()


def request(identity, method, path, document=None, admin=False):
    context = ssl.create_default_context(cafile=str(certs / "ca.crt"))
    context.load_cert_chain(str(certs / f"{identity}.crt"), str(certs / f"{identity}.key"))
    body = b"" if document is None else json.dumps(document, separators=(",", ":")).encode()
    headers = ["Host: 127.0.0.1", "Connection: close"]
    if document is not None:
        headers += ["Content-Type: application/json", f"Content-Length: {len(body)}"]
    if admin:
        headers.append("Authorization: Bearer " + token)
    wire = (f"{method} {path} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n").encode() + body
    with context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5),
                             server_hostname="127.0.0.1") as connection:
        connection.settimeout(5)
        connection.sendall(wire)
        response = bytearray()
        while True:
            try:
                chunk = connection.recv(8192)
            except ConnectionResetError:
                break
            if not chunk:
                break
            response.extend(chunk)
    if b"\r\n\r\n" not in response:
        return 0, {}
    head, payload = bytes(response).split(b"\r\n\r\n", 1)
    status = int(head.split(b"\r\n", 1)[0].split()[1])
    return status, json.loads(payload) if payload else {}


old_hash = create_certificate("lifecycle-old")
new_hash = create_certificate("lifecycle-new")
replacement_hash = create_certificate("lifecycle-replacement")
assert len({old_hash, new_hash, replacement_hash}) == 3
health = ("GET", "/healthz")
status_path = f"/v1/admin/agents/{agent_id}"

assert request("lifecycle-old", *health)[0] in (0, 403)
assert request("operator", "GET", status_path, admin=True)[0] == 404
assert request("agent", "POST", "/v1/admin/agents:enroll",
               {"agent_id": agent_id, "certificate_sha256": old_hash}, admin=True)[0] == 403
assert request("operator", "POST", "/v1/admin/agents:enroll",
               {"agent_id": agent_id, "certificate_sha256": old_hash})[0] == 403
assert request("operator", "POST", "/v1/admin/agents:enroll",
               {"agent_id": agent_id, "certificate_sha256": old_hash}, admin=True)[0] == 201
assert request("operator", "POST", "/v1/admin/agents:enroll",
               {"agent_id": agent_id, "certificate_sha256": old_hash}, admin=True)[0] == 409
assert request("lifecycle-old", *health)[0] == 200
status, body = request("operator", "GET", status_path, admin=True)
assert status == 200 and body["enabled"] and body["last_seen"] is not None

assert request("operator", "POST", "/v1/admin/agents:rotate",
               {"agent_id": agent_id, "certificate_sha256": new_hash}, admin=True)[0] == 202
assert request("lifecycle-new", *health)[0] == 200
assert request("lifecycle-old", *health)[0] in (0, 403)
with sqlite3.connect(database) as db:
    states = dict(db.execute(
        "SELECT fingerprint,state FROM agent_certificates WHERE agent_id=?", (agent_id,)
    ))
assert states[old_hash] == "retired" and states[new_hash] == "current", states

assert request("operator", "POST", "/v1/admin/agents:revoke",
               {"agent_id": agent_id}, admin=True)[0] == 200
assert request("lifecycle-new", *health)[0] in (0, 403)
status, body = request("operator", "GET", status_path, admin=True)
assert status == 200 and body["enabled"] is False
assert request("operator", "POST", "/v1/admin/agents:rotate",
               {"agent_id": agent_id, "certificate_sha256": replacement_hash},
               admin=True)[0] == 404

assert request("operator", "POST", "/v1/admin/agents:reenroll",
               {"agent_id": agent_id, "certificate_sha256": replacement_hash},
               admin=True)[0] == 201
assert request("lifecycle-replacement", *health)[0] == 200
assert request("lifecycle-new", *health)[0] in (0, 403)
status, body = request("operator", "GET", status_path, admin=True)
assert status == 200 and body["enabled"] is True and body["last_seen"] is not None
print("agent registry lifecycle: PASS")
