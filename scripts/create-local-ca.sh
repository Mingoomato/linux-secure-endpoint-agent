#!/bin/sh
set -eu

out="$HOME/.local/state/linuxsecurity-lab-certs"
if [ "$#" -gt 0 ]; then out=$1; fi
case "$out" in
    "$PWD"/*|*/linux-secure-endpoint-agent|*/linux-secure-endpoint-agent/*)
        echo "Certificate material must be outside the repository." >&2
        exit 2
        ;;
esac
mkdir -p "$out"
chmod 700 "$out"
umask 077

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$out/ca.key" >/dev/null 2>&1
openssl req -x509 -new -key "$out/ca.key" -sha256 -days 365 \
    -subj "/CN=LinuxSecurity Lab CA" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=hash" -out "$out/ca.crt" \
    >/dev/null 2>&1

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$out/server.key" >/dev/null 2>&1
openssl req -new -key "$out/server.key" -subj "/CN=localhost" -out "$out/server.csr" >/dev/null 2>&1
cat >"$out/server.ext" <<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
EOF
openssl x509 -req -in "$out/server.csr" -CA "$out/ca.crt" -CAkey "$out/ca.key" \
    -CAcreateserial -out "$out/server.crt" -days 90 -sha256 -extfile "$out/server.ext" >/dev/null 2>&1

agent_id=00000000-0000-4000-8000-000000000001
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$out/agent.key" >/dev/null 2>&1
openssl req -new -key "$out/agent.key" -subj "/CN=$agent_id" -out "$out/agent.csr" >/dev/null 2>&1
cat >"$out/agent.ext" <<'EOF'
extendedKeyUsage=clientAuth
keyUsage=digitalSignature,keyEncipherment
EOF
openssl x509 -req -in "$out/agent.csr" -CA "$out/ca.crt" -CAkey "$out/ca.key" \
    -CAcreateserial -out "$out/agent.crt" -days 90 -sha256 -extfile "$out/agent.ext" >/dev/null 2>&1
printf '%s\n' "$agent_id" >"$out/agents.txt"

openssl genpkey -algorithm ED25519 -out "$out/policy-signing.key" >/dev/null 2>&1
openssl pkey -in "$out/policy-signing.key" -pubout -out "$out/policy-signing.pub" >/dev/null 2>&1
chmod 600 "$out"/*.key "$out"/*.csr
chmod 644 "$out"/*.crt "$out"/*.pub "$out"/agents.txt
echo "Lab certificates and policy signing key created outside the repository at $out"
