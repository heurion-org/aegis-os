#!/usr/bin/env bash
# Generate self-signed CA + Gateway server cert + client cert for UOMP Gateway mTLS testing.

set -e

DATA_DIR="${UOMP_DATA_DIR:-$HOME/.uomp}"
CERT_DIR="${UOMP_GATEWAY_CERT_DIR:-$DATA_DIR/.gateway-certs}"
mkdir -p "$CERT_DIR"

cd "$CERT_DIR"

# Generate CA key and cert
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=uomp-gateway-ca"

# Generate Gateway server key and cert signed by CA (includes localhost SAN)
openssl genrsa -out gateway.key 2048
openssl req -new -key gateway.key -out gateway.csr -subj "/CN=uomp-gateway"
openssl x509 -req -in gateway.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out gateway.crt -days 365 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

# Generate client key and cert signed by CA
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=uomp-agent-client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365

# Print client fingerprint for Remote Profile allowlist
echo ""
echo "Client certificate fingerprint (add to remote-profile.json agent_allowlist):"
openssl x509 -in client.crt -noout -fingerprint -sha256

echo ""
echo "Certs generated in: $CERT_DIR"
