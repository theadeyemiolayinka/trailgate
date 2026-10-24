#!/usr/bin/env bash
# Generates a local development CA and a localhost server certificate for
# ExampleShop TLS mode. Requires openssl (available in Git Bash on Windows).
#
# After running this script:
#   - the shop serves HTTPS on SHOP_TLS_PORT (default 3443)
#   - the agent CLI trusts it with:
#       export NODE_EXTRA_CA_CERTS=apps/example-shop/dev-certs/ca.crt
#   - the browser trusts it after you import ca.crt as a trusted root
#     (or accept the one-time warning)
set -euo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)/dev-certs"
mkdir -p "$DIR"
cd "$DIR"

if [ ! -f ca.key ]; then
  openssl genrsa -out ca.key 4096 >/dev/null 2>&1
  openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
    -subj "/CN=ExampleShop Dev CA/O=TrailGate dev" -out ca.crt
fi

if [ ! -f server.key ]; then
  openssl genrsa -out server.key 2048 >/dev/null 2>&1
fi

cat > server.cnf <<'EOF'
[req]
distinguished_name = dn
req_extensions = ext
[dn]
[ext]
subjectAltName = DNS:localhost,DNS:127.0.0.1,IP:127.0.0.1
EOF

openssl req -new -key server.key -subj "/CN=localhost/O=TrailGate dev" \
  -out server.csr -config server.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -sha256 -extensions ext -extfile server.cnf -out server.crt

rm -f server.csr server.cnf ca.srl

echo "wrote $DIR/ca.crt, server.crt, server.key"
echo "trust for node CLIs: export NODE_EXTRA_CA_CERTS=$DIR/ca.crt"
