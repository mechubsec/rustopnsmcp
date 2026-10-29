#!/usr/bin/env bash
# The MCP client completes a stdio handshake, and unwraps and unescapes a real server response.
# The device is a local loopback HTTPS stub with a throwaway CA: no real device is contacted.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bin="${RUSTOPNSMCP_BIN:-${CARGO_TARGET_DIR:-target}/debug/rustopnsmcp}"
work=$(mktemp -d); trap 'kill "${stub:-}" 2>/dev/null || true; rm -rf "$work"' EXIT
cd "$work"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.key -out ca.pem \
  -days 1 -subj /CN=smoke-ca 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout leaf.key -out leaf.csr \
  -subj /CN=localhost 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n' > ext
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out leaf.pem -days 1 \
  -extfile ext 2>/dev/null
cat > stub.py <<'PY'
import http.server, json, ssl
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # the entity-escaped characters in "note" are what the client must unescape
        body = json.dumps({"product_version": "26.7", "note": "a<b & c>d"}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("leaf.pem", "leaf.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
print(server.server_address[1], flush=True)
server.serve_forever()
PY
python3 -I stub.py > port & stub=$!
until [ -s port ]; do sleep 0.1; done
printf 'stub-key' > key; printf 'stub-secret' > secret; chmod 600 key secret
printf '{"version":1,"devices":{"stub":{"endpoint":"https://127.0.0.1:%s","api_key_file":"%s/key","api_secret_file":"%s/secret","ca_pem_path":"%s/ca.pem"}}}\n' \
  "$(cat port)" "$work" "$work" "$work" > devices.json; chmod 600 devices.json
cat > calls.json <<'JSON'
[{"name":"status","tool":"opnsmcp_status","arguments":{},"expect":"ok","keys":["version"]},
 {"name":"unknown device refused","tool":"get_opnsense_firmware_status","arguments":{"device":"nope"},"expect":"error"},
 {"name":"wrapped device read","tool":"get_opnsense_firmware_status","arguments":{"device":"stub"},"expect":"ok",
  "keys":["product_version"],"pointers":{"/note":"^a<b & c>d$"}}]
JSON
cd - >/dev/null
out=$(python3 -I scripts/live/mcp_call.py "$work/calls.json" --stdio -- "$bin" --device-mapping "$work/devices.json" --inventory-readonly) || true  # a failing call must still print its FAIL line
printf '%s\n' "$out"
[ "$(printf '%s\n' "$out" | grep -c '^PASS')" = 3 ]
