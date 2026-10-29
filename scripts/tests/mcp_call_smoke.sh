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
        failing = "firmware" not in self.path  # every other path is a device error carrying a canary
        body = b"DEVICE-ERROR-CANARY" if failing else json.dumps({"product_version": "26.7", "note": "a<b & c>d", "rows": [{"uuid": "ROWUUID"}]}).encode()
        self.send_response(500 if failing else 200)
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
  "keys":["product_version"],"pointers":{"/note":"^a<b & c>d$"}},
 {"name":"device error","tool":"list_opnsense_interfaces","arguments":{"device":"stub"},"expect":"error"}]
JSON
cat > mismatch.json <<'JSON'
[{"name":"saved-value mismatch","tool":"get_opnsense_firmware_status","arguments":{"device":"stub"},
  "expect":"ok","pointers":{"/note":"$canary"}}]
JSON
cat > guard.json <<'JSON'
[{"name":"guard fails","tool":"get_opnsense_firmware_status","arguments":{"device":"stub"},"expect":"error"},
 {"name":"later call","tool":"get_opnsense_firmware_status","arguments":{"device":"stub"},"expect":"ok"}]
JSON
cat > saves.json <<'JSON'
[{"name":"save through array","tool":"get_opnsense_firmware_status","arguments":{"device":"stub"},"expect":"ok",
  "save":{"uuid":"/rows/0/uuid"}},
 {"name":"saved value used","tool":"get_opnsense_firmware_status","arguments":{"device":"stub"},"expect":"ok",
  "pointers":{"/rows/0/uuid":"$uuid"}}]
JSON
cat > unresolved.json <<'JSON'
[{"name":"unresolved save","tool":"get_opnsense_firmware_status","arguments":{"device":"stub"},"expect":"ok",
  "save":{"gone":"/rows/9/uuid"}}]
JSON
cat > undefined.json <<'JSON'
[{"name":"undefined variable","tool":"get_opnsense_firmware_status","arguments":{"device":"stub"},"expect":"ok",
  "pointers":{"/nothing":"$never_saved"}}]
JSON
printf '{"canary":"SAVEDVALUECANARY"}' > vars.json
cd - >/dev/null
client=(python3 -I scripts/live/mcp_call.py)
server=(--stdio -- "$bin" --device-mapping "$work/devices.json" --inventory-readonly)
out=$("${client[@]}" "$work/calls.json" "${server[@]}") || true  # a failing call must still print its FAIL line
printf '%s\n' "$out"
[ "$(printf '%s\n' "$out" | grep -c '^PASS')" = 4 ]
if printf '%s' "$out" | grep -q 'DEVICE-ERROR-CANARY\|untrusted-device-content'; then echo 'device error text leaked'; exit 1; fi
# A $var pointer mismatch must FAIL without printing the saved value.
mismatch=$("${client[@]}" "$work/mismatch.json" --vars "$work/vars.json" "${server[@]}") || true
printf '%s\n' "$mismatch"
printf '%s' "$mismatch" | grep -q '^FAIL'
if printf '%s' "$mismatch" | grep -q 'SAVEDVALUECANARY'; then echo 'saved value leaked'; exit 1; fi
# Stop at the first FAIL by default; --keep-going runs on.
guard=$("${client[@]}" "$work/guard.json" "${server[@]}") || true
printf '%s\n' "$guard"
printf '%s' "$guard" | grep -q '^ABORT: stopping after guard fails; 1 later call(s) not run'
if printf '%s' "$guard" | grep -q 'later call  '; then echo 'a call ran after a FAIL'; exit 1; fi
going=$("${client[@]}" --keep-going "$work/guard.json" "${server[@]}") || true
printf '%s' "$going" | grep -q '^PASS later call'
# save and pointers traverse array indexes; an unresolved save or an undefined variable is a FAIL.
saves=$("${client[@]}" "$work/saves.json" "${server[@]}")
printf '%s\n' "$saves"
[ "$(printf '%s\n' "$saves" | grep -c '^PASS')" = 2 ]
unresolved=$("${client[@]}" "$work/unresolved.json" "${server[@]}") || true
printf '%s' "$unresolved" | grep -q '^FAIL unresolved save.*save gone: pointer /rows/9/uuid unresolved'
undefined=$("${client[@]}" "$work/undefined.json" "${server[@]}") || true
# shellcheck disable=SC2016  # the $ is literal
printf '%s' "$undefined" | grep -q '^FAIL undefined variable.*unknown variable \$never_saved'
if printf '%s' "$saves$unresolved$undefined" | grep -q 'ROWUUID'; then echo 'device value leaked'; exit 1; fi
