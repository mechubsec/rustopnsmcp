#!/usr/bin/env bash
# emit-credential.sh must write exactly one credential to stdout and hand it to no child process;
# make-devices-json.py must put no credential in devices.json. The lab is never contacted.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
emit="$PWD/scripts/live/emit-credential.sh"; devices="$PWD/scripts/live/make-devices-json.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"; : > "$work/seen"
real_cat=$(command -v cat)
printf '#!/usr/bin/env bash\nif env | grep -q CANARY; then echo "cat leaked" >> "%s/seen"; fi\nexec "%s" "$@"\n' "$work" "$real_cat" > "$work/bin/cat"
chmod +x "$work/bin/cat"
printf 'CA-BYTES' > "$work/ca.pem"
printf 'export OPNSENSE_URL=https://192.0.2.1\nexport OPNSENSE_API_KEY=CANARY-KEY\nOPNSENSE_API_SECRET=CANARY-SECRET\nOPNSENSE_CA=%s\n' "$work/ca.pem" > "$work/env"
get() { PATH="$work/bin:$PATH" LAB_ENV_FILE="$work/env" bash "$emit" "$1"; }
for pair in key=CANARY-KEY secret=CANARY-SECRET ca=CA-BYTES endpoint=https://192.0.2.1; do
  [ "$(get "${pair%%=*}")" = "${pair#*=}" ] || { echo "FAIL: wrong output for ${pair%%=*}"; exit 1; }
done
if get bogus 2>/dev/null; then echo "FAIL: unknown selector accepted"; exit 1; fi
[ ! -s "$work/seen" ] || { cat "$work/seen"; exit 1; }
json=$(get endpoint | python3 -I "$devices")
case "$json" in *CANARY*) echo "FAIL: credential in devices.json"; exit 1 ;; esac
[ "$(printf '%s' "$json" | python3 -I -c 'import json,sys; d=json.load(sys.stdin)["devices"]["opnsense-lab"]; print(d["endpoint"], d["api_key_file"])')" \
  = "https://192.0.2.1 /etc/rustopnsmcp/credentials/api-key" ] || { echo "FAIL: devices.json shape"; exit 1; }
if printf 'http://192.0.2.1' | python3 -I "$devices" 2>/dev/null; then echo "FAIL: http endpoint accepted"; exit 1; fi
echo "emit-credential env isolation: PASS"
