#!/usr/bin/env bash
# lab-get.sh must hand the API key and secret to curl on stdin only: no child process may inherit them.
# Every external command the script runs is replaced by a stub that records whether the canary credential
# is in its environment. The lab is never contacted: the stub curl answers.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
script="$PWD/scripts/live/lab-get.sh"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"; : > "$work/seen"
for tool in sed mktemp install python3 cat rm; do
  real=$(command -v "$tool")
  printf '#!/usr/bin/env bash\nif env | grep -q CANARY; then echo "%s leaked" >> "%s/seen"; fi\nexec "%s" "$@"\n' \
    "$tool" "$work" "$real" > "$work/bin/$tool"
done
cat > "$work/bin/curl" <<STUB
#!/usr/bin/env bash
if env | grep -q CANARY; then echo "curl leaked" >> "$work/seen"; fi
config=\$(cat)
case "\$config" in *CANARY-KEY:CANARY-SECRET*) echo "stdin ok" >> "$work/seen" ;; esac
while [ \$# -gt 0 ]; do [ "\$1" = -o ] && printf '{"a":1}' > "\$2"; shift; done
printf 200
STUB
chmod +x "$work/bin"/*
printf 'export OPNSENSE_URL=https://192.0.2.1\nOPNSENSE_API_KEY=CANARY-KEY\nOPNSENSE_API_SECRET=CANARY-SECRET\n' > "$work/env"
out=$(PATH="$work/bin:$PATH" LAB_ENV_FILE="$work/env" LAB_CA_FILE=/dev/null bash "$script" shape /api/x)
printf '%s\n' "$out"
cat "$work/seen"
[ "$(cat "$work/seen")" = "stdin ok" ]
[ "$(printf '%s\n' "$out" | tail -1)" = '{"a": "int"}' ]
echo "lab-get env isolation: PASS"
