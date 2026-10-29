#!/usr/bin/env bash
# Read-only GET against opnsense-lab. Runs on the dev host that holds the owner-only lab credentials.
#   lab-get.sh shape <path[?query]>            HTTP status and JSON key names/types only
#   lab-get.sh raw   <path[?query]> <out-file> raw body to a 0600 file (never printed)
# Needs: LAB_ENV_FILE (defines OPNSENSE_URL, OPNSENSE_API_KEY, OPNSENSE_API_SECRET), LAB_CA_FILE.
set -euo pipefail
set +x  # xtrace would print the curl config that carries the key and secret
mode="${1:?shape|raw}"; path="${2:?path}"; out="${3:-}"
case "$mode" in shape|raw) ;; *) echo "mode must be shape or raw" >&2; exit 2 ;; esac
case "$path" in /api/*) ;; *) echo "path must start with /api/" >&2; exit 2 ;; esac
# The credentials are sourced only inside the left side of the pipe below, and printf is a builtin, so no
# child process (curl included) ever inherits them. Even if the env file itself uses `export`, that stays
# inside the subshell. The URL is not secret, so it is read in its own subshell first.
# shellcheck source=/dev/null
url=$(. "$LAB_ENV_FILE"; printf '%s' "$OPNSENSE_URL")
host=$(printf '%s' "$url" | sed -E 's#^https?://##; s#[:/].*$##')
body=$(mktemp); trap 'rm -f "$body"' EXIT; umask 077
# shellcheck source=/dev/null
code=$( { . "$LAB_ENV_FILE"; printf 'user = "%s:%s"\n' "$OPNSENSE_API_KEY" "$OPNSENSE_API_SECRET"; } \
  | curl -s -X GET -o "$body" -w '%{http_code}' -K - --cacert "$LAB_CA_FILE" \
      --resolve "opnsense-lab:443:$host" "https://opnsense-lab$path")
if [ "$mode" = raw ]; then install -m 600 "$body" "${out:?out-file}"; echo "HTTP $code -> raw saved"; exit 0; fi
echo "HTTP $code"
python3 -I - "$body" <<'PY'
import json, sys
def shape(v, depth=0):
    if isinstance(v, dict):
        return "{...%d keys}" % len(v) if depth >= 3 else {k: shape(x, depth + 1) for k, x in list(v.items())[:40]}
    if isinstance(v, list):
        return ["list[%d]" % len(v)] + ([shape(v[0], depth + 1)] if v and depth < 3 else [])
    return type(v).__name__
try:
    print(json.dumps(shape(json.load(open(sys.argv[1])))))
except ValueError:
    print("non-json body")
PY
