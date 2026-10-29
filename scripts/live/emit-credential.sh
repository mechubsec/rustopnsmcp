#!/usr/bin/env bash
# shellcheck disable=SC1090 # the env file is the dev host's, not part of this repo
# Runs on the dev host (ssh ... bash -s -- <what> < emit-credential.sh). Writes one lab credential to
# stdout and nothing else, for piping straight into a rig. Never run it with its output on a terminal.
# The env file is sourced in a subshell and read by builtins only, so no child process (cat included)
# inherits the key or secret, even if the file uses `export`. The subshell's stderr is discarded: a syntax
# error in the file would otherwise print a fragment of a credential line.
set -euo pipefail
set +x
: "${LAB_ENV_FILE:?}"
# read_var <NAME>: value of NAME as defined by the env file; a fixed message on any failure.
read_var() {
  ( . "$LAB_ENV_FILE" && printf '%s' "${!1}" ) 2>/dev/null || { echo "emit-credential: cannot read $1 from the env file" >&2; exit 1; }
}
case "${1:?key|secret|ca|endpoint}" in
  key) read_var OPNSENSE_API_KEY ;;
  secret) read_var OPNSENSE_API_SECRET ;;
  ca) ca_path=$(read_var OPNSENSE_CA); cat "$ca_path" ;;
  endpoint) read_var OPNSENSE_URL ;;
  *) exit 2 ;;
esac
