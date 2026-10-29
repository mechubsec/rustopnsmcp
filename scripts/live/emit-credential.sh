#!/usr/bin/env bash
# shellcheck disable=SC1090 # the env file is the dev host's, not part of this repo
# Runs on the dev host (ssh ... bash -s -- <what> < emit-credential.sh). Writes one lab credential to
# stdout and nothing else, for piping straight into a rig. Never run it with its output on a terminal.
# The env file is sourced in a subshell and read by builtins only, so no child process (cat included)
# inherits the key or secret, even if the file uses `export`.
set -euo pipefail
set +x
: "${LAB_ENV_FILE:?}"
case "${1:?key|secret|ca|endpoint}" in
  key) ( . "$LAB_ENV_FILE"; printf '%s' "$OPNSENSE_API_KEY" ) ;;
  secret) ( . "$LAB_ENV_FILE"; printf '%s' "$OPNSENSE_API_SECRET" ) ;;
  ca) ca_path=$( . "$LAB_ENV_FILE"; printf '%s' "$OPNSENSE_CA" ); cat "$ca_path" ;;
  endpoint) ( . "$LAB_ENV_FILE"; printf '%s' "$OPNSENSE_URL" ) ;;
  *) exit 2 ;;
esac
