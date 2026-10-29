#!/usr/bin/env bash
# Sanitize a raw OPNsense capture (see scripts/sanitize_fixture.py for the rules).
exec python3 -I "$(dirname "$0")/sanitize_fixture.py" "$@"
