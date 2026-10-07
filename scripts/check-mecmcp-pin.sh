#!/usr/bin/env bash
# Every mecmcp crate in the build graph must resolve to exactly one git ref.
#
# Two refs means two copies of shared types (CallerCtx, AuditScope, ...) that
# the compiler treats as unrelated, and a security fix that reaches only half
# the graph. Spec §3.3: "All mecmcp crates are pinned to one ref."
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

tree=$(cargo tree --workspace --locked -e normal --prefix none)

refs=$(printf '%s\n' "$tree" \
  | grep -oE '^mecmcp-[a-z]+ v[0-9.]+ \(https://github\.com/mechubsec/mecmcp\?[^)]*\)' \
  | sed -E 's/^.*\?([^#)]*)#([0-9a-f]+)\)$/\1#\2/' \
  | sort -u)

count=$(printf '%s\n' "$refs" | grep -c . || true)
if [ "$count" -ne 1 ]; then
  echo "FAIL: mecmcp crates resolve to $count refs:"
  printf '  %s\n' $refs
  exit 1
fi

# The same crate at two versions or sources is a duplicate even under one ref.
dups=$(printf '%s\n' "$tree" \
  | grep -oE '^mecmcp-[a-z]+ v[0-9.]+ \([^)]*\)' | sort -u \
  | awk '{print $1}' | uniq -d)
if [ -n "$dups" ]; then
  echo "FAIL: mecmcp crates present more than once in the graph:"
  printf '  %s\n' $dups
  exit 1
fi

case "$refs" in
  tag=v*) echo "OK: every mecmcp crate resolves to $refs" ;;
  *) echo "FAIL: mecmcp is pinned by $refs; pin a released tag, not a rev or branch"; exit 1 ;;
esac
