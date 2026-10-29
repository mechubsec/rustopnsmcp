#!/usr/bin/env bash
# git_commit must not lie: a dirty tree is marked, and public refuses a dirty
# tree or a prebuilt binary. Runs in a scratch clone so the real tree is untouched.
set -euo pipefail
root=$(git rev-parse --show-toplevel)
binary=${CARGO_TARGET_DIR:-$root/target}/release/rustopnsmcp
[[ -x "$binary" ]] || { echo "build $binary first"; exit 1; }
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
git clone -q "$root" "$scratch/repo"
# Test the working-tree script, committed in the clone so the clone stays clean.
cp "$root/scripts/package-lxc.sh" "$scratch/repo/scripts/"
cd "$scratch/repo"; git -c user.name=t -c user.email=t@example.org commit -qam scratch
mkdir -p target/release; cp "$binary" target/release/
unset CARGO_TARGET_DIR
run() { OPNSMCP_PACKAGE_SKIP_BUILD=${SKIP:-1} OPNSMCP_PACKAGE_OUTPUT_DIR="$scratch/out" "$@" scripts/package-lxc.sh; }
commit_of() { tar -xzOf "$scratch"/out/*.tar.gz --wildcards '*/BUILD-INFO' | sed -n 's/^git_commit=//p'; }

run env >/dev/null 2>&1; [[ "$(commit_of)" != *-dirty ]] || { echo "FAIL: clean tree marked dirty"; exit 1; }
touch packaging/stray-file
run env OPNSMCP_RELEASE_STATUS=lab-only >/dev/null 2>&1
[[ "$(commit_of)" == *-dirty ]] || { echo "FAIL: dirty tree not marked -dirty"; exit 1; }
if run env OPNSMCP_RELEASE_STATUS=public 2>"$scratch/err" >/dev/null; then echo "FAIL: public accepted dirty tree"; exit 1; fi
grep -q 'dirty' "$scratch/err" || { echo "FAIL: wrong refusal for dirty+public"; exit 1; }
rm packaging/stray-file
if run env OPNSMCP_RELEASE_STATUS=public 2>"$scratch/err" >/dev/null; then echo "FAIL: public accepted SKIP_BUILD"; exit 1; fi
grep -q 'SKIP_BUILD' "$scratch/err" || { echo "FAIL: wrong refusal for skip-build+public"; exit 1; }
echo "package-refusals: ok"
