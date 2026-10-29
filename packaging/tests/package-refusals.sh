#!/usr/bin/env bash
# git_commit stays a bare 40-hex SHA and git_dirty records a dirty tree; public
# refuses a dirty tree or a prebuilt binary. Runs in a scratch clone so the real tree is untouched.
set -euo pipefail
root=$(git rev-parse --show-toplevel)
binary=${CARGO_TARGET_DIR:-$root/target}/release/rustopnsmcp
[[ -x "$binary" ]] || { echo "build $binary first"; exit 1; }
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
git clone -q "$root" "$scratch/repo"
# Test the working-tree script, committed in the clone so the clone stays clean.
cp "$root/scripts/package-lxc.sh" "$scratch/repo/scripts/"
cd "$scratch/repo"
# Commit only if the copied script differs (a clean checkout has no change).
if [[ -n "$(git status --porcelain)" ]]; then git -c user.name=t -c user.email=t@example.org commit -qam scratch; fi
mkdir -p target/release; cp "$binary" target/release/
unset CARGO_TARGET_DIR
run() { OPNSMCP_PACKAGE_SKIP_BUILD=${SKIP:-1} OPNSMCP_PACKAGE_OUTPUT_DIR="$scratch/out" "$@" scripts/package-lxc.sh; }
info_of() { tar -xzOf "$scratch"/out/*.tar.gz --wildcards '*/BUILD-INFO' | sed -n "s/^$1=//p"; }

run env >/dev/null 2>&1
[[ "$(info_of git_commit)" =~ ^[0-9a-f]{40}$ ]] || { echo "FAIL: clean git_commit is not a bare SHA"; exit 1; }
[[ "$(info_of git_dirty)" == false ]] || { echo "FAIL: clean tree not git_dirty=false"; exit 1; }
touch packaging/stray-file
run env OPNSMCP_RELEASE_STATUS=lab-only >/dev/null 2>&1
[[ "$(info_of git_commit)" =~ ^[0-9a-f]{40}$ ]] || { echo "FAIL: dirty git_commit is not a bare SHA"; exit 1; }
[[ "$(info_of git_dirty)" == true ]] || { echo "FAIL: dirty tree not git_dirty=true"; exit 1; }
if run env OPNSMCP_RELEASE_STATUS=public 2>"$scratch/err" >/dev/null; then echo "FAIL: public accepted dirty tree"; exit 1; fi
grep -q 'dirty' "$scratch/err" || { echo "FAIL: wrong refusal for dirty+public"; exit 1; }
rm packaging/stray-file
if run env OPNSMCP_RELEASE_STATUS=public 2>"$scratch/err" >/dev/null; then echo "FAIL: public accepted SKIP_BUILD"; exit 1; fi
grep -q 'SKIP_BUILD' "$scratch/err" || { echo "FAIL: wrong refusal for skip-build+public"; exit 1; }
echo "package-refusals: ok"
