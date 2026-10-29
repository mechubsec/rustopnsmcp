#!/usr/bin/env bash
# Documentation gate: public-repo hygiene, resolvable links and paths, only
# real flags, and the site override example embedded in the LXC guide being
# the shipped file. Run from anywhere in the checkout: scripts/check-docs.sh
#
# Checks every Markdown file git knows about (tracked, or new and not ignored),
# except the design records under docs/design/, so a new doc is gated before
# it is committed.
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
failed=0
fail() { echo "FAIL: $*" >&2; failed=1; }

docs=()
while IFS= read -r file; do
    [[ -f "$file" ]] && docs+=("$file")
done < <(git ls-files --cached --others --exclude-standard -- '*.md' ':!:docs/design/*' | sort -u)

# 1. Hygiene. The only IPv4 addresses allowed are the RFC 5737 documentation
# ranges, loopback and 0.0.0.0. RFC 1918 is deliberately NOT allowed: the real
# lab is RFC 1918, so allowing it would let a real address through. To allow
# another address, add it here with a comment saying why.
allowed='^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|127\.|0\.0\.0\.0$)'
while IFS=: read -r file line address; do
    [[ "$address" =~ $allowed ]] || fail "$file:$line IPv4 address outside the documentation ranges: $address"
done < <(grep -noE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "${docs[@]}" || true)
# Bare mechub.org stays allowed (branding); any name under it is the real lab.
if grep -nE '[A-Za-z0-9-]+\.(lan|local|internal|corp|home\.arpa)\b|[A-Za-z0-9-]+\.mechub\.org\b' "${docs[@]}"; then
    fail "site-looking hostname (use *.example.org)"
fi
if grep -nE '(/home/[a-z]|~/\.env|\.credentials)' "${docs[@]}"; then
    fail "credential-looking path or value"
fi

# 2. Relative links resolve, and so does every `packaging/…`, `scripts/…` or
# `docs/…` path written in backticks.
# shellcheck disable=SC2016 # the backticks are literal Markdown, not a command substitution
backticked_path='`(packaging|scripts|docs)/[A-Za-z0-9._/-]+`'
for doc in "${docs[@]}"; do
    dir=$(dirname "$doc")
    while IFS= read -r target; do
        target=${target%%#*}
        [[ -z "$target" || "$target" =~ ^(https?:|mailto:) ]] && continue
        [[ -e "$dir/$target" ]] || fail "$doc links to missing $target"
    done < <(grep -oE '\]\([^)]+\)' "$doc" | sed -E 's/^\]\((.*)\)$/\1/' || true)
    while IFS= read -r path; do
        [[ -e "$path" ]] || fail "$doc names the path $path, which does not exist"
    done < <(grep -oE "$backticked_path" "$doc" | tr -d '`' || true)
done

# 3. Every --flag in the docs is a flag of rustopnsmcp (top level, each
# subcommand, and each subcommand's subcommands) or a listed foreign one.
# A trailing * in a documented flag (--ssdf-audit-*) is a prefix match.
binary=${CARGO_TARGET_DIR:-target}/debug/rustopnsmcp
[[ -x "$binary" ]] || cargo build -q -p rustopnsmcp
help_flags() { "$binary" "$@" --help | grep -oE -- '--[a-z0-9][a-z0-9-]*' || true; }
subcommands() { "$binary" "$@" --help | awk '/^Commands:/{on=1; next} on && /^[[:space:]]*$/{on=0} on && $1 != "help" {print $1}'; }
real=$({
    help_flags
    while IFS= read -r sub; do
        help_flags "$sub"
        while IFS= read -r leaf; do help_flags "$sub" "$leaf"; done < <(subcommands "$sub")
    done < <(subcommands)
} | sort -u)
# Flags another tool owns. Add one only when the docs show that tool, and say
# which, so this list cannot quietly hide a misspelt rustopnsmcp flag.
# systemctl/docker: --kill-whom --signal --now. journalctl: --after-cursor
# --show-cursor --no-pager. systemd-tmpfiles: --create. curl: --cacert.
# pct: --features. cosign: --bundle --certificate-oidc-issuer
# --certificate-identity-regexp --certificate-github-workflow-repository. docker: --rm --restart --read-only --cap-drop
# --security-opt --tmpfs --env-file --platform (--name is also a real token flag).
# cargo: --all --all-features --all-targets --check --locked --no-deps
# --workspace. scripts/parity-check.sh: --junos-src. mecfeed-serve:
# --allow-anonymous-feeds --allow-cidr --clients-file --generate-basic-password --listen.
foreign=" \
    --kill-whom --signal --now \
    --allow-anonymous-feeds --allow-cidr --clients-file --generate-basic-password --listen \
    --after-cursor --show-cursor --no-pager \
    --create \
    --cacert \
    --features \
    --bundle --certificate-oidc-issuer --certificate-identity-regexp \
    --certificate-github-workflow-repository \
    --rm --restart --read-only --cap-drop --security-opt --tmpfs --env-file --platform \
    --all --all-features --all-targets --check --locked --no-deps --workspace \
    --junos-src \
"
while IFS= read -r flag; do
    if [[ "$flag" == *'*' ]]; then
        prefix=${flag%\*}
        [[ "$prefix" != -- ]] && grep -q -e "^$prefix" <<<"$real" && continue
        fail "docs mention $flag, which matches no rustopnsmcp flag"
        continue
    fi
    grep -qxF -- "$flag" <<<"$real" && continue
    [[ "$foreign" == *" $flag "* ]] && continue
    fail "docs mention $flag, which rustopnsmcp --help does not list (add it to 'foreign' only if another tool owns it)"
done < <(grep -ohE -- '--[a-z0-9][a-z0-9-]*\*?' "${docs[@]}" | sort -u || true)

# 4. The override example in the LXC guide is the shipped file.
guide=docs/HOW-TO-SETUP-LXC.md
example=packaging/systemd/rustopnsmcp.override.conf.example
[[ -e "$guide" ]] || fail "$guide is missing"
embedded=$(sed -n '/<!-- override-example:start -->/,/<!-- override-example:end -->/p' "$guide" 2>/dev/null \
    | sed -E -e '/<!--/d' -e '/^[`]{3}/d' | grep -v '^#' | sed 's/[[:space:]]*$//' || true)
shipped=$(grep -v '^#' "$example" | sed 's/[[:space:]]*$//')
[[ -n "$embedded" ]] || fail "$guide has no override-example block"
[[ "$embedded" == "$shipped" ]] || fail "$guide's override block differs from $example"

# 5. Every doc in docs/ is linked from README.md.
for doc in docs/*.md; do
    [[ -e "$doc" ]] || continue
    grep -qF "]($doc)" README.md || fail "README.md does not link $doc"
done

[[ "$failed" -eq 0 ]] && echo "check-docs: ok"
exit "$failed"
