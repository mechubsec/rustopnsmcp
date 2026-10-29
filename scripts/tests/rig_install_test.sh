#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal $(...) payloads are the test input
# rig-install.sh and rig-token.sh against a stub ssh/scp/pct. The stub ssh behaves like the real one: it joins
# its arguments into one string and lets a shell re-split it, so quoting bugs show up. The "guest" is a
# directory; the dev host is this machine. Nothing leaves it.
#   LIVE_DIR=<dir> bash rig_install_test.sh   runs against another copy of the scripts (default: this repo)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
live="${LIVE_DIR:-$PWD/scripts/live}"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/tmp" "$work/guest"; export TMPDIR="$work/tmp"
cat > "$work/bin/ssh" <<STUB
#!/usr/bin/env bash
# Like real ssh: without -n it reads stdin to EOF, passing it to the remote command or, for the local
# pvesh/hostname answers, swallowing it.
nostdin=0; [ "\$1" = -n ] && { nostdin=1; shift; }
host=\$1; shift
echo "ssh \$host \$*" >> "$work/ssh-calls"
case "\$*" in
  *"pvesh get /cluster/resources"*)
    [ \$nostdin = 1 ] || cat >/dev/null
    n=\$(( \$(cat "$work/pvesh-count" 2>/dev/null || echo 0) + 1 )); echo \$n > "$work/pvesh-count"
    vmid=901
    if [ -e "$work/flip" ] || [ \$n -gt "\${FLIP_AFTER:-999}" ]; then vmid=902; fi
    printf '[{"name":"test-labmode-opns","type":"lxc","node":"nodeA","vmid":%s,"status":"running","tags":"disposable"}]' \$vmid ;;
  "hostname -s") [ \$nostdin = 1 ] || cat >/dev/null; echo nodeA ;;
  *) [ \$nostdin = 1 ] && exec bash -c "\$*" </dev/null; exec bash -c "\$*" ;;
esac
STUB
cat > "$work/bin/scp" <<STUB
#!/usr/bin/env bash
shift; args=("\$@"); dest=\${args[-1]#*:}; unset 'args[-1]'; cp "\${args[@]}" "\$dest"
STUB
cat > "$work/bin/pct" <<STUB
#!/usr/bin/env bash
echo "\$*" >> "$work/pct-calls"
root="$work/guest"
case \$1 in
  push)
    # A running service holds its binary open: replacing it fails, as on a real rig.
    if [ "\$4" = /usr/local/bin/rustopnsmcp ] && [ -e "\$root/running" ]; then echo "failed to create file: \$4: Text file busy" >&2; exit 255; fi
    mkdir -p "\$(dirname "\$root\$4")"; cp "\$3" "\$root\$4" ;;
  exec) shift 3
    case \$1 in
      hostname) echo 192.0.2.10 ;;
      systemctl) case \$2 in stop) [ -n "\${STUCK_RUNNING:-}" ] || rm -f "\$root/running" ;; start) touch "\$root/running" ;;
                 enable) [ -z "\${FLIP_ON_ENABLE:-}" ] || touch "$work/flip" ;; esac ;;
      sha256sum) [ -z "\${NO_HASH:-}" ] || exit 1
                 if [ -n "\${WRONG_HASH:-}" ]; then echo "0000 \$2"; else sha256sum "\$root\$2" | sed "s#\$root##"; fi ;;
      systemd-sysusers|systemd-tmpfiles|chown) ;;
      install) mkdir -p "\$root\${@: -1}"; touch "$work/credentials-dir-made"; [ -z "\${FLIP_ON_INSTALL:-}" ] || touch "$work/flip" ;;
      mkdir) mkdir -p "\$root\${@: -1}" ;;
      sh) shift 2; cmd="\$(printf '%s' "\$1" | sed -E "s#(^|[ >])/(etc|usr|var)/#\\1\$root/\\2/#g")"
          if [ -n "\${ZERO_WRITES:-}" ]; then sh -c "\$cmd" </dev/null; else sh -c "\$cmd"; fi ;;
      stat) shift; fmt=\$2; shift 2; for f in "\$@"; do stat -c "\$fmt" "\$root\$f"; done | sed "s#\$root##" ;;
      runuser) echo "p3-token-value" ;;
      *) echo "unexpected guest command: \$*" >&2; exit 9 ;;
    esac ;;
esac
STUB
chmod +x "$work/bin"/*
printf 'OPNSENSE_URL=https://192.0.2.1\nOPNSENSE_API_KEY=CANARY-KEY\nOPNSENSE_API_SECRET=CANARY-SECRET\nOPNSENSE_CA=%s\n' "$work/ca.pem" > "$work/env"
printf 'CA-BYTES' > "$work/ca.pem"; printf 'BIN' > "$work/binary"
reset() { rm -rf "$work/guest" "$work/flip" "$work/credentials-dir-made" "$work/pvesh-count"; mkdir "$work/guest"; : > "$work/ssh-calls"; : > "$work/pct-calls"; }
run() { PATH="$work/bin:$PATH" RIG_PVE=pvehost LAB_HOST=labhost LAB_ENV_FILE="${ENVF-$work/env}" bash "$live/$1" "${@:2}" 2>"$work/err" </dev/null; }
fail() { echo "FAIL $*"; exit 1; }

# 1. Happy path: files land, the stat report works and every size is non-zero, no credential in any output.
reset
run rig-install.sh test-labmode-opns "$work/binary" >"$work/out" || { cat "$work/err"; fail "install exited non-zero"; }
[ "$(cat "$work/guest/etc/rustopnsmcp/credentials/api-key")" = CANARY-KEY ] || fail "api-key not written"
[ "$(cat "$work/guest/etc/rustopnsmcp/credentials/ca.pem")" = CA-BYTES ] || fail "ca not written"
[ "$(wc -l < "$work/out")" = 4 ] || fail "expected 4 stat lines, got: $(cat "$work/out")"
awk '{ if (NF != 4 || $1 != "600" || $3 + 0 == 0) exit 1 }' "$work/out" || fail "mode/size report wrong: $(cat "$work/out")"
grep -q CANARY "$work/out" "$work/err" "$work/ssh-calls" "$work/pct-calls" && fail "credential visible in output or arguments"
grep -q -- '--audit-journald' "$work/guest/etc/systemd/system/rustopnsmcp.service.d/override.conf" || fail "override lacks audit flags"
grep -q 'systemctl enable' "$work/pct-calls" || fail "service not enabled"
grep -q 'still stopped' "$work/err" && fail "stopped-service warning on a successful install"
echo "ok   install: stat report is parsed correctly, 4 files, 600, non-zero, no credential in argv or output"

# 1a. Re-install over a running service: the service is stopped first, the new binary lands and its hash matches.
reset
mkdir -p "$work/guest/usr/local/bin"; printf OLD > "$work/guest/usr/local/bin/rustopnsmcp"; touch "$work/guest/running"
run rig-install.sh test-labmode-opns "$work/binary" >/dev/null || { cat "$work/err"; fail "re-install over a running service failed"; }
[ "$(cat "$work/guest/usr/local/bin/rustopnsmcp")" = BIN ] || fail "old binary left in place"
grep -q 'systemctl stop' "$work/pct-calls" || fail "service not stopped before the push"
grep -q 'still stopped' "$work/err" && fail "stopped-service warning on a successful re-install"
echo "ok   install: running service is stopped, the busy binary is replaced, the hash matches"

# 1a2. A binary that does not land (or lands different) fails the install with the old binary untouched.
reset
mkdir -p "$work/guest/usr/local/bin"; printf OLD > "$work/guest/usr/local/bin/rustopnsmcp"; touch "$work/guest/running"
if STUCK_RUNNING=1 run rig-install.sh test-labmode-opns "$work/binary" >/dev/null; then fail "install exited 0 with the old binary in place"; fi
grep -q 'could not replace' "$work/err" || fail "no clear message: $(head -1 "$work/err")"
grep -q 'rustopnsmcp on test-labmode-opns was stopped for this install and is still stopped' "$work/err" \
  || fail "failed push after the stop did not say the service is still stopped: $(cat "$work/err")"
grep -q 'rig-ctl.sh svc test-labmode-opns restart' "$work/err" || fail "no recovery command after the failed push"
[ "$(cat "$work/guest/usr/local/bin/rustopnsmcp")" = OLD ] || fail "binary changed despite the failure"
reset
if WRONG_HASH=1 run rig-install.sh test-labmode-opns "$work/binary" >/dev/null; then fail "install passed with a mismatched binary"; fi
grep -q 'does not match' "$work/err" || fail "no hash message: $(head -1 "$work/err")"
grep -q 'still stopped' "$work/err" || fail "hash mismatch did not say the service is still stopped"
reset
if NO_HASH=1 run rig-install.sh test-labmode-opns "$work/binary" >/dev/null; then fail "install passed with no rig hash"; fi
grep -q 'could not read the hash' "$work/err" || fail "no message when the rig hash cannot be read: $(cat "$work/err")"
# The hash read is a guest operation too: a recycled id is refused before it, not after.
reset
if FLIP_ON_ENABLE=1 run rig-install.sh test-labmode-opns "$work/binary" >/dev/null; then fail "install passed after the vmid changed"; fi
grep -q sha256sum "$work/pct-calls" && fail "hash read from the guest after the vmid changed"
grep -q 'no longer resolves' "$work/err" || fail "wrong refusal: $(head -1 "$work/err")"
echo "ok   install: a failed replace, hash read or hash mismatch fails clearly and says the service is still stopped"

# 1b. If the rig received nothing (zero-size files), the install fails loudly and prints no secret.
reset
if ZERO_WRITES=1 run rig-install.sh test-labmode-opns "$work/binary" >"$work/out"; then fail "install succeeded with empty credential files"; fi
grep -q 'missing or empty' "$work/err" || fail "no clear message: $(head -1 "$work/err")"
grep -q CANARY "$work/out" "$work/err" && fail "secret printed"
echo "ok   install: zero-size credential files make the install fail with a clear message"

# 2. A guest id that changes after resolve is refused before any credential is sent.
reset
if FLIP_ON_INSTALL=1 run rig-install.sh test-labmode-opns "$work/binary" >/dev/null; then fail "install proceeded after the vmid changed"; fi
[ ! -e "$work/guest/etc/rustopnsmcp/credentials/api-key" ] || fail "credential written after the vmid changed"
grep -q 'no longer resolves' "$work/err" || fail "wrong refusal: $(head -1 "$work/err")"
echo "ok   install: vmid changed after the credentials directory was made, refused with nothing written"

# 3. Operator values with shell metacharacters are refused before any ssh.
for bad in '/tmp/x; touch /tmp/pwned' '/tmp/a b' 'relative/env' '/tmp/$(id)' ''; do
  reset
  if ENVF="$bad" run rig-install.sh test-labmode-opns "$work/binary" >/dev/null 2>&1; then fail "LAB_ENV_FILE '$bad' accepted"; fi
  [ ! -s "$work/ssh-calls" ] || fail "ssh ran for LAB_ENV_FILE '$bad'"
done
reset
if PATH="$work/bin:$PATH" RIG_PVE='-oProxyCommand=x' LAB_HOST=labhost LAB_ENV_FILE="$work/env" bash "$live/rig-install.sh" test-labmode-opns "$work/binary" >/dev/null 2>&1; then fail "option-like RIG_PVE accepted"; fi
[ ! -s "$work/ssh-calls" ] || fail "ssh ran for a bad RIG_PVE"
echo "ok   install: unsafe LAB_ENV_FILE / RIG_PVE refused before any ssh"

# 4. Token: happy path prints the token alone; bad name / actor refused with no ssh; vmid change refused with no mint.
reset
[ "$(run rig-token.sh test-labmode-opns p3-lab agent)" = p3-token-value ] || fail "token not printed alone"
for args in "p3;id agent" 'a$(id) agent' "p3-lab root" "p3-lab unknown" "x"; do
  reset
  # shellcheck disable=SC2086 # word splitting of the case list is the point
  if run rig-token.sh test-labmode-opns $args >/dev/null 2>&1; then fail "token args '$args' accepted"; fi
  [ ! -s "$work/ssh-calls" ] || fail "ssh ran for token args '$args'"
done
# 4b. Optional tool list: reaches the guest intact; the default wildcard is not globbed by the node shell.
reset; run rig-token.sh test-labmode-opns p3-lab agent create_opnsense_change_set,get_opnsense_config_fingerprint >/dev/null
grep -q -- '--tools create_opnsense_change_set,get_opnsense_config_fingerprint --actor-type agent' "$work/pct-calls" || fail "tool list mangled: $(grep runuser "$work/pct-calls")"
reset; run rig-token.sh test-labmode-opns p3-lab agent >/dev/null
grep -q -- '--tools \* --actor-type agent' "$work/pct-calls" || fail "default wildcard mangled: $(grep runuser "$work/pct-calls")"
for tools in 'a;id' 'a b' 'A_b' 'a,,b' ',a' 'a,' '$(id)' 'a*'; do
  reset
  if run rig-token.sh test-labmode-opns p3-lab agent "$tools" >/dev/null 2>&1; then fail "tool list '$tools' accepted"; fi
  [ ! -s "$work/ssh-calls" ] || fail "ssh ran for tool list '$tools'"
done
echo "ok   token: tool list passed intact, wildcard default not globbed, unsafe lists refused before ssh"

reset
if FLIP_AFTER=1 run rig-token.sh test-labmode-opns p3-lab agent >/dev/null; then fail "token minted after the vmid changed"; fi
[ ! -s "$work/pct-calls" ] || fail "pct ran after the vmid changed"
echo "ok   token: bad name/actor refused before ssh; vmid change refused before minting"
echo "rig-install/rig-token: PASS"
