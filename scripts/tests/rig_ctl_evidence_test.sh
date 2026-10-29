#!/usr/bin/env bash
# rig-ctl.sh must prove a guest is disposable and unprotected before it does anything. A stub `ssh` on PATH
# serves canned `pvesh get /cluster/resources` JSON and records every other command it is asked to run;
# nothing leaves this machine. Refused cases must record no guest command at all.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
script="$PWD/scripts/live/rig-ctl.sh"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"
cat > "$work/bin/ssh" <<STUB
#!/usr/bin/env bash
case "\$*" in
  *"pvesh get /cluster/resources"*) cat "$work/fixture.json" ;;
  *"hostname -s"*) echo nodeA ;;
  *"hostname -I"*) echo "192.0.2.10" ;;
  *) echo "\$*" >> "$work/guest-calls" ;;
esac
STUB
chmod +x "$work/bin/ssh"
fixture() { printf '%s' "$1" > "$work/fixture.json"; : > "$work/guest-calls"; }
run() { PATH="$work/bin:$PATH" RIG_PVE=stub bash "$script" "$@" 2>"$work/err"; }
refuses() { # <label> <args...>: must fail, with no guest command recorded
  label=$1; shift
  if run "$@" >/dev/null; then echo "FAIL $label: proceeded"; exit 1; fi
  [ ! -s "$work/guest-calls" ] || { echo "FAIL $label: ran $(cat "$work/guest-calls")"; exit 1; }
  echo "ok   $label: refused ($(head -1 "$work/err"))"
}
rig='"name":"test-labmode-opns","type":"lxc","node":"nodeA","vmid":901'
fixture "[{$rig,\"status\":\"stopped\",\"tags\":\"disposable;protected\"}]"; refuses "protected+disposable" start test-labmode-opns
fixture "[{$rig,\"status\":\"stopped\",\"tags\":\"protected\"}]";            refuses "protected only" start test-labmode-opns
fixture "[{$rig,\"status\":\"stopped\",\"tags\":\"\"}]";                    refuses "no tags" stop test-labmode-opns
fixture "[{$rig,\"status\":\"stopped\",\"tags\":\"notdisposable\"}]";       refuses "lookalike tag" start test-labmode-opns
fixture "[{$rig,\"status\":\"running\"}]";                                  refuses "tags absent" purge-credentials test-labmode-opns
fixture "[{\"name\":\"test-labmode-opns\",\"type\":\"qemu\",\"node\":\"nodeA\",\"vmid\":901,\"status\":\"stopped\",\"tags\":\"disposable\"}]"
refuses "a VM, not an LXC" start test-labmode-opns
fixture "[]";                                                               refuses "zero guests" start test-labmode-opns
fixture "[{$rig,\"status\":\"stopped\",\"tags\":\"disposable\"},{\"name\":\"test-labmode-opns\",\"type\":\"lxc\",\"node\":\"nodeA\",\"vmid\":902,\"status\":\"stopped\",\"tags\":\"disposable\"}]"
refuses "two guests" start test-labmode-opns
fixture "[{\"name\":\"test-labmode-opns\",\"type\":\"lxc\",\"node\":\"nodeB\",\"vmid\":901,\"status\":\"stopped\",\"tags\":\"disposable\"}]"
refuses "guest on another node" start test-labmode-opns
fixture "[{$rig,\"status\":\"stopped\",\"tags\":\"disposable\"}]";           refuses "not a rig name" start some-other-guest
fixture "[{$rig,\"status\":\"stopped\",\"tags\":\"disposable\"}]";           refuses "purge a stopped rig" purge-credentials test-labmode-opns

fixture "[{$rig,\"status\":\"stopped\",\"tags\":\"disposable\"}]"
[ "$(run vmid test-labmode-opns)" = 901 ] || { echo "FAIL vmid"; exit 1; }
run start test-labmode-opns >/dev/null
grep -q 'pct start 901' "$work/guest-calls" || { echo "FAIL start did not run pct start 901"; exit 1; }
echo "ok   disposable, unprotected LXC: start proceeded ($(grep -c . "$work/guest-calls") guest commands)"
fixture "[{$rig,\"status\":\"running\",\"tags\":\"disposable;lab\"}]"
run purge-credentials test-labmode-opns >/dev/null
grep -q 'rm -rf /etc/rustopnsmcp/credentials' "$work/guest-calls" || { echo "FAIL purge did not remove credentials"; exit 1; }
grep -q 'rm -f /etc/rustopnsmcp/devices.json' "$work/guest-calls" || { echo "FAIL purge did not remove devices.json"; exit 1; }
echo "ok   purge-credentials proceeded for a running disposable rig"
echo "rig-ctl evidence: PASS"
