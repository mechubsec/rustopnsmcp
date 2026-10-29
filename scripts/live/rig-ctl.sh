#!/usr/bin/env bash
# Control a P3 test rig (a disposable LXC) from the workstation.
#   rig-ctl.sh check|start|stop <rig>      evidence check, then start or stop the guest
#   rig-ctl.sh svc <rig> <verb>            systemctl <verb> rustopnsmcp inside the rig
#   rig-ctl.sh reset-state <rig>           stop the service, delete its change-set state, start it
#   rig-ctl.sh purge-credentials <rig>     stop the service, delete the lab credentials and devices.json
#   rig-ctl.sh vmid <rig>                  print the guest id on stdout (for other scripts)
# <rig> is test-twoperson-opns or test-labmode-opns. Needs RIG_PVE: the ssh alias of the node hosting them.
set -euo pipefail
action="${1:?check|start|stop|svc|reset-state|purge-credentials|vmid}"; name="${2:?rig name}"
case "$name" in test-twoperson-opns|test-labmode-opns) ;; *) echo "not a P3 rig: $name" >&2; exit 2 ;; esac
: "${RIG_PVE:?}"
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=scripts/live/rig-lib.sh
. "$here/rig-lib.sh"
require_match RIG_PVE "$RIG_PVE" "$alias_re"
# Resolve the name to a guest and its tags every time; ids get recycled.
info=$(ssh -n "$RIG_PVE" pvesh get /cluster/resources --type vm --output-format json | NAME="$name" python3 -I -c '
import json, os, sys
rows = [r for r in json.load(sys.stdin) if r.get("name") == os.environ["NAME"]]
if len(rows) != 1:
    sys.exit("expected exactly one guest named %s, found %d" % (os.environ["NAME"], len(rows)))
guest = rows[0]
tags = [t.strip() for t in (guest.get("tags") or "").replace(",", ";").split(";")]
if guest.get("type") != "lxc" or "protected" in tags or "disposable" not in tags:
    sys.exit("refusing: %s must be a disposable, unprotected LXC (tags: %s)" % (guest["name"], ";".join(tags)))
print(guest["vmid"], guest["node"], guest["status"])')
read -r vmid node status <<<"$info"
require_match "guest id" "$vmid" '^[0-9]{1,10}$'
[ "$node" = "$(ssh -n "$RIG_PVE" hostname -s)" ] || { echo "$name is on $node, not on the node $RIG_PVE reaches" >&2; exit 1; }
echo "$name: node $node, $status, tags include disposable and not protected" >&2
inrig() { ssh -n "$RIG_PVE" pct exec "$vmid" -- "$@"; }
need_running() { [ "$status" = running ] || { echo "$name is $status; start it first" >&2; exit 1; }; }
case "$action" in
  vmid) echo "$vmid" ;;
  check) ;;
  start)
    # shellcheck disable=SC2029 # vmid is resolved locally on purpose
    [ "$status" = running ] || ssh -n "$RIG_PVE" pct start "$vmid"
    for _ in $(seq 30); do
      [ -n "$(inrig hostname -I 2>/dev/null | tr -d ' \n')" ] && exit 0
      sleep 2
    done
    echo "$name has no address after 60 s" >&2; exit 1 ;;
  stop) [ "$status" = stopped ] || ssh -n "$RIG_PVE" pct shutdown "$vmid" --timeout 30 ;;
  svc)
    case "${3:?verb}" in start|stop|restart|reload|status|is-active) ;; *) echo "verb not allowed: $3" >&2; exit 2 ;; esac
    need_running; inrig systemctl "$3" rustopnsmcp ;;
  reset-state)
    need_running
    inrig systemctl stop rustopnsmcp
    inrig rm -f /var/lib/rustopnsmcp/changeset-state.json
    inrig systemctl start rustopnsmcp ;;
  purge-credentials)
    need_running
    inrig systemctl stop rustopnsmcp || true
    inrig rm -rf /etc/rustopnsmcp/credentials
    inrig rm -f /etc/rustopnsmcp/devices.json
    inrig test ! -e /etc/rustopnsmcp/credentials
    inrig test ! -e /etc/rustopnsmcp/devices.json
    echo "$name: lab credentials and devices.json removed; service stopped" >&2 ;;
  *) echo "unknown action $action" >&2; exit 2 ;;
esac
