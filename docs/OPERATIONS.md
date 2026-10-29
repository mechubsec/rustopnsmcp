# Operating rustopnsmcp

Day-two tasks for the LXC/systemd install. Paths are those in
`packaging/FILESYSTEM.md`. Each section ends with a command that shows the
claim holds on your guest.

## Reloading with SIGHUP

A SIGHUP reloads the following. The device clients are swapped under a lock, so
calls already in flight finish on the old clients:

- the device inventory (`devices.json`), then rebuilds the HTTP client for
  every device from it. Credentials named as `*_file` and the CA file named by
  `ca_pem_path` are read again;
  credentials named as `*_env` are not, because the environment is fixed when
  the process starts (restart to change those);
- the token store (`--tokens-file`);
- the audit file, reopened, if `--audit-log-file` is set (this is what logrotate
  uses).

It does not reload command-line flags, TLS certificate and key
(`--tls-cert`, `--tls-key`), the HMAC key, or the unit. Those need
`systemctl restart rustopnsmcp`.

A bad reload keeps the previous snapshot and logs a warning; it never leaves the
server without an inventory. A reload also builds new device clients, so the
`/readyz` authentication state returns to healthy until the next call to a
device (see Health and readiness).

```sh
systemctl kill --kill-whom=main --signal=HUP rustopnsmcp.service
journalctl -u rustopnsmcp -n 20
```

Expect `device inventory reloaded`, `HTTP clients rebuilt from reloaded
inventory` and `token store reloaded`, plus `audit file reopened` when an audit
file is configured. Each part that fails keeps its old state and logs one of:

- `device inventory reload failed; retaining previous snapshot` (the client
  rebuild is then skipped);
- `client rebuild failed; retaining previous clients` (the old clients keep the
  old credentials and CA);
- `token store reload failed; retaining previous snapshot`;
- `audit file reopen failed`.

To check one reload on its own, stamp the time before sending the signal, so an
older failure still in the journal is not mistaken for this one. This is
`sh` syntax, wrapped so it also pastes into fish:

```sh
sh -c 'since=$(date "+%Y-%m-%d %H:%M:%S"); systemctl kill --kill-whom=main --signal=HUP rustopnsmcp.service; sleep 2; journalctl -u rustopnsmcp --since "$since" --no-pager | grep -E "reloaded|rebuilt|reopened|reload failed|rebuild failed|reopen failed"'
```

A good reload prints `device inventory reloaded`, `HTTP clients rebuilt from
reloaded inventory` and `token store reloaded` (and `audit file reopened` if an
audit file is configured) and none of the four failure lines above. The unit
defines no `ExecReload`, so `systemctl reload` does not work; use the signal.

## `add_device` and `--inventory-readonly`

The stock unit runs with `--inventory-readonly`. `add_device` and
`reload_devices` return an error naming the flag; nothing is written. To add or
change a device, edit the file as root, keep the owner and mode, and send SIGHUP:

```sh
$EDITOR /etc/rustopnsmcp/devices.json
chown rustopnsmcp:rustopnsmcp /etc/rustopnsmcp/devices.json
chmod 600 /etc/rustopnsmcp/devices.json
systemctl kill --kill-whom=main --signal=HUP rustopnsmcp.service
stat -c '%a %U:%G' /etc/rustopnsmcp/devices.json
```

The last command must print `600 rustopnsmcp:rustopnsmcp`. A device uses
`endpoint`, an API key and secret (each from an environment variable or an
owner-only file) and `ca_pem_path`; see `packaging/examples/devices.example.json`.

## Lab mode

`--lab-mode` removes the second-person approval step for change sets. It exists
for a single-operator lab and is never part of a product install:

- it is a command-line flag only, never read from a config file;
- put it in the site override (`override.conf`), never in the stock unit;
- a waived change set records `approver: null` with `approval_waiver:
  "lab-mode"`, so it stays distinguishable from one a second person approved;
- the server logs a warning at startup.

Remember an override replaces `ExecStart` entirely: restate every stock flag
(see `packaging/systemd/rustopnsmcp.override.conf.example`).

```sh
journalctl -u rustopnsmcp -b | grep 'lab mode is enabled'
```

No output means lab mode is off.

## Health and readiness

- `GET /healthz` returns 200 `ok` while the process is up. It checks nothing else.
- `GET /readyz` returns 200 when ready and 503 with a JSON body listing the
  failed check, `opnsense_auth`, while any device's most recent API reply was
  401 (the key or secret is wrong or revoked). The body carries a fixed reason
  and no device name, because the endpoint is unauthenticated.

`/readyz` is passive: it makes no calls of its own. A quiet server, or one that
has not yet been asked anything, is ready. A 401 flips it to 503; the next 2xx
from that device clears it. A 403 (the key is valid but lacks a privilege) never
flips it. To make it re-test, call any read tool on the device, or reload as
above (which resets it to healthy rather than testing it).

Under the stock unit the listener is plain HTTP on loopback. With TLS in an
override, use `https://` and `--cacert` (or `-k` from the guest itself).

```sh
curl -fsS http://127.0.0.1:30037/healthz
curl -fsS http://127.0.0.1:30037/readyz
```

`curl -f` exits non-zero on 503. Without `-f`, the 503 body names `opnsense_auth`.

## Audit

The stock unit's baseline is:

```
--audit-format json --audit-journald --audit-redact devices=hmac \
--audit-hmac-key-file /etc/rustopnsmcp/audit-hmac.key
```

`--audit-redact devices=hmac` replaces device names in audit records with a keyed
hash (HMAC) so the trail does not carry them, yet the same device always maps to
the same pseudonym. The key is `/etc/rustopnsmcp/audit-hmac.key` (see
`packaging/FILESYSTEM.md`). Keep a copy with your backups: without it you
cannot relate old pseudonyms to current device names, and a new key breaks the
correlation with older records.

`--audit-journald` sends each record straight to the systemd journal. In an
unprivileged LXC that is the integrity control: the service cannot rewrite
records already handed to journald, and a file the service owns could be
rewritten by the service. Forward the journal off the guest to make that hold
if the guest itself is compromised.

The stock unit does not write an audit file. To also keep one, add
`--audit-log-file /var/lib/rustopnsmcp/audit.jsonl` to the override. It is
written by the service as JSON lines; rotate it with logrotate, which signals
the service (SIGHUP) so it reopens the file. The package ships a logrotate
snippet for this (Task 24; this paragraph is to be corrected if the shipped
snippet differs). The file is also under `/var/lib`, so it is covered by the
upgrade rules below.

```sh
journalctl -u rustopnsmcp -n 5 -o cat
```

Each line is one JSON audit record.

## Upgrading

1. Snapshot the guest first (Proxmox: `pct snapshot <vmid> pre-upgrade`). A
   snapshot is the rollback path; the installer has none of its own.
2. Run the installer from the new release tarball. It validates the package
   before changing the host.
3. `systemctl restart rustopnsmcp`. The installer never starts or enables the
   service.

The installer never overwrites `tokens.json`, `changeset-state.json`,
`devices.json`, `credentials.env` or `audit-hmac.key`. It replaces the unit file
and says so if the installed one differed from the packaged one; a site
`override.conf` is untouched, so re-check it against the new stock unit
(`packaging/tests/unit-contract.sh` does this for the shipped example).
This section describes the installer planned in Task 26 and is to be corrected
if the built installer behaves differently.

```sh
rustopnsmcp --version
systemctl status rustopnsmcp
```

## `IPAddressAllow` is not enforced in an unprivileged LXC

The unit sets `IPAddressDeny=any` with `IPAddressAllow` for loopback,
link-local and the RFC 1918 ranges. systemd accepts these and `systemctl show`
reports them, but in an unprivileged LXC guest it cannot attach the cgroup BPF
program that enforces them, so they do nothing. On a normal host or a privileged
container they do enforce. Do not treat them as active protection on an LXC.

Restrict what the service can reach at the guest's network edge instead: an
egress rule on your firewall allowing the guest to reach only the OPNsense
devices it manages. There is no command in this package that proves enforcement;
test it from the guest by trying a connection that policy should block.

```sh
systemctl show rustopnsmcp -p IPAddressDeny -p IPAddressAllow
```

This shows the configured values, not whether they are enforced.
