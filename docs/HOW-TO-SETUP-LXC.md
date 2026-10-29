# Set up rustopnsmcp in a Debian 13 LXC

This takes a fresh Proxmox LXC to a running, token-protected `rustopnsmcp`
service. Commands run in a shell on the guest as root unless a step says
otherwise. Replace `<vmid>` and `<version>` where they appear. For day-two work
(reload, upgrade, audit) see [OPERATIONS.md](OPERATIONS.md); for who owns which
file see [FILESYSTEM.md](../packaging/FILESYSTEM.md).

> **Under construction.** No release exists yet, so the download step below has
> nothing to fetch until the first version tag is published.

## 1. The container

Use Debian 13, **unprivileged**, with **nesting enabled**. Without `nesting=1`,
systemd 257 inside the guest comes up `degraded` with three failed mounts.
Enable it from the Proxmox host and restart the guest:

```sh
pct set <vmid> --features nesting=1
pct reboot <vmid>
```

Size: 1 vCPU, 256 MB RAM, 1 GB disk. The guest needs HTTPS to the OPNsense
API. Inside the guest, make sure the download tools exist:

```sh
apt-get update && apt-get install -y curl ca-certificates
```

## 2. Download and verify

The archive is `rustopnsmcp-v<version>-x86_64-unknown-linux-gnu.tar.gz`, with a
`.sha256` file beside it. The checksum file names the bare archive, so check it
from the directory you downloaded into:

```sh
version=<version>
archive=rustopnsmcp-v${version}-x86_64-unknown-linux-gnu.tar.gz
base=https://github.com/mechubsec/rustopnsmcp/releases/download/v${version}
curl -fsSLO "$base/$archive"
curl -fsSLO "$base/$archive.sha256"
sha256sum -c "$archive.sha256"
```

`sha256sum` must print `<archive>: OK`. The release also carries a keyless
cosign signature, `$archive.cosign.bundle`. If you have `cosign`, check that
the archive was signed by the release workflow:

```sh
curl -fsSLO "$base/$archive.cosign.bundle"
cosign verify-blob --bundle "$archive.cosign.bundle" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/mechubsec/mecmcp/\.github/workflows/reusable-sign-release-tarball\.yml@' \
  --certificate-github-workflow-repository mechubsec/rustopnsmcp \
  "$archive"
```

## 3. Install

Extract the archive and run **its** installer from the extracted root:

```sh
tar -xzf "$archive"
cd rustopnsmcp-v${version}
packaging/lxc/install.sh
```

The installer checks the package first (required files, `BUILD-INFO`, the
binary's checksum, the SBOM, and that the host glibc is new enough), and
changes nothing if any check fails. It then creates the `rustopnsmcp` user, the
directories, a bootable empty `devices.json`, `credentials.env`, `tokens.json`
and the audit key, installs the binary and the unit, and prints next steps. It
never enables or starts the service, and it never overwrites an existing
`tokens.json`, `changeset-state.json`, `devices.json`, `credentials.env` or
`audit-hmac.key`. If one of those exists with the wrong owner or mode it
refuses and tells you the `chown`/`chmod` to run; it does not change your file.

## 4. Configure

Edit the device inventory. `devices.example.json` beside it shows the shape: an
`endpoint`, an API key and secret (each from an environment variable or an
owner-only file) and, for a private CA, `ca_pem_path`. There is no option to
skip TLS verification.

```sh
$EDITOR /etc/rustopnsmcp/devices.json
```

Put the OPNsense API key and secret (System > Access > Users > API keys) in
`credentials.env`, under the variable names the inventory's `api_key_env` and
`api_secret_env` give:

```sh
$EDITOR /etc/rustopnsmcp/credentials.env
stat -c '%a %U:%G %n' /etc/rustopnsmcp/devices.json /etc/rustopnsmcp/credentials.env
```

Both files must show `600 rustopnsmcp:rustopnsmcp`. If you replaced one with a
new file, run `chown rustopnsmcp:rustopnsmcp` and `chmod 600` on it.

## 5. Mint the first token

Run `token add` as the service user, not as root. A root run leaves a
root-owned `tokens.json` that the service cannot read (see Troubleshooting).
`runuser` is part of util-linux, so it exists on a minimal guest; the
installer's printed hint uses it too, and shows a read-only token and one that
names the write tools and the reads they need.

```sh
runuser -u rustopnsmcp -- /usr/local/bin/rustopnsmcp token add \
  --tokens-file /var/lib/rustopnsmcp/tokens.json \
  --name operator --devices '*' --tools '*'
```

Use the absolute binary path: a root shell without `/usr/local/bin` on `PATH`
(`pct exec`, some `sudo`/`su` setups) fails with `runuser: failed to execute
rustopnsmcp: No such file or directory`.

To create, approve and apply change sets, the token must name the write tools
and the reads the workflow needs; `create_opnsense_change_set` takes the
`expected_fingerprint` from `get_opnsense_config_fingerprint`. A tool list is
exact, so `'*'` cannot be mixed with names:

```sh
runuser -u rustopnsmcp -- /usr/local/bin/rustopnsmcp token add \
  --tokens-file /var/lib/rustopnsmcp/tokens.json \
  --name changer --devices '*' \
  --tools 'get_opnsense_config_fingerprint,get_opnsense_change_set_status,list_opnsense_change_sets,create_opnsense_change_set,approve_opnsense_change_set,apply_opnsense_change_set,confirm_opnsense_change_set,cancel_opnsense_change_set'
```

The secret is printed once, on stdout. Store it now; only a digest is kept.
`--devices` and `--tools` are both required. `'*'` means everything, which for
tools is every read tool and none of the mutating ones (create, approve, apply,
confirm and cancel a change set, `add_device`, `reload_devices`): those must be
named. Prefer the exact device and tool names the caller needs. The token is a bearer
token; MCP clients send it as `Authorization: Bearer <secret>`. List tokens
with `token list --tokens-file …` (names and scopes only).

## 6. Start and check

```sh
systemctl start rustopnsmcp
curl -fsS http://127.0.0.1:30037/readyz
systemctl enable rustopnsmcp
```

`/readyz` prints `{"status":"ok"}`. The stock unit listens on loopback only,
over plain HTTP. If `systemctl start` fails, `journalctl -u rustopnsmcp -n 20
--no-pager` shows why; the Troubleshooting section lists the usual causes.

## 7. Listen on the network: the site override

To bind a non-loopback address, add TLS, or restrict allowed hosts, do not edit
the packaged unit: the installer replaces it on every upgrade. Put the change in
a drop-in. Copy the shipped example and edit it:

```sh
install -d /etc/systemd/system/rustopnsmcp.service.d
cp packaging/systemd/rustopnsmcp.override.conf.example \
  /etc/systemd/system/rustopnsmcp.service.d/override.conf
$EDITOR /etc/systemd/system/rustopnsmcp.service.d/override.conf
```

The example is below, and `scripts/check-docs.sh` fails if this block differs
from the shipped file:

<!-- override-example:start -->
```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/rustopnsmcp \
    --device-mapping /etc/rustopnsmcp/devices.json \
    --tokens-file /var/lib/rustopnsmcp/tokens.json \
    --state-file /var/lib/rustopnsmcp/changeset-state.json \
    --inventory-readonly \
    --transport streamable-http \
    --host 192.0.2.10 --port 30037 \
    --allowed-host rustopnsmcp.example.org:30037 \
    --allowed-host 192.0.2.10:30037 \
    --allowed-origin https://console.example.org \
    --tls-cert /etc/rustopnsmcp/fullchain.pem \
    --tls-key /etc/rustopnsmcp/privkey.pem \
    --audit-format json \
    --audit-journald \
    --audit-redact devices=hmac \
    --audit-hmac-key-file /etc/rustopnsmcp/audit-hmac.key
```
<!-- override-example:end -->

What to change for your site:

- `--host`: the guest's own address (the example uses a documentation address).
- `--allowed-host`: every `host:port` a client will dial, one flag each. Clients
  whose `Host` header is not listed get a 421.
- `--allowed-origin`: every browser origin that may call the server. An origin
  not listed gets a 403. A non-loopback bind refuses to start without at least
  one `--allowed-host` and one `--allowed-origin`.
- `--tls-cert` and `--tls-key`: leave them for HTTPS. Without them a
  non-loopback bind also needs `--allow-insecure-bind`, which sends the bearer
  token in clear text; do not do that on a network you do not control.

**The empty `ExecStart=` line is required.** A drop-in can only add to
`ExecStart`, and a service of this type may have only one, so systemd would
refuse the unit with `Service has more than one ExecStart= setting, which is
only allowed for Type=oneshot services`. The empty assignment clears the
packaged command, and the line after it replaces it. That is also why the
example restates every flag of the stock unit: if you drop one, such as
`--inventory-readonly` or the audit flags, the server runs without it.

Put the TLS files where the service can read them, owned by the service user
with mode `0600`:

```sh
install -o rustopnsmcp -g rustopnsmcp -m 0600 -t /etc/rustopnsmcp fullchain.pem privkey.pem
```

Apply and check it. Use `https://` and your CA once TLS is on:

```sh
systemctl daemon-reload
systemctl restart rustopnsmcp
systemctl cat rustopnsmcp
curl -fsS --cacert /etc/rustopnsmcp/fullchain.pem https://rustopnsmcp.example.org:30037/readyz
```

`systemctl cat` must show the packaged unit followed by `override.conf`. The
`curl` runs from a host that resolves that name to the guest; drop `--cacert` if
the certificate chains to a public CA.

### Lab mode

`--lab-mode` waives the second-person approval for change sets. It is for a
single-operator lab only, and belongs in the override, never the stock unit. Add
one line to the override's `ExecStart`, after `--inventory-readonly \`:

```ini
    --lab-mode \
```

Then `systemctl daemon-reload && systemctl restart rustopnsmcp`. Waived change
sets record `approver: null` and `approval_waiver: "lab-mode"`, and the log has
a startup warning: `journalctl -u rustopnsmcp -b | grep 'lab mode is enabled'`.

## 8. Journal persistence and forwarding

The audit trail goes to journald (`--audit-journald`). In an unprivileged LXC
there is no Forward Secure Sealing, so the integrity control is getting the
records off the guest before an attacker on it can rewrite them. Set this up at
provisioning, not after an incident.

The installer already makes the journal persistent
(`/etc/systemd/journald.conf.d/20-audit-retention.conf`: `Storage=persistent`,
`SystemMaxUse=512M`), unless a file of that name existed. To forward it, install
the uploader and point it at your collector:

```sh
apt-get install -y systemd-journal-remote
printf '[Upload]\nURL=https://logs.example.org:19532\n' > /etc/systemd/journal-upload.conf
systemctl enable --now systemd-journal-upload
systemctl status systemd-journal-upload --no-pager
```

The collector must run `systemd-journal-remote` (or accept its protocol);
use the TLS options in `journal-upload.conf(5)` for anything off the guest's own
network. `rsyslog` with the `imjournal` input is an alternative if your
collector speaks syslog; this guide does not configure it. What the records
contain is in [AUDIT.md](AUDIT.md); the threats they answer are in
[THREAT-MODEL.md](THREAT-MODEL.md).

## 9. Upgrade

Snapshot the guest first, then run the new archive's installer and restart:

```sh
pct snapshot <vmid> pre-upgrade
```

That one runs on the Proxmox host. Then, on the guest, extract the new archive
as in step 3 and:

```sh
packaging/lxc/install.sh
systemctl restart rustopnsmcp
/usr/local/bin/rustopnsmcp --version
```

State, secrets and your `override.conf` are untouched. Re-check the override
against the new stock unit, since a new stock flag does not reach it
automatically. [OPERATIONS.md](OPERATIONS.md) has the details.

## Troubleshooting

Each message below is what the binary or the server prints.

| You see | Cause and fix |
|---|---|
| `Error: non-loopback bind '192.0.2.10' requires at least one --allowed-host (the accepted HTTP Host authority, e.g. server.example.org:8443)` | `--host` is not loopback. Add `--allowed-host <name>:<port>` for each name clients dial. |
| `Error: non-loopback bind '192.0.2.10' requires at least one --allowed-origin (the accepted browser Origin, e.g. https://server.example.org:8443)` | Add `--allowed-origin https://<client origin>`. |
| `Error: non-loopback bind '192.0.2.10' over plain HTTP requires --allow-insecure-bind (or supply --tls-cert/--tls-key)` | Add `--tls-cert` and `--tls-key` (preferred), or accept plain HTTP knowingly with `--allow-insecure-bind`. |
| HTTP 421, `Host 'x' is not allowed` | The client's `Host` header is not in any `--allowed-host`. Add the exact `host:port` it uses. |
| HTTP 403, `Origin 'x' is not allowed` | The request's `Origin` is not in any `--allowed-origin`. Add it. |
| HTTP 401, `invalid bearer token` | Wrong, revoked or not-yet-loaded token. After `token add` while the service runs, send SIGHUP (`systemctl kill --kill-whom=main --signal=HUP rustopnsmcp.service`) or pass `--server-pid`. |
| `Error: token file /var/lib/rustopnsmcp/tokens.json: Permission denied (os error 13)` | The file is not owned by `rustopnsmcp` (usually `token add` was run as root). `chown rustopnsmcp:rustopnsmcp /var/lib/rustopnsmcp/tokens.json && chmod 600 /var/lib/rustopnsmcp/tokens.json`. |
| `--audit-hmac-key-file …: existing key is unsafe` | Wrong owner or mode on `audit-hmac.key`; see [FILESYSTEM.md](../packaging/FILESYSTEM.md). |
| Installer: `<path> is root:root 600, expected rustopnsmcp:rustopnsmcp 600; fix with: chown …` | A file you own has the wrong owner or mode. Run the `chown`/`chmod` it prints and re-run the installer. |
| `Service has more than one ExecStart= setting …` | The override is missing the empty `ExecStart=` line. |
| `systemctl is-system-running` says `degraded` | The container lacks `nesting=1` (step 1). |
