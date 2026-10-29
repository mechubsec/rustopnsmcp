# rustopnsmcp filesystem layout

Where the LXC/systemd package puts things, who owns them, and why. The unit
(`packaging/systemd/rustopnsmcp.service`), the sysusers file and the tmpfiles
file are the source of truth; this page explains them.

The service user, the group and the directory base are all `rustopnsmcp`, the
full binary name. The sibling servers use a shortened base (`jmcp`,
`proxmoxmcp`, `unifimcp`); this one does not, so do not carry paths over from
them.

## Layout

```
/etc/rustopnsmcp/                  0750 root:rustopnsmcp   configuration, read-only to the service
├── devices.json                   0600 rustopnsmcp:rustopnsmcp
├── audit-hmac.key                 0600 rustopnsmcp:rustopnsmcp
├── credentials.env                0600 rustopnsmcp:rustopnsmcp
└── *.pem                          CA certificates (and TLS cert/key if the site uses them)

/var/lib/rustopnsmcp/              0700 rustopnsmcp:rustopnsmcp   state, the only path the service can write
├── tokens.json                    0600 rustopnsmcp:rustopnsmcp
├── changeset-state.json           0600 rustopnsmcp:rustopnsmcp
└── audit.jsonl                    0600 rustopnsmcp:rustopnsmcp   only if --audit-log-file is set
```

| Path | Owner:group | Mode | Written by |
|---|---|---|---|
| `/etc/rustopnsmcp` | `root:rustopnsmcp` | `0750` | tmpfiles |
| `/etc/rustopnsmcp/devices.json` | `rustopnsmcp:rustopnsmcp` | `0600` | operator, as root |
| `/etc/rustopnsmcp/audit-hmac.key` | `rustopnsmcp:rustopnsmcp` | `0600` | installer, once |
| `/etc/rustopnsmcp/credentials.env` | `rustopnsmcp:rustopnsmcp` | `0600` | operator, as root |
| `/var/lib/rustopnsmcp` | `rustopnsmcp:rustopnsmcp` | `0700` | tmpfiles, `StateDirectory=` |
| `/var/lib/rustopnsmcp/tokens.json` | `rustopnsmcp:rustopnsmcp` | `0600` | the `token` subcommands, then the service |
| `/var/lib/rustopnsmcp/changeset-state.json` | `rustopnsmcp:rustopnsmcp` | `0600` | the service |
| `/var/lib/rustopnsmcp/audit.jsonl` | `rustopnsmcp:rustopnsmcp` | `0600` | the service (optional) |

`devices.json` is owned by the service user so the service can read it at
mode 0600 (the global P2 decision). It is still not writable by the service:
its directory is `root`-owned and the unit makes `/etc` read-only.

Check it on a running guest:

```sh
stat -c '%a %U:%G %n' /etc/rustopnsmcp /etc/rustopnsmcp/* /var/lib/rustopnsmcp /var/lib/rustopnsmcp/*
```

## Why `tokens.json` and `changeset-state.json` are under `/var/lib`

The service rewrites both files atomically: it writes a temp file in the same
directory and renames it over the target. That needs a writable directory.
`/etc/rustopnsmcp` is not one: the unit sets `ProtectSystem=strict`, which
mounts the whole filesystem read-only, and `ReadWritePaths=/var/lib/rustopnsmcp`
re-opens only the state directory. Putting either file under `/etc` would fail
on the first write.

Keeping `/etc/rustopnsmcp` read-only is also deliberate. The device inventory
and the credentials can only change by a root edit, so nothing the server could
be talked into doing changes which devices it talks to.

## Why `audit-hmac.key` is under `/etc`

It is created once and never rewritten. The LXC installer generates it when it
is absent. If the installer was skipped, the binary creates it at startup, only
when nothing exists at that path: 32 random bytes written to a temp file in the
same directory, fsynced, then published by hard link, so an existing key is
never replaced and the final path never holds a partial key.

An existing key is not trusted blindly. The server refuses to start if the key
is a symlink, is not a regular file, is readable by group or other, or is not
owned by the service user. A root-owned key is refused too: the service runs
non-root, and the root exception only applies to a process that is itself root.
The error names `chmod 600` and `chown`.
Fix it with:

```sh
chown rustopnsmcp:rustopnsmcp /etc/rustopnsmcp/audit-hmac.key
chmod 600 /etc/rustopnsmcp/audit-hmac.key
```

Never regenerate a key that has been used: audit records already written under
it can no longer be matched to the same device pseudonyms.

Creating the key at startup needs a writable directory. Under the stock unit
`/etc/rustopnsmcp` is read-only, so the installer is the only thing that can
create it there. In a container there is no `/etc` to protect: the key lives in
the state volume (`/var/lib/rustopnsmcp/audit-hmac.key`), the only writable
mount, and the binary creates it on first start.

## sysusers and tmpfiles

`packaging/systemd/rustopnsmcp.sysusers`, installed as
`/usr/lib/sysusers.d/rustopnsmcp.conf`:

```
u rustopnsmcp - "rustopnsmcp service" /var/lib/rustopnsmcp /usr/sbin/nologin
```

`packaging/systemd/rustopnsmcp.tmpfiles`, installed as
`/usr/lib/tmpfiles.d/rustopnsmcp.conf`:

```
d /etc/rustopnsmcp 0750 root rustopnsmcp -
d /var/lib/rustopnsmcp 0700 rustopnsmcp rustopnsmcp -
```

The installer applies them with:

```sh
systemd-sysusers /usr/lib/sysusers.d/rustopnsmcp.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/rustopnsmcp.conf
```

The tmpfiles lines set the directories only. Files are created by the
installer (`tokens.json` as `{"version":1,"tokens":[]}`, `audit-hmac.key`) and
by the operator (`devices.json`, `credentials.env`), then given the modes in
the table above. The installer never overwrites an existing state file.
