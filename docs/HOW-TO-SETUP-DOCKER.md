# Set up rustopnsmcp in Docker

Run the published image, or one you build yourself, with a device inventory and
a bearer token. Commands are POSIX shell. For the LXC/systemd install see
[HOW-TO-SETUP-LXC.md](HOW-TO-SETUP-LXC.md); for audit records see the
[operations guide](OPERATIONS.md) and [AUDIT.md](AUDIT.md) (the container
differs only where this page says so).

> **Under construction.** No version has been released, so the published
> images below do not exist yet. Until the first tag, build the image locally
> (see Building locally) and set `image=rustopnsmcp:local`.

## Docker

Images are published on every version tag to two registries:

| Registry | Image |
|---|---|
| GitHub Container Registry | `ghcr.io/mechubsec/rustopnsmcp` |
| Docker Hub | `docker.io/mechub/rustopnsmcp` |

Tags are `<version>` (for example `1.0.0`), `<major>.<minor>` and `latest`. The
examples below use one shell variable so you can swap the image in one place;
pin a version, or a digest you reviewed, in production:

```sh
image=ghcr.io/mechubsec/rustopnsmcp:latest
```

### Prerequisites

- Docker 20.10 or later, or a compatible runtime.
- `curl` and `openssl` on the host (health checks and the TLS example).
- Host paths for configuration and state, created below.

Every release image is signed keyless with cosign by the release workflow.
With `cosign` installed, verify before running (use a real version in place of
`<version>`):

```sh
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/mechubsec/mecmcp/\.github/workflows/reusable-release-image\.yml@' \
  ghcr.io/mechubsec/rustopnsmcp:<version>

cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/mechubsec/mecmcp/\.github/workflows/reusable-release-image\.yml@' \
  docker.io/mechub/rustopnsmcp:<version>
```

### Prepare host directories

The container runs as uid and gid **65532:65532** and has no shell. A bind
mount carries the host's uid straight through, so files you create as yourself
cannot be read, and directories cannot be written, by the container. Create
what you need, then hand it over.

An empty inventory lets the server start; add your device in the next step.

```sh
mkdir -p config state
printf '%s\n' '{"version":1,"devices":{}}' > config/devices.json
```

To add an OPNsense device, write it into `config/devices.json` instead. The key
and secret come from environment variables named in the file, and you supply
the values from an env file kept outside any repository:

```sh
cat > config/devices.json <<'JSON'
{
  "version": 1,
  "devices": {
    "fw-1": {
      "endpoint": "https://fw-1.example.org",
      "api_key_env": "OPNSENSE_FW_1_API_KEY",
      "api_secret_env": "OPNSENSE_FW_1_API_SECRET"
    }
  }
}
JSON
printf '%s\n' 'OPNSENSE_FW_1_API_KEY=replace-with-the-api-key' \
  'OPNSENSE_FW_1_API_SECRET=replace-with-the-api-secret' > credentials.env
chmod 0600 credentials.env
```

If the device presents a certificate from a private CA, copy the CA's PEM into
`config/` and add `"ca_pem_path": "/etc/rustopnsmcp/<file>.pem"` to the
device. There is no option to skip TLS verification.

Now give the container ownership. The **directories** must be writable too, not
just the files: `token add` and the server's state writes go through a temp file
in the same directory. Run this immediately before the first `docker run` below
(and again after you add files to `config/` as yourself):

```sh
sudo chown -R 65532:65532 config state
sudo chmod 0750 config
sudo chmod 0700 state
sudo chmod 0600 config/devices.json
```

If you skip it, the next step fails with
`Error: token file /var/lib/rustopnsmcp/tokens.json: Permission denied (os error 13) at path "/var/lib/rustopnsmcp/.tokens-XXXXXX.tmp"`,
and the server itself fails with `--audit-hmac-key-file
/var/lib/rustopnsmcp/audit-hmac.key: cannot create the key: Permission denied`.

### Run

Mint a token first. The image's entrypoint already carries the config paths, so
only the subcommand is yours. This creates `state/tokens.json` (a server start
without it fails with `No such file or directory`). The secret is printed once;
store it:

```sh
docker run --rm \
  -v "$PWD/config:/etc/rustopnsmcp:ro" \
  -v "$PWD/state:/var/lib/rustopnsmcp" \
  "$image" token add \
  --tokens-file /var/lib/rustopnsmcp/tokens.json \
  --name operator --devices '*' --tools '*'
```

`--devices` and `--tools` are both required. `'*'` is everything, which for
tools means every read tool and none of the mutating ones (those must be named),
so prefer the exact names the caller needs. Now start the server:

```sh
docker run -d --name rustopnsmcp \
  --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=64m,mode=1777 \
  --env-file credentials.env \
  -p 127.0.0.1:30037:30037 \
  -v "$PWD/config:/etc/rustopnsmcp:ro" \
  -v "$PWD/state:/var/lib/rustopnsmcp" \
  "$image" \
  --transport streamable-http --host 0.0.0.0 --port 30037 \
  --allow-insecure-bind \
  --allowed-host localhost:30037 --allowed-origin http://localhost:30037
```

Things that are different from a plain install:

- **Arguments you pass replace the image's default `CMD`, not its
  `ENTRYPOINT`.** The config paths, `--state-file`, `--inventory-readonly` and
  the audit flags are in the entrypoint and always apply. The default `CMD` is
  loopback-only (`--host 127.0.0.1`), which cannot be reached through a
  published port, so you restate `--transport`, `--host` and `--port`.
- **Binding `0.0.0.0` inside the container is required to publish the port.**
  The publish above keeps the host side on loopback. Because the bind is not
  loopback, the server refuses to start without `--allowed-host` and
  `--allowed-origin`, and without TLS it also needs `--allow-insecure-bind`
  (acceptable here only because the host side is loopback). Use the values
  clients actually dial.
- **Audit is `--audit-format json`, not `--audit-journald`.** A container has no
  journald socket. Records go to stdout for the container runtime to collect
  (`docker logs rustopnsmcp`). The keyed redaction of device names is still on:
  the image runs with `--audit-redact devices=hmac`.
- **The audit key is created in the state volume on first start**
  (`state/audit-hmac.key`, 32 bytes, mode 0600). Back it up with the state:
  without it, old device pseudonyms cannot be related to current ones.
- **`/etc/rustopnsmcp` is read-only to the container** (`:ro`), as in the LXC
  install, so the inventory changes only when you edit the file on the host.
  After editing it, reload without restarting; `docker restart` is not needed:

  ```sh
  docker kill --signal=HUP rustopnsmcp
  docker logs rustopnsmcp 2>&1 | grep -E 'reloaded|rebuilt'
  ```

  Environment variables are fixed at container start. To change a key or
  secret, recreate the container with the new env file.

Stop and remove it with `docker rm -f rustopnsmcp`.

### TLS

For remote clients, serve HTTPS. Create a certificate (a self-signed one is for
testing; use your CA's for real), then give the container the files. The key
goes in `config/`, which the container mounts read-only:

```sh
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout server.key -out server.crt -days 365 \
  -subj "/CN=rustopnsmcp.example.org" \
  -addext "subjectAltName=DNS:rustopnsmcp.example.org"
sudo cp server.key server.crt config/
sudo chown 65532:65532 config/server.key config/server.crt
sudo chmod 0600 config/server.key
sudo chmod 0644 config/server.crt
rm server.key
```

Start it without `--allow-insecure-bind`, and with the names and origins your
clients use. This publishes on every host interface; write
`-p <host address>:30037:30037` to bind one:

```sh
docker rm -f rustopnsmcp
docker run -d --name rustopnsmcp \
  --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=64m,mode=1777 \
  --env-file credentials.env \
  -p 30037:30037 \
  -v "$PWD/config:/etc/rustopnsmcp:ro" \
  -v "$PWD/state:/var/lib/rustopnsmcp" \
  "$image" \
  --transport streamable-http --host 0.0.0.0 --port 30037 \
  --tls-cert /etc/rustopnsmcp/server.crt --tls-key /etc/rustopnsmcp/server.key \
  --allowed-host rustopnsmcp.example.org:30037 \
  --allowed-origin https://console.example.org
```

`--allowed-host` must match the `host:port` in the client's URL (a request with
any other `Host` gets a 421, `Host '…' is not allowed`), and `--allowed-origin`
the browser origin (otherwise a 403, `Origin '…' is not allowed`). Both are
required for any non-loopback bind.

### Compose

[`packaging/container/compose.example.yaml`](../packaging/container/compose.example.yaml)
is the same deployment as Compose: read-only root, all capabilities dropped,
uid 65532, loopback publish, and the entrypoint's flags left alone. Its header
lists the directory preparation, which is the section above. From a checkout of
this repository, copy it next to `config/`, `state/` and `credentials.env`, set
the image (a digest for production), and start it:

```sh
cp packaging/container/compose.example.yaml compose.yaml
docker compose up -d
docker compose ps
```

The `env_file` it names must exist, or Compose refuses to start.

### Health check

The image has no `HEALTHCHECK`: it is distroless, with no shell or `curl` to
run one, and `docker ps` shows only whether the process is up. Probe from the
host (use `https://`, `--cacert server.crt` and the TLS name when TLS is on):

```sh
curl -fsS http://127.0.0.1:30037/healthz
curl -fsS http://127.0.0.1:30037/readyz
```

`/healthz` returns `ok`; `/readyz` returns `{"status":"ok"}`, or 503 naming
`opnsense_auth` while a device is rejecting the API key. Put these in your
orchestrator's probe. See [OPERATIONS.md](OPERATIONS.md) for what each means.

### Platform notes

The images are `linux/amd64` only. On Apple Silicon they run under emulation;
add `--platform linux/amd64` to `docker pull` and `docker run` if Docker warns
about a platform mismatch. Building locally for your own architecture is faster.

### Building locally

```sh
docker build -t rustopnsmcp:local .
image=rustopnsmcp:local
docker run --rm "$image" --version
```

The `Dockerfile` is at the repository root and builds with the pinned Rust
toolchain, so it needs network access to pull its base images and crates. Use
the `image=` value above in every command in this guide.
