# Audit records

`rustopnsmcp` writes audit records through the shared `mecmcp-audit` crate.
This page says what a record contains, how device names are hidden in it, who
can read the key, and which flags send the trail somewhere else. For querying
it on a guest see [OPERATIONS.md](OPERATIONS.md#audit); for the threats it
answers see [THREAT-MODEL.md](THREAT-MODEL.md).

## What is recorded

Every tool call over HTTP produces **two** records that share a `request_id`:

1. A **transport** record (`action` is `transport`, `metadata` is
   `layer=preflight`), written before the call reaches a handler. It is the
   record you get for a call refused on scope, and it carries no device,
   because the device argument has not been read yet.
2. A **handler** record (`action` is `read` or `write`), written when the call
   finishes. `write` is used for the mutating tools (create, approve, apply,
   confirm and cancel a change set, `add_device`, `reload_devices`).

A call rmcp rejects before any handler runs (unknown arguments, an unknown tool
name, recorded as `unknown_tool`) is still audited. The server's own startup,
reload and shutdown events are ordinary log lines, not call records.

Error text is **not** copied into the record: it can carry device-sourced
detail, and the trail needs the outcome rather than the prose. A failed
handler shows `error_kind` and a fixed `error`.

A real handler record, from a call to `list_opnsense_aliases` for a device
name the inventory did not contain (so the result is an error), with
`--audit-format json --audit-redact devices=hmac`:

```json
{"timestamp":"2026-10-29T15:32:37.693468Z","level":"INFO","fields":{"message":"audit","request_id":"8f80ea66-78f6-4938-ba79-5d08367a08c1","caller":"operator","oauth_issuer":"","oauth_subject":"","oauth_client_id":"","identity_mechanism":"token","actor_type":"unknown","token_verified_fields":"none","provider":"unknown","provider_tier":"public","model_id":"","session_id":"","client_name":"t","client_version":"","client_call_id":"","on_behalf_of":"","change_ref":"","tool":"list_opnsense_aliases","devices":"hmac:9783ecae2cbf8e6e1ae76b6ee92554752d4cd81abf70d81d70214414d0285778","device_count":1,"action":"read","authorization":"allowed","result":"error","duration_ms":0,"error_kind":"tool_error","error":"the tool returned an error result","reason":"","metadata":""},"target":"audit","span":{"name":"serve_inner"},"spans":[{"name":"serve_inner"}]}
```

A call refused for scope looks like this (a token whose tool scope is `*` calling
a mutating tool; see Scope below):

```json
{"timestamp":"2026-10-29T15:44:52.786168Z","level":"INFO","fields":{"message":"audit","request_id":"1ce74bbb-381c-48b9-b37e-cf710da7df05","caller":"operator","oauth_issuer":"","oauth_subject":"","oauth_client_id":"","identity_mechanism":"token","actor_type":"unknown","token_verified_fields":"none","provider":"unknown","provider_tier":"public","model_id":"","session_id":"","client_name":"t","client_version":"0","client_call_id":"","on_behalf_of":"","change_ref":"","tool":"create_opnsense_change_set","devices":"","device_count":0,"action":"transport","authorization":"denied","result":"denied","duration_ms":0,"error_kind":"","error":"","reason":"insufficient_scope","metadata":"layer=preflight"},"target":"audit"}
```

## Fields

| Field | Meaning |
|---|---|
| `request_id` | Correlates the transport and handler records of one call. |
| `caller` | The token's `--name`. Never redacted. |
| `identity_mechanism` | How the caller was identified: `token`, `oauth`, `oidc-step-up`, or `none` (stdio). |
| `oauth_issuer`, `oauth_subject`, `oauth_client_id` | Set for OAuth callers; empty for token callers. |
| `actor_type` | `human`, `agent` or `unknown`, from the token's `--actor-type`. Only a `human` can be the second principal who approves a change set. |
| `provider`, `provider_tier` | The token's `--provider` and `--provider-tier` (`unknown` / `public` when unset). |
| `on_behalf_of` | The token's `--on-behalf-of`. |
| `token_verified_fields` | Which of the token-bound fields above came from the token store (server-verified) rather than from the caller. `none` means none did. |
| `model_id`, `session_id`, `client_name`, `client_version`, `client_call_id` | Asserted by the client; never evidence of identity. `client_call_id` ties a record to the call in the client's own transcript. |
| `change_ref` | An external change-control reference, when supplied. |
| `tool` | The tool called. An unregistered name is recorded as `unknown_tool`, so caller input never reaches this field. |
| `devices`, `device_count` | The device the call named, after redaction (below), and how many. |
| `action` | `transport` (preflight record), `read` or `write`. |
| `authorization` | `allowed`, `denied`, or `no_auth` (stdio, or `--allow-no-auth`). |
| `result` | `ok`, `error`, `denied` or `unsettled` (the client disconnected before an outcome). |
| `error_kind`, `error` | For `error`: a stable category (`tool_error`, `rejected`, `unexpected_response`, `timeout`, and so on) and a fixed bounded message. |
| `reason` | For `denied`: why. `insufficient_scope` for a token scope refusal; `direct_commit_disabled` for a direct-commit tool called without `--allow-direct-commit` (the flag exists in this build; its tools are not in the tool list yet). |
| `duration_ms` | Wall time of the call. |
| `metadata` | Non-secret key=value detail. `layer=preflight` on transport records. |

Scope: a token's tool scope `*` covers every read tool and **none** of the
mutating ones. To let a token create or apply change sets, name those tools
(`--tools` takes exact names), and mint the approver's token with
`--actor-type human`.

## Device names: `devices=hmac`

The packaged unit and the image run with `--audit-redact devices=hmac` and an
`--audit-hmac-key-file`. A device name is replaced by `hmac:` and the
hex HMAC-SHA256 of the name under the key, so the trail does not carry names yet
the same device always maps to the same value. Other fields can be redacted the
same way: `--audit-redact` accepts `devices`, `host`, `name`, `basename`,
`command` and `pfe_command`, each with `keep`, `drop` or `hmac`
(`devices=hmac,host=drop`). `caller` is never redactable.

To find which pseudonym is a given device, compute it with the key (any shell
with OpenSSL; the key file is raw bytes, so it is passed as hex):

```sh
printf '%s' fw-1 | openssl dgst -sha256 -mac HMAC \
  -macopt hexkey:"$(od -An -vtx1 /etc/rustopnsmcp/audit-hmac.key | tr -d ' \n')"
```

The digest printed must equal the 64 hex characters after `hmac:` in the record.
Read the key as root; it is `0600` for the service user.

## Key custody

- The key is 32 random bytes. The LXC installer creates it once at
  `/etc/rustopnsmcp/audit-hmac.key`, mode `0600`, owned by `rustopnsmcp`. In a
  container the binary creates it on first start at
  `/var/lib/rustopnsmcp/audit-hmac.key`, the only writable mount.
- It is never rewritten. The server refuses to start on an existing key that is
  a symlink, not a regular file, group- or world-readable, or not owned by the
  service user. [FILESYSTEM.md](../packaging/FILESYSTEM.md) has the fix.
- **Back it up with your other secrets.** Without it you cannot relate old
  pseudonyms to current device names, and a replacement key breaks correlation
  with every older record. Anyone holding the key can confirm a guessed device
  name against a record, so treat it as a secret, not as a log.

## Where records go

| Sink | Flag | Notes |
|---|---|---|
| Log output, as JSON | `--audit-format json` | Stderr under the unit; stdout for the container runtime in Docker. |
| systemd journal | `--audit-journald` | In the stock unit. Not in the image: a container has no journald socket. |
| A file of JSON lines | `--audit-log-file <path>` | Optional. Written by the service, so the service could also rewrite it; rotate it with the shipped logrotate fragment (see [OPERATIONS.md](OPERATIONS.md#audit)). |

In an unprivileged LXC the integrity control is the journal, which the service
cannot rewrite, plus forwarding it off the guest before it is needed
([HOW-TO-SETUP-LXC.md](HOW-TO-SETUP-LXC.md)).

## Evidence pipeline flags

Two optional sinks ship hash-chained segments of the trail to a second system.
They are off unless their endpoint flag is set. Flags are as `rustopnsmcp
--help` lists them.

`--ssdf-audit-*` sends to a ClickHouse endpoint with an insert-only identity:

- `--ssdf-audit-endpoint` enables it. Once it is set, `--ssdf-audit-server-id`,
  `--ssdf-audit-outbox` and `--ssdf-audit-ledger` are required. The server id
  is deliberately not defaulted to the hostname: the chain is keyed by it, and a
  changed value starts a second chain that verifies as valid.
- Credentials are files, never flag values, and must be `0600`:
  `--ssdf-audit-password-file` for the write identity (`--ssdf-audit-user`) and
  `--ssdf-audit-verify-password-file` for the select-only identity
  (`--ssdf-audit-verify-user`). `--ssdf-audit-database` names the database.
- `--ssdf-audit-ca-file` is the trust anchor for an `https://` endpoint.
- `--ssdf-audit-interval-secs` and `--ssdf-audit-records-per-segment` tune
  delivery. `--ssdf-audit-signing-key` (an Ed25519 key, `0600`) signs each
  segment as it closes; without it segments are unsigned.

`--audit-forward-*` sends the same chained segments to a second, best-effort
destination such as a SIEM or collector, independent of SSDF:

- `--audit-forward-endpoint` enables it (HTTPS, or loopback HTTP). Then
  `--audit-forward-outbox` and `--audit-forward-ledger` are required.
- `--audit-forward-token-file` is an optional bearer token (`0600`);
  `--audit-forward-ca-file` is the trust anchor if the endpoint's certificate is
  not publicly trusted.

Both need writable directories for their outbox and ledger. Under the stock unit
that means a path below `/var/lib/rustopnsmcp/`, the only writable location.
