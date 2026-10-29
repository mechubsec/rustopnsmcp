# Metrics

`rustopnsmcp` can serve Prometheus metrics at `/metrics`. They are **off by
default**; the server's `--help` explains why: `/metrics` carries no bearer
authentication of its own, so turning it on is an operator decision.

## Turn it on

Add `--enable-metrics` to the server's arguments. Under systemd that means the
site override, which replaces the whole command line, so restate every flag
([HOW-TO-SETUP-LXC.md](HOW-TO-SETUP-LXC.md#7-listen-on-the-network-the-site-override)) and add the
flag after `--inventory-readonly \`. In Docker, pass it after the image name
([HOW-TO-SETUP-DOCKER.md](HOW-TO-SETUP-DOCKER.md#run)). Metrics exist only on
the `streamable-http` transport.

```sh
curl -s http://127.0.0.1:30037/metrics
```

## Access: loopback only

`/metrics` answers **only callers on loopback**, whatever address the server is
bound to, and it takes no bearer token. A scraper on another host is refused. So
either run the scraper on the guest (an agent that forwards the samples), or
reach it through a tunnel you control. Do not publish `/metrics` through a
reverse proxy on the same machine: the proxy connects over loopback, so it would
hand the endpoint to everyone who can reach the proxy.

## What is returned

All series carry a `server="opnsense"` label. This was captured from a running
build with `--enable-metrics`, after a session, two calls and some
rate-limited requests; every name below appeared in that output.

| Metric | Type | Labels besides `server` | Meaning |
|---|---|---|---|
| `rustopnsmcp_active_sessions` | gauge | none | MCP sessions the HTTP session manager is tracking now. Present from start, at 0. |
| `rustopnsmcp_limit_hits_total` | counter | `limit`, `event` | Requests rejected by a resource limit. Appears after the first rejection. Observed: `limit="ip_rate"`, `event="request_rejected"` (HTTP 429 from the per-IP rate limit). The transport also records `request_body`, `global_concurrency` (both `request_rejected`) and `session_cap` (`session_registration_rejected`). |
| `mecmcp_tool_duration_seconds` | summary | `tool`, `result` (`ok`, `error` or `denied`), and `quantile` on the sample lines | Duration of each audit record, in seconds: one series per tool and result, with `_sum` and `_count`. Quantiles reported: 0, 0.5, 0.9, 0.95, 0.99, 0.999 and 1. |

Example lines, from the same run:

```
rustopnsmcp_active_sessions{server="opnsense"} 1
rustopnsmcp_limit_hits_total{server="opnsense",limit="ip_rate",event="request_rejected"} 4
mecmcp_tool_duration_seconds_sum{server="opnsense",tool="get_device_list",result="ok"} 0.00008991400000000001
mecmcp_tool_duration_seconds_count{server="opnsense",tool="get_device_list",result="ok"} 2
```

Notes:

- The duration metric keeps the shared `mecmcp_` prefix, while the other two
  use `rustopnsmcp_`. Write dashboards against the names as returned.
- It is exported as a summary (quantiles), not a histogram, so you cannot
  aggregate it across instances with `histogram_quantile`.
- It is fed by the audit records ([AUDIT.md](AUDIT.md)), and one call writes
  two: the transport preflight record, which is `ok` once the call is allowed
  through, and the handler record. So one call that fails in its handler adds
  one sample to `result="ok"` and one to `result="error"`, and `_count` is about
  twice the number of calls. A call refused on scope adds a single
  `result="denied"` sample. Use `result="error"` and `"denied"` for failures,
  not the ratio of `_count` to calls.
- The transport also defines `rustopnsmcp_sessions_reaped_total` (counter,
  label `reason`). It did not appear in a short test with a one-second session
  idle timeout, so treat it as unconfirmed here.
