# Configuration

All configuration is environment variables, prefixed `RELAY_`. `pydantic-settings`
reads them from the process environment and (if present) a `.env` file in the
working directory.

## Public endpoint

| Variable             | Default | Description                                                                    |
| -------------------- | ------- | ------------------------------------------------------------------------------ |
| `RELAY_PUBLIC_HOST`  | —       | **Required.** Host the extension should connect to (what `/cookie` returns). |
| `RELAY_PUBLIC_PORT`  | `443`   | Public port. Must match what the extension dials.                              |

These values are baked into the `/cookie` redirect response. They must reflect
the URL **the browser** sees, not the one uvicorn binds to.

## Identity

| Variable                    | Default | Description                                                                 |
| --------------------------- | ------- | --------------------------------------------------------------------------- |
| `RELAY_IDENTITY_PROVIDER`   | `none`  | `none`, `cloudflare-access`, or `gcp-iap`.                                  |
| `RELAY_AUTH_REQUIRED`       | `true`  | When `true`, requests without a valid JWT are rejected. `false` is dev-only. |
| `RELAY_CF_TEAM_DOMAIN`      | —       | CF team subdomain, e.g. `yourteam` for `yourteam.cloudflareaccess.com`.    |
| `RELAY_CF_AUDIENCE`         | —       | Application AUD from the CF Access Application settings.                    |
| `RELAY_IAP_AUDIENCE`        | —       | Full audience string (e.g. `/projects/123/global/backendServices/456`).    |

`none` is only appropriate when an upstream proxy already authenticates the
user *and* you trust the network path between that proxy and the relay.

## Session behavior

| Variable                    | Default       | Description                                                           |
| --------------------------- | ------------- | --------------------------------------------------------------------- |
| `RELAY_READ_CHUNK_BYTES`    | `65536`       | TCP read granularity.                                                  |
| `RELAY_MAX_FRAME_BYTES`     | `1048576`     | Reject WS frames larger than this (close code 1009).                  |
| `RELAY_MAX_REPLAY_BUFFER`   | `4194304`     | Per-session ring buffer for reconnect replay.                         |
| `RELAY_GRACE_SECONDS`       | `120`         | Keep a closed WS's session dialable for this long before tearing down. |

Tuning guidance:

- **`MAX_REPLAY_BUFFER`** bounds how much data the server will replay on
  reconnect. The extension only reconnects after a brief outage; 4 MiB handles
  most practical hiccups (e.g., WiFi roam). Increase if you have long-running
  chatty sessions (e.g., `scp` of large files) going over flaky uplinks.
- **`GRACE_SECONDS`** is how long a laptop can close its lid before the session
  is lost. 120 s is a reasonable default; shorten if you're memory-constrained,
  lengthen if you want to survive longer WiFi gaps.
- **`MAX_FRAME_BYTES`** caps individual WebSocket frames. The relay doesn't
  reassemble above this; the extension never sends frames this large in
  practice.

## Source-port pinning (PAN User-ID)

| Variable                   | Default | Description                                                                |
| -------------------------- | ------- | -------------------------------------------------------------------------- |
| `RELAY_SOURCE_PORT_MIN`    | —       | Lower bound of the dedicated source-port range.                             |
| `RELAY_SOURCE_PORT_MAX`    | —       | Upper bound.                                                                |
| `RELAY_RELAY_IP`           | —       | Public IP of the relay — the IP PAN will see. Used in User-ID XML.         |

Unset `RELAY_SOURCE_PORT_MIN`/`MAX` to let the kernel pick ephemeral ports. Set
them if you're emitting to PAN (so the firewall can map `(relay_ip, port) →
user`). Pick a range **outside** the OS ephemeral range
(`/proc/sys/net/ipv4/ip_local_port_range` on Linux, typically `32768–60999`)
to avoid conflicts.

Each active session consumes one port from the range. Size it to your expected
concurrent-session count plus headroom. A pool of 10 000 is usually plenty.

## Logging

| Variable                         | Default    | Description                                                                 |
| -------------------------------- | ---------- | --------------------------------------------------------------------------- |
| `RELAY_LOG_SINKS`                | `stderr`   | Comma-separated subset of `stderr`, `file`, `splunk`, `pan`.                |
| `RELAY_LOG_FILE_PATH`            | —          | Required if `file` is in sinks.                                              |
| `RELAY_LOG_FILE_MAX_BYTES`       | `100 MiB`  | Rotate when file exceeds this.                                               |
| `RELAY_LOG_FILE_BACKUP_COUNT`    | `10`       | Keep this many rotated files.                                                |
| `RELAY_SPLUNK_URL`               | —          | Splunk base URL, e.g. `https://splunk.example.com:8088`.                   |
| `RELAY_SPLUNK_TOKEN`             | —          | HEC token.                                                                   |
| `RELAY_SPLUNK_INDEX`             | —          | Optional; overrides the token's default index.                              |
| `RELAY_SPLUNK_SOURCE`            | `ssh-relay`| HEC `source` metadata.                                                       |
| `RELAY_SPLUNK_SOURCETYPE`        | `_json`    | HEC `sourcetype`.                                                            |
| `RELAY_SPLUNK_VERIFY`            | `true`     | Set `false` only with private Splunk CAs in dev.                             |
| `RELAY_PAN_FIREWALL_URLS`        | —          | Comma-separated firewall URLs, e.g. `https://fw1,https://fw2`.             |
| `RELAY_PAN_API_KEY`              | —          | PAN-OS API key.                                                              |
| `RELAY_PAN_VERIFY`               | `true`     | TLS verification for PAN.                                                    |
| `RELAY_PAN_LOGIN_TIMEOUT_SECONDS`| `0`        | Optional `timeout` attribute in the User-ID `<login>` entry. 0 = none.      |

See [logging.md](logging.md) for the event schema and sink semantics.

## `.env` file

For local dev, copy `.env.example` to `.env`. uvicorn picks it up automatically
via `pydantic-settings`. For production, prefer process environment (systemd
`EnvironmentFile=`, Docker `-e`, Kubernetes `envFrom`) so the file lives where
your secrets tooling expects it.
