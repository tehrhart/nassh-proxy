# Logging and audit events

The relay emits structured JSON events on session lifecycle transitions. Events
fan out to all configured sinks in parallel through an in-process async event
bus. Sinks are non-blocking — if a sink's 10 000-event queue fills up, new
events are dropped for that sink with a warning, but the hot path (proxying
bytes) never stalls on a slow sink.

## Sinks

Select sinks via `RELAY_LOG_SINKS` (comma-separated):

| Name     | What it does                                                                              |
| -------- | ----------------------------------------------------------------------------------------- |
| `stderr` | One JSON object per line to stderr. Good with systemd/journald and Docker.               |
| `file`   | Rotating JSONL file (`logging.handlers.RotatingFileHandler`).                            |
| `splunk` | Posts each event to a Splunk HTTP Event Collector.                                        |
| `pan`    | Pushes User-ID XML on `session.start` (login) and `session.close` (logout).               |

Combine freely: `RELAY_LOG_SINKS=stderr,file,splunk,pan`.

## Event schema

All events share:

```json
{
  "event": "<type>",
  "ts": "2026-04-18T15:30:00.123456+00:00",
  "ts_unix": 1745511000.123456,
  "session_id": "32-char-hex"
}
```

### `session.start`

Emitted **before any bytes flow**, immediately after a successful TCP dial and
WebSocket accept. Recording the start is what lets you find *active* sessions
in your logs — sessions that haven't ended yet wouldn't otherwise appear.

```json
{
  "event": "session.start",
  "ts": "...",
  "ts_unix": ...,
  "session_id": "...",
  "identity": {
    "provider": "cloudflare-access",
    "sub": "abc123",
    "email": "user@example.com"
  },
  "source_ip": "203.0.113.4",
  "source_port": 40123,
  "user_agent": "Mozilla/5.0 ...",
  "target_host": "bastion-1.corp",
  "target_port": 22,
  "dial_seconds": 0.0184
}
```

- `identity` is `null` when `RELAY_IDENTITY_PROVIDER=none`.
- `source_ip` is pulled from `cf-connecting-ip`, then `x-forwarded-for`, then
  the direct peer. Make sure your proxy sets one of these or you'll get the
  proxy's IP.
- `source_port` is the relay's outbound port toward the target — populated
  only when `RELAY_SOURCE_PORT_MIN/MAX` are set.

### `session.reconnect`

Emitted on a successful `/v4/reconnect`:

```json
{
  "event": "session.reconnect",
  "ts": "...",
  "ts_unix": ...,
  "session_id": "...",
  "source_ip": "...",
  "user_agent": "...",
  "resume_ack": 12345,
  "reconnect_count": 2
}
```

A high `reconnect_count` on a single session is a hint of a flaky client link.

### `session.close`

Emitted **exactly once** per session, on every exit path (clean close,
grace-expiry, handler error, server shutdown):

```json
{
  "event": "session.close",
  "ts": "...",
  "ts_unix": ...,
  "session_id": "...",
  "reason": "closed",
  "error": null,
  "duration_seconds": 327.412,
  "bytes_to_target": 4812,
  "bytes_from_target": 92831,
  "reconnect_count": 1,
  "client_ssh_banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
  "target_ssh_banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7",
  "identity": { ... },
  "source_port": 40123,
  "target_host": "bastion-1.corp",
  "target_port": 22
}
```

- `reason` is one of `closed`, `grace_expired`, `server_shutdown`,
  `session_gone`, `handler_error`.
- `error` carries the Python exception string on error paths, `null` otherwise.
- `client_ssh_banner` / `target_ssh_banner` are the first `\n`-delimited line
  observed in each direction (typically `SSH-2.0-...`). The relay doesn't
  parse SSH — it just peeks the first ~256 bytes.

## Splunk HEC

Events POST to `{RELAY_SPLUNK_URL}/services/collector/event` with
`Authorization: Splunk <token>`. The relay uses the event's `ts_unix` as the
Splunk `time` field. You'll typically set `sourcetype=_json` so Splunk
field-extracts automatically.

Splunk is a best-effort sink: queue-full drops and per-request failures are
logged but do not crash the relay. For regulated environments that require
delivery guarantees, also run the `file` sink and ship the rotated files with
a forwarder.

## Palo Alto Networks User-ID

The PAN sink pushes **login** on `session.start` and **logout** on
`session.close`:

```xml
<uid-message><version>1.0</version><type>update</type><payload>
  <login><entry name="user@example.com" ip="203.0.113.10"
                source-port-start="40123" source-port-end="40123"/></login>
</payload></uid-message>
```

This maps `(relay_ip, port) → user`, so firewall rules downstream of the relay
can be written in terms of users, not IPs. Two things to verify:

1. **Port pool is enabled** (`RELAY_SOURCE_PORT_MIN/MAX`). Without it, the
   relay can't tell PAN which port belongs to which user.
2. **`RELAY_RELAY_IP`** matches the source IP the firewall actually sees — if
   you're behind SNAT, set it to the SNAT IP, not the relay's interface IP.

Only events with both `identity.principal` (email or sub) and `source_port`
are pushed. Everything else is silently skipped.

If you want PAN to age entries out on its own (in case logout is lost), set
`RELAY_PAN_LOGIN_TIMEOUT_SECONDS` to a value slightly larger than your
`RELAY_GRACE_SECONDS`. Default `0` disables the timeout attribute.

## File rotation

`logging.handlers.RotatingFileHandler` is stdlib and rotates in-process.
Rotation is best-effort on shutdown — use log shipping that tails
`*.log*.jsonl` if you need every byte offsite. For containerized deployments,
prefer `stderr` + journald/fluentd instead of a file inside the container.
