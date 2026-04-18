# Debugging

Three things can go wrong: the extension doesn't reach the relay, the relay
doesn't accept the identity, or the relay can't dial the target. Each has a
characteristic signature.

## Turn on relay logs

```bash
uvicorn ssh_relay.app:app --host 127.0.0.1 --port 8080 --log-level debug
```

Or with make:

```bash
LOG_LEVEL=debug make dev
```

When running under systemd:

```bash
journalctl -u ssh-relay -f
```

## Extension side

The Secure Shell extension has its own debug channel. In the connection
options box, add:

```
--proxy-debug=true
```

Then open the **Chrome** DevTools (`Ctrl+Shift+J` from the extension's
terminal tab) and watch the console — you'll see the `/cookie` hit, the
WebSocket URL, and any close codes.

## Characteristic failures

### Browser says `ERR_SSL_PROTOCOL_ERROR` / relay logs `WARNING: Invalid HTTP request received`

The browser is forcing HTTPS (HTTPS-First Mode) but the relay is plain HTTP.
Either front it with TLS (production) or use `make dev-tls` (local mkcert).

### Close code 4401 (extension immediately closes)

Identity verification failed. Check:

- `RELAY_IDENTITY_PROVIDER` matches the proxy in front of you.
- `RELAY_CF_AUDIENCE` matches the Application AUD from the Access dashboard
  (it's a hash, not the hostname).
- `RELAY_IAP_AUDIENCE` is the *full* backend-service audience:
  `/projects/<NUMBER>/global/backendServices/<ID>` — the numeric project number,
  not the project id.
- The JWT header is actually arriving. For CF Access, hit any endpoint and
  check `cf-access-jwt-assertion` shows up in request headers (use a small
  test handler or log `request.headers` with debug level).

### Close code 4404 on `/v4/reconnect`

Either the session id doesn't exist (relay restarted, grace expired, or the
id is bogus) or the reconnecting identity doesn't match the original. The
extension handles this gracefully — it gives up and starts a fresh
`/v4/connect`.

### Close code 4502

TCP dial to the target failed. The relay log line `dial failed host:port <err>`
has the OS error. Common cases:

- Firewall between relay and target doesn't permit the port.
- Target host resolves but port 22 is closed.
- DNS resolution fails (target hostname unknown inside the relay's network
  namespace — especially in containers).

### `corp-relay-v4@google.com` "handshake failed" / "bad protocol"

The extension is using a different protocol mode. Verify
`--proxy-mode=corp-relay-v4@google.com` exactly (with the `@google.com`).

### WebSocket closes mid-session with 1009

A frame exceeded `RELAY_MAX_FRAME_BYTES` (default 1 MiB). The extension
doesn't actually emit frames that big — this usually points at a misconfigured
reverse proxy trying to re-fragment data. Check nginx
`proxy_buffering`/`proxy_request_buffering` or Apache `ProxyIOBufferSize`.

### Sessions disconnect every ~60s

Your upstream proxy has a WebSocket idle timeout. Each idle proxy product
picks a different default; typical values:

- **Cloudflare**: 100 s idle for WebSockets.
- **GCP HTTPS LB**: backend-service `timeoutSec`; defaults matter.
- **AWS ALB**: `idle_timeout.timeout_seconds`.
- **nginx**: `proxy_read_timeout`, default 60 s.

SSH is frequently idle. Either raise the upstream timeout (preferred) or keep
the session alive from the extension (enable `SendEnv` / server-side keepalive
on the target sshd).

## Is the protocol working? Inspect `/cookie`

```bash
curl -s 'http://127.0.0.1:8080/cookie?ext=iodihamcpbpeioajjeobimgagajmlibd&path=html/nassh.html&version=2&method=js-redirect' | head -c 400
```

You should see a `<script>window.location.replace("chrome-extension://.../#...")`
redirect. The fragment is base64url(JSON). Decode it to verify the
advertised endpoint:

```bash
python3 - <<'PY'
import base64, json
frag = "..."  # paste fragment here
print(json.loads(base64.urlsafe_b64decode(frag + "==")))
PY
```

## End-to-end smoke test (no browser)

```bash
.venv/bin/pytest tests/ -v --timeout=15
```

The test suite spins up uvicorn + a toy TCP echo server + a websockets client
and round-trips bytes through the relay. If that passes, the relay is healthy
— any failure you see in the browser is in the path between the browser and
the relay.
