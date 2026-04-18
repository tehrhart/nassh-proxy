# ssh-relay

Browser-native SSH, SCP, and SFTP over a TLS WebSocket relay, gated by an
identity provider of your choice. Implements the nassh `corp-relay-v4@google.com`
protocol, so the existing Google-published [Secure Shell extension][ext] for
Chrome/Chromium works without modification.

[ext]: https://chromewebstore.google.com/detail/secure-shell/iodihamcpbpeioajjeobimgagajmlibd

## Why

If you run a Zero Trust program, arbitrary SSH to a corporate fleet is the last
workflow that keeps dragging users onto a VPN or the legacy office network.
This relay lets you publish SSH behind the same identity-aware proxy you
already use for HTTP apps (Cloudflare Access, GCP IAP, or anything else that
terminates TLS and attaches a JWT). The endpoint is *dynamic*: a user types
any `user@host:port` into the browser extension and the relay dials it, so you
don't have to pre-register every target host.

## What's in the box

- **`corp-relay-v4@google.com` protocol** — `/cookie`, `/v4/connect`,
  `/v4/reconnect`, with session resumption and a replay buffer.
- **Pluggable identity** — Cloudflare Access (RS256 JWT), GCP IAP (ES256 JWT),
  or none (when an upstream proxy already enforces auth).
- **Structured audit logging** — `session.start`, `session.reconnect`,
  `session.close` events, fanned out to stderr / rotating JSONL / Splunk HEC /
  Palo Alto Networks User-ID in parallel.
- **Source-port pinning** — optional per-session bind to a fixed port range so
  PAN can map `(relay_ip, source_port) → user` without IP-per-user hacks.
- **Single-process async Python** — FastAPI + uvicorn, no external state store.

## Quickstart (local)

```bash
make install
make dev            # http://127.0.0.1:8080, no auth
```

Point the Chrome extension at `127.0.0.1:8080`:

- **Relay Server Options**: `--proxy-host=127.0.0.1 --proxy-port=8080 --proxy-mode=corp-relay-v4@google.com --use-ssl=false`

Browsers increasingly refuse plaintext — if Chrome's HTTPS-First Mode insists on
TLS, use the locally-trusted mkcert flow:

```bash
make dev-tls        # https://127.0.0.1:8443
```

…and set `--proxy-port=8443 --use-ssl=true` instead.

For a tunnel exposed to your real browser-side extension:

```bash
make dev-tunnel     # uvicorn + cloudflared trycloudflare
```

Tests:

```bash
make test
```

## Quickstart (VM behind Cloudflare Tunnel)

The shortest path from "I have a VM" to "I can SSH in the browser". Assumes
you'll add cloudflared + a Cloudflare Access Application later.

```bash
# On your laptop: push the source to the VM.
rsync -av --exclude .venv --exclude .git --exclude .certs --exclude .pytest_cache \
      ./ user@vm:~/ssh-relay/

# On the VM:
cd ~/ssh-relay
sudo ./deploy/systemd/install.sh
sudoedit /etc/ssh-relay/env
sudo systemctl enable --now ssh-relay
journalctl -u ssh-relay -f
```

The installer creates a `ssh-relay` system user, a venv at
`/opt/ssh-relay/.venv`, copies source to `/opt/ssh-relay/src`, installs the
systemd unit, and seeds `/etc/ssh-relay/env` from `.env.example`.

**Minimum env to smoke-test before cloudflared is wired up** (no auth):

```bash
RELAY_PUBLIC_HOST=ssh-relay.example.com
RELAY_PUBLIC_PORT=443
RELAY_IDENTITY_PROVIDER=none
RELAY_AUTH_REQUIRED=false
RELAY_LOG_SINKS=stderr
```

Verify on the VM: `curl http://127.0.0.1:8080/healthz` → `{"ok":true}`.

**When you add cloudflared + CF Access**, flip four lines and restart:

```bash
RELAY_IDENTITY_PROVIDER=cloudflare-access
RELAY_CF_TEAM_DOMAIN=yourteam
RELAY_CF_AUDIENCE=<aud-from-access-app>
RELAY_AUTH_REQUIRED=true
```

```bash
sudo systemctl restart ssh-relay
```

Full cloudflared walkthrough: [docs/deploy/cloudflare-access.md](docs/deploy/cloudflare-access.md).

### A note on Cloudflare Origin certs

With Cloudflare Tunnel you don't need one — cloudflared dials the CF edge
over its own authenticated mTLS tunnel and talks to the relay on
`127.0.0.1:8080` as plain HTTP (see
[`deploy/cloudflared/config.yml`](deploy/cloudflared/config.yml)). A 10-year
Origin cert matters only if you later switch to a **proxied DNS record
pointing at the VM's public IP** (no tunnel), in which case front the relay
with nginx using [`deploy/nginx/ssh-relay.conf`](deploy/nginx/ssh-relay.conf)
and hand it the Origin cert + key.

## Documentation

- [Installation](docs/installation.md) — venv, Docker, systemd.
- [Configuration](docs/configuration.md) — all `RELAY_*` env vars.
- [Logging and audit events](docs/logging.md) — event schema and sinks.
- [Debugging](docs/debugging.md) — common failures on both sides of the wire.

Deployment guides:

- [Cloudflare Access](docs/deploy/cloudflare-access.md) — Cloudflare Tunnel
  with an Access Application enforcing the JWT.
- [GCP IAP](docs/deploy/gcp-iap.md) — Managed Instance Group behind an HTTPS
  Load Balancer with Identity-Aware Proxy.
- [nginx](docs/deploy/nginx.md) — generic reverse proxy with WebSocket upgrade.
- [Apache](docs/deploy/apache.md) — `mod_proxy_wstunnel` front door.

Example configs and scripts live in [`deploy/`](deploy/).

## Architecture

```
 Browser          Identity-aware proxy        Relay               Target
 (Secure Shell)    (CF Access / GCP IAP /   (this repo)         (sshd)
                   nginx / apache)
 ───HTTPS──────▶  ─────HTTPS w/ JWT─────▶   ────TCP────▶
     WebSocket upgrade preserved end-to-end
```

The relay treats the WebSocket payload as opaque SSH bytes and forwards them to
a TCP dial of `host:port` supplied by the client. Identity is asserted by the
upstream proxy via a signed JWT header; the relay verifies it using the
provider's JWKS.

## Security model

- **Identity is the perimeter.** Any authenticated user can SSH to any host
  reachable from the relay's network. That's usually what you want (replace
  VPN); if not, place network ACLs between the relay and sensitive targets.
- **No destination allowlist.** By design. Mix in firewall rules if you need
  one.
- **Session ownership.** Reconnect is gated on `identity.principal` matching
  the original session. A stolen session-id without the same JWT subject
  cannot resume.
- **Audit completeness.** `session.start` is emitted before any bytes flow, so
  orphan sessions (e.g., a crashing worker) still leave a trail. `session.close`
  is guaranteed on every exit path, including grace-expiry.
