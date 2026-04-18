# Deploy behind Cloudflare Access

Run the relay privately (no public IP), expose it with a Cloudflare Tunnel,
and put an Access Application in front.

```
Browser ──TLS──▶ Cloudflare edge ──Access JWT──▶ cloudflared ──HTTP──▶ relay
```

## 1. Install and run cloudflared on the relay host

```bash
sudo cloudflared tunnel login
sudo cloudflared tunnel create ssh-relay
sudo mkdir -p /etc/cloudflared
sudo install -m 0600 ~/.cloudflared/<TUNNEL-ID>.json /etc/cloudflared/ssh-relay.json
```

Drop in [`deploy/cloudflared/config.yml`](../../deploy/cloudflared/config.yml),
edit the hostname, then:

```bash
sudo cloudflared tunnel route dns ssh-relay ssh-relay.example.com
sudo cloudflared --config /etc/cloudflared/config.yml tunnel run ssh-relay
```

Install the systemd service:

```bash
sudo cloudflared service install
sudo systemctl enable --now cloudflared
```

## 2. Configure the Access Application

In **Zero Trust → Access → Applications**, create a **Self-hosted**
application:

- **Application domain**: `ssh-relay.example.com`
- **Identity providers**: the ones you already use (SSO/IdP).
- **Policies**: scope to the user group allowed to SSH in the browser.
- **CORS**: not required (WebSocket). Leave defaults.
- **Session Duration**: the JWT lifetime; 1–24 h depending on your posture.

After save, copy the **Application Audience (AUD) tag** — that's what goes in
`RELAY_CF_AUDIENCE`.

Bypass-auth for `/healthz` if your load-balancer health probes go through the
edge. Alternatively, probe locally on the relay host.

## 3. Configure the relay

```bash
RELAY_PUBLIC_HOST=ssh-relay.example.com
RELAY_PUBLIC_PORT=443
RELAY_IDENTITY_PROVIDER=cloudflare-access
RELAY_CF_TEAM_DOMAIN=yourteam
RELAY_CF_AUDIENCE=<aud-tag-from-step-2>
RELAY_AUTH_REQUIRED=true
RELAY_LOG_SINKS=stderr
```

Start the relay (`make dev` for a smoke test, systemd for production — see
[installation.md](../installation.md#systemd-service-vm)).

## 4. Configure the Chrome extension

Open **Secure Shell → Options → Relay Server Options** and set:

```
--proxy-host=ssh-relay.example.com
--proxy-port=443
--proxy-mode=corp-relay-v4@google.com
--use-ssl=true
```

### Admin-console rollout

You can **force-install** the extension via Google Admin console —
`Devices → Chrome → Apps & extensions → Users & browsers → +` → search the
store for Secure Shell → *Installation policy: Force install*. That puts the
extension on every managed browser.

What you **cannot** do from the Admin console is prefill the relay host,
port, and proxy mode. The nassh extension does not ship a
`managed_schema.json`, so Chrome's `3rdparty.extensions.<ID>` managed-policy
mechanism has nothing to write into — the options page persists to
per-user `chrome.storage.sync`, which admin policy can't seed.

Practical workarounds:

- **Onboarding doc**: post a 3-line instruction for users to paste into
  *Extension → Options → Relay Server Options*:
  ```
  --proxy-host=ssh-relay.example.com --proxy-port=443 \
  --proxy-mode=corp-relay-v4@google.com --use-ssl=true
  ```
- **Launch URL**: bookmark a deep link to the extension's connection page
  with params baked in, e.g.
  `chrome-extension://iodihamcpbpeioajjeobimgagajmlibd/html/nassh.html`
  and teach users to create a profile with the relay filled in the first
  time. The profile is sticky after that.
- **File a request**: if managed-policy support matters to your rollout,
  [libapps issue tracker](https://issuetracker.google.com/issues?q=componentid:654284)
  is where to ask for a `managed_schema.json`.

## 5. Smoke test

1. Open `https://ssh-relay.example.com/healthz` in a browser. You should be
   bounced through the Cloudflare Access login, then see `{"ok": true}`.
2. In the Secure Shell extension, type `user@somehost:22` and connect. If
   the handshake stalls, re-read [debugging.md](../debugging.md).

## Notes

- The Secure Shell extension does a one-time `/cookie` fetch that returns a
  JS redirect back into the extension origin with the relay endpoint baked
  in. This is a normal HTTPS request — CF Access applies its policy and
  mints the JWT before the redirect ever hits the relay.
- WebSocket idle timeouts on the Cloudflare edge are ~100 s. SSH sessions
  that sit idle will drop; enable server-side `ClientAliveInterval 60` on
  your target sshd, or the extension's keepalive option.
- Session affinity: if you ever scale to multiple relays behind CF Load
  Balancer, enable **Session Affinity** (`cf-affinity` cookie). The session
  store is in-process, so a reconnect must land on the same relay.
