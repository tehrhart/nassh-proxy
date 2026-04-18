# Installation

The relay is a small Python service. Pick the mode that matches your ops
posture.

## Requirements

- Python 3.11+ (tested on 3.12)
- Outbound TCP to the targets you want users to reach
- A fronting TLS terminator if you're exposing the relay to the internet
  (Cloudflare Tunnel, GCP HTTPS LB, nginx, Apache — see the
  [deployment guides](deploy/))

## From source (virtualenv)

```bash
git clone <this-repo> ssh-relay
cd ssh-relay
make install             # creates .venv and installs in editable mode
cp .env.example .env     # edit to taste
make dev                 # foreground, reload-on-edit
```

`make install` is equivalent to:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

## Docker

```bash
docker build -t ssh-relay .
docker run --rm -p 8080:8080 \
  -e RELAY_PUBLIC_HOST=ssh-relay.example.com \
  -e RELAY_PUBLIC_PORT=443 \
  -e RELAY_IDENTITY_PROVIDER=cloudflare-access \
  -e RELAY_CF_TEAM_DOMAIN=yourteam \
  -e RELAY_CF_AUDIENCE=<aud-from-access-app> \
  ssh-relay
```

`CMD` already includes `--proxy-headers --forwarded-allow-ips "*"`, which is
what you want when a reverse proxy terminates TLS and forwards the WebSocket.

## docker compose

A minimal compose file lives at
[`deploy/docker/docker-compose.yml`](../deploy/docker/docker-compose.yml).

```bash
cd deploy/docker
cp ../../.env.example .env
docker compose up -d
```

## systemd service (VM)

A unit file is provided at
[`deploy/systemd/ssh-relay.service`](../deploy/systemd/ssh-relay.service).

```bash
# Install code into /opt/ssh-relay, create a venv, create a system user.
sudo ./deploy/systemd/install.sh

# Install config.
sudo install -m 0640 -o ssh-relay -g ssh-relay .env.example /etc/ssh-relay/env
sudoedit /etc/ssh-relay/env

# Enable + start.
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-relay
sudo systemctl status ssh-relay
journalctl -u ssh-relay -f
```

The install script creates a `ssh-relay` system user, drops a venv in
`/opt/ssh-relay/.venv`, and puts the code in `/opt/ssh-relay/src/`.

## Health check

The service exposes `GET /healthz` → `{"ok": true}` with no auth required (it
returns before the identity check). Use this as your load-balancer health
probe. When running behind CF Access or GCP IAP, you may need to mark the path
as a public/bypass path in the upstream proxy's configuration.

## Upgrade

Pull new code and restart:

```bash
cd /opt/ssh-relay/src
sudo -u ssh-relay git pull
sudo -u ssh-relay /opt/ssh-relay/.venv/bin/pip install -e .
sudo systemctl restart ssh-relay
```

Sessions do not survive a restart. The Secure Shell extension will try to
reconnect using the stored session id and get a `4404` close, which is
indistinguishable to the user from a transient network blip — they'll
reconnect cleanly.
