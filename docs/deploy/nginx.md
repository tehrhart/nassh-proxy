# Deploy behind nginx

For environments with an existing nginx edge — for example, an internal
reverse proxy that does auth via OIDC (`oauth2-proxy`, `vouch-proxy`) or mTLS.
nginx terminates TLS, forwards the WebSocket upgrade, and optionally strips
or sets identity headers before forwarding to the relay.

The nginx setup can operate in two modes:

1. **nginx authenticates, relay trusts** — `RELAY_IDENTITY_PROVIDER=none`.
   nginx is responsible for all access control.
2. **nginx is pass-through** — relay verifies a JWT header that nginx just
   forwards from a further-upstream proxy (e.g., CF Access sitting in front
   of nginx). Use the appropriate `RELAY_IDENTITY_PROVIDER` in that case.

Mode 1 is simpler but ties audit identity entirely to what nginx logs —
the relay will have `identity: null` in its events. For strong audit, prefer
mode 2 (or add nginx-set headers you read elsewhere).

## Config

Copy [`deploy/nginx/ssh-relay.conf`](../../deploy/nginx/ssh-relay.conf) to
`/etc/nginx/sites-available/`, edit the `server_name` and cert paths, then:

```bash
sudo ln -s /etc/nginx/sites-available/ssh-relay.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

The key pieces (full file in `deploy/nginx/`):

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;

    proxy_set_header Upgrade    $http_upgrade;
    proxy_set_header Connection $connection_upgrade;

    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # SSH sessions sit idle; raise from nginx's 60s default.
    proxy_read_timeout  24h;
    proxy_send_timeout  24h;

    # Don't buffer — this is a full-duplex stream.
    proxy_buffering         off;
    proxy_request_buffering off;
}
```

And in `http {}` or a snippet at `/etc/nginx/conf.d/ws_upgrade.conf`:

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
```

## Start the relay

```bash
RELAY_PUBLIC_HOST=ssh-relay.example.com \
RELAY_PUBLIC_PORT=443 \
RELAY_IDENTITY_PROVIDER=none \
RELAY_AUTH_REQUIRED=false \
RELAY_LOG_SINKS=stderr,file \
RELAY_LOG_FILE_PATH=/var/log/ssh-relay/audit.jsonl \
uvicorn ssh_relay.app:app \
  --host 127.0.0.1 --port 8080 \
  --proxy-headers --forwarded-allow-ips "127.0.0.1"
```

`--proxy-headers` makes uvicorn trust `X-Forwarded-*` from the nginx IP,
which lets the relay see the real client IP (nginx sets `X-Forwarded-For`,
and the relay reads it into `source_ip`).

## Pairing with `oauth2-proxy`

If you already run `oauth2-proxy` in front of nginx for your internal web
apps, you get OIDC-authenticated users for free. Add in the server block:

```nginx
auth_request /oauth2/auth;
error_page 401 = /oauth2/sign_in;

auth_request_set $auth_email $upstream_http_x_auth_request_email;
proxy_set_header X-Forwarded-Email $auth_email;
```

Then parse `X-Forwarded-Email` on the relay side if you want it in audit
events. The current code doesn't look at that header — you'd add a small
`HeaderTrustProvider` in `identity.py` (not included by default, to avoid
footguns around trusting whatever header is forwarded).

## Checklist

- [ ] `proxy_buffering off;` and `proxy_request_buffering off;`
- [ ] `proxy_read_timeout` ≥ expected idle SSH duration
- [ ] `proxy_http_version 1.1;` and `Connection: $connection_upgrade`
- [ ] TLS cert covers `RELAY_PUBLIC_HOST`
- [ ] Relay bound to `127.0.0.1` only (not `0.0.0.0`) if nginx is on the same
      host — nothing should reach the relay except via nginx
