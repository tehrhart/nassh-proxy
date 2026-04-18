# Deploy behind Apache httpd

Apache can proxy WebSockets with `mod_proxy_wstunnel`. If you already run
Apache for other apps — say, behind `mod_auth_openidc` for OIDC — plugging
the relay in is straightforward.

## Required modules

```bash
sudo a2enmod proxy proxy_http proxy_wstunnel headers rewrite ssl
# optional auth:
sudo a2enmod auth_openidc
sudo systemctl reload apache2
```

## Config

Copy [`deploy/apache/ssh-relay.conf`](../../deploy/apache/ssh-relay.conf)
to `/etc/apache2/sites-available/`, edit the `ServerName` and cert paths,
then:

```bash
sudo a2ensite ssh-relay
sudo apachectl configtest
sudo systemctl reload apache2
```

The important bits:

```apache
<VirtualHost *:443>
    ServerName ssh-relay.example.com

    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/ssh-relay.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/ssh-relay.example.com/privkey.pem

    # Route WebSocket upgrades to the relay's WS port; keep HTTP for the cookie.
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteRule ^/(.*)$ ws://127.0.0.1:8080/$1 [P,L]

    ProxyPreserveHost On
    ProxyRequests Off
    ProxyPass        / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/

    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-For   "%{REMOTE_ADDR}s"

    # SSH idles.
    ProxyTimeout 86400
</VirtualHost>
```

`mod_proxy_wstunnel` via the `RewriteRule [P]` trick is the standard idiom —
the rewrite only fires when the `Upgrade: websocket` header is present, so
the `/cookie` HTTP GET still falls through to the HTTP `ProxyPass`.

## Authentication via `mod_auth_openidc`

Terminate OIDC at Apache, then pass the authenticated identity downstream:

```apache
OIDCProviderMetadataURL https://idp.example.com/.well-known/openid-configuration
OIDCClientID            ssh-relay
OIDCClientSecret        <secret>
OIDCRedirectURI         https://ssh-relay.example.com/oidc-callback
OIDCCryptoPassphrase    <random>
OIDCScope               "openid email profile"

<Location />
    AuthType openid-connect
    Require valid-user
</Location>

# Pass the email downstream so the relay can read it.
RequestHeader set X-Auth-Email "%{OIDC_CLAIM_email}e"
```

`RELAY_IDENTITY_PROVIDER=none` again — Apache is the identity authority. The
relay won't populate `identity` in audit events unless you add a
header-trust provider (same caveat as in the nginx guide).

## Start the relay

```bash
RELAY_PUBLIC_HOST=ssh-relay.example.com \
RELAY_PUBLIC_PORT=443 \
RELAY_IDENTITY_PROVIDER=none \
RELAY_AUTH_REQUIRED=false \
uvicorn ssh_relay.app:app \
  --host 127.0.0.1 --port 8080 \
  --proxy-headers --forwarded-allow-ips "127.0.0.1"
```

## Gotchas

- **`ProxyTimeout`** defaults to 60 s. Raise it for SSH idle sessions.
- **`ProxyIOBufferSize`** defaults to 8 KiB. That's fine — don't raise it
  enough to trip `RELAY_MAX_FRAME_BYTES`.
- **`mod_reqtimeout`** can kill slow WebSocket handshakes on stressed
  systems. If you see random handshake drops, check
  `RequestReadTimeout handshake=20` and relax it.
- **HTTP/2 upstream**: `ProxyPass h2c://...` is *not* how you do WebSockets
  via Apache. Stick to `http://` / `ws://` for the upstream; the public
  listener can still be HTTP/2 for non-WS requests.
