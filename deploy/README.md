# Deployment assets

Example configs and scripts referenced from [`docs/deploy/`](../docs/deploy/).
Everything here is intended to be copied and adapted — nothing is picked up
automatically.

```
deploy/
├── apache/          Virtual host with mod_proxy_wstunnel.
├── cloudflared/     Named-tunnel config pointing at the local relay.
├── docker/          docker-compose.yml for a local Docker run.
├── gcp/             One-shot GCE deployment script (VM + firewall + SA).
├── nginx/           TLS-terminating reverse proxy with WebSocket upgrade.
└── systemd/         Unit file + installer for running on a bare VM.
```

Start from the doc that matches your target platform:

- [Cloudflare Access](../docs/deploy/cloudflare-access.md)
- [GCP IAP](../docs/deploy/gcp-iap.md)
- [nginx](../docs/deploy/nginx.md)
- [Apache](../docs/deploy/apache.md)
