# Deploy on GCP behind IAP

Google's Identity-Aware Proxy fronts an external HTTPS Load Balancer and
forwards requests with a signed `x-goog-iap-jwt-assertion` header. The relay
validates that assertion.

**GAE / Cloud Run don't work for long-lived WebSockets to arbitrary ports**
the way this relay needs (Cloud Run supports WebSockets, but with request
timeouts that kneecap SSH sessions). Run on **Compute Engine** (VM or MIG) or
GKE with a pod-native backend service.

```
Browser ──TLS──▶ HTTPS LB (IAP) ──HTTP + JWT──▶ GCE VM running relay
```

## 1. Provision the VM (or MIG)

A one-shot script is at
[`deploy/gcp/deploy-gce.sh`](../../deploy/gcp/deploy-gce.sh). It creates a
Debian 12 VM, installs the relay as a systemd unit, and opens port 8080 to
the IAP IP range.

```bash
cd deploy/gcp
export PROJECT=my-gcp-project
export REGION=us-central1
export ZONE=us-central1-a
export NAME=ssh-relay-01
./deploy-gce.sh
```

The script:

1. Creates a service account for the VM with `roles/logging.logWriter`.
2. Boots a `e2-small` VM with a startup script that installs the relay.
3. Adds a firewall rule allowing TCP/8080 from the GCP LB health-check ranges
   (`130.211.0.0/22`, `35.191.0.0/16`) and the IAP range
   (`35.235.240.0/20` for IAP-authenticated traffic).

Edit the script first to pin your source ref and match your environment.

## 2. Create the Load Balancer

IAP requires an **external Application Load Balancer** (global or regional).
Easiest path is the console — **Network Services → Load balancing → Create →
Application Load Balancer (HTTP/S) → From internet to my VMs**:

- **Backend**: instance group containing the VM from step 1, port `8080`.
- **Backend protocol**: `HTTP`.
- **Health check**: HTTP to `/healthz` on port `8080`, expect `200`.
- **Host/path rules**: all paths → the backend.
- **Frontend**: HTTPS, with a Google-managed certificate for
  `ssh-relay.example.com`.
- **Timeouts**: set **backend service timeout** to something large
  (e.g., `86400s`) — the default 30 s will kill WebSockets.

gcloud equivalent lives as comments at the bottom of `deploy-gce.sh`.

## 3. Enable IAP on the backend

**Security → Identity-Aware Proxy**, flip the toggle on the backend service.
Grant `IAP-secured Web App User` to the Google group that should reach the
relay.

From the IAP panel, copy the backend service's OAuth audience — it's
`/projects/<PROJECT_NUMBER>/global/backendServices/<BACKEND_SERVICE_ID>`.
Note: **project number**, not project id. Find it with:

```bash
gcloud projects describe $PROJECT --format='value(projectNumber)'
gcloud compute backend-services describe ssh-relay-backend --global --format='value(id)'
```

That full string goes into `RELAY_IAP_AUDIENCE`.

## 4. Configure the relay

On the VM, edit `/etc/ssh-relay/env`:

```bash
RELAY_PUBLIC_HOST=ssh-relay.example.com
RELAY_PUBLIC_PORT=443
RELAY_IDENTITY_PROVIDER=gcp-iap
RELAY_IAP_AUDIENCE=/projects/123456789012/global/backendServices/9876543210987654321
RELAY_AUTH_REQUIRED=true
RELAY_LOG_SINKS=stderr
```

```bash
sudo systemctl restart ssh-relay
```

## 5. Point the extension at the LB

Same as the CF Access flow — the extension doesn't care what's in front:

```
--proxy-host=ssh-relay.example.com
--proxy-port=443
--proxy-mode=corp-relay-v4@google.com
--use-ssl=true
```

## 6. Smoke test

```bash
# In a browser, signed in as an IAP-authorized user:
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
     https://ssh-relay.example.com/healthz
# Expect: {"ok":true}
```

## IAP specifics

- **JWT algorithm is ES256.** The relay pulls the Google public JWKS at
  `https://www.gstatic.com/iap/verify/public_key-jwk`.
- **Issuer** is `https://cloud.google.com/iap`.
- **`sub`** is a stable user ID (`accounts.google.com:...`). **`email`** is
  the user's email. The relay uses `email` if present, else `sub`, as the
  session owner key for reconnect.
- **Health check must bypass IAP** — either configure IAP to exempt
  `/healthz` from auth, or run the LB probe on the raw VM port via a second
  unauthenticated backend. Most folks just point the probe at the VM's
  internal IP directly (that's what the deploy script does by opening 8080 to
  the LB health-check range).

## Why not Cloud Run?

Cloud Run tolerates WebSockets up to 60 min per request (configurable up to
some limits), and it does attach an IAP JWT when IAP is enabled — but:

- Source-port pinning (PAN User-ID) is meaningless: you don't control the
  egress IP or port on Cloud Run.
- The service bills per request-second, which with long SSH sessions adds
  up unpredictably.

If you don't need PAN User-ID and your sessions are short, Cloud Run *can*
work. The relay code itself doesn't care. But GCE is the recommended path.
