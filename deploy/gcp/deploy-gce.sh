#!/usr/bin/env bash
# Provision a GCE VM running the ssh-relay behind IAP.
#
# Required env: PROJECT, REGION, ZONE, NAME
# Optional env:
#   MACHINE_TYPE (default e2-small)
#   IMAGE_FAMILY (default debian-12)
#   NETWORK      (default default)
#   SUBNET       (default default)
#   RELAY_REPO_URL — git URL the VM will clone at boot.
#                    If empty, the startup script bootstraps from a release tarball URL
#                    set in RELAY_TARBALL_URL instead.
#
# After this script:
#   1. Create an HTTPS LB pointing at this VM on port 8080 (see bottom).
#   2. Enable IAP on the backend service.
#   3. Edit /etc/ssh-relay/env on the VM with RELAY_IAP_AUDIENCE.

set -euo pipefail

: "${PROJECT:?set PROJECT}"
: "${REGION:?set REGION}"
: "${ZONE:?set ZONE}"
: "${NAME:?set NAME}"
MACHINE_TYPE=${MACHINE_TYPE:-e2-small}
IMAGE_FAMILY=${IMAGE_FAMILY:-debian-12}
NETWORK=${NETWORK:-default}
SUBNET=${SUBNET:-default}
SA_NAME=${SA_NAME:-ssh-relay-runtime}
SA_EMAIL="${SA_NAME}@${PROJECT}.iam.gserviceaccount.com"
FW_NAME=${FW_NAME:-ssh-relay-allow-lb-iap}

gcloud config set project "$PROJECT" >/dev/null

# ---- Service account ---------------------------------------------------------
if ! gcloud iam service-accounts describe "$SA_EMAIL" >/dev/null 2>&1; then
    gcloud iam service-accounts create "$SA_NAME" --display-name "ssh-relay runtime"
    gcloud projects add-iam-policy-binding "$PROJECT" \
        --member "serviceAccount:$SA_EMAIL" \
        --role   "roles/logging.logWriter" >/dev/null
fi

# ---- Firewall ---------------------------------------------------------------
# Allow TCP/8080 from the GCP health-check ranges and IAP's TCP-forwarding range.
if ! gcloud compute firewall-rules describe "$FW_NAME" >/dev/null 2>&1; then
    gcloud compute firewall-rules create "$FW_NAME" \
        --network "$NETWORK" \
        --direction INGRESS \
        --action ALLOW \
        --rules tcp:8080 \
        --source-ranges 130.211.0.0/22,35.191.0.0/16,35.235.240.0/20 \
        --target-tags ssh-relay
fi

# ---- Startup script ---------------------------------------------------------
STARTUP=$(mktemp)
cat >"$STARTUP" <<'STARTUP_EOF'
#!/usr/bin/env bash
set -euo pipefail
exec > >(tee -a /var/log/ssh-relay-startup.log) 2>&1

apt-get update
apt-get install -y python3-venv git rsync

useradd --system --home-dir /opt/ssh-relay --shell /usr/sbin/nologin ssh-relay || true
install -d -o ssh-relay -g ssh-relay -m 0750 /opt/ssh-relay /etc/ssh-relay /var/log/ssh-relay

cd /opt/ssh-relay
if [[ ! -d src/.git ]]; then
    sudo -u ssh-relay git clone "__REPO_URL__" src
fi
sudo -u ssh-relay python3 -m venv .venv
sudo -u ssh-relay .venv/bin/pip install --quiet --upgrade pip
sudo -u ssh-relay .venv/bin/pip install --quiet -e src

if [[ ! -f /etc/ssh-relay/env ]]; then
    install -m 0640 -o ssh-relay -g ssh-relay src/.env.example /etc/ssh-relay/env
    # Override a few defaults for GCP/IAP.
    sed -i \
        -e 's|^RELAY_IDENTITY_PROVIDER=.*|RELAY_IDENTITY_PROVIDER=gcp-iap|' \
        -e 's|^# RELAY_IAP_AUDIENCE=.*|RELAY_IAP_AUDIENCE=PLACEHOLDER_SET_ME|' \
        /etc/ssh-relay/env
fi

install -m 0644 src/deploy/systemd/ssh-relay.service /etc/systemd/system/ssh-relay.service
systemctl daemon-reload
systemctl enable --now ssh-relay
STARTUP_EOF

REPO_URL=${RELAY_REPO_URL:-https://github.com/yourorg/ssh-relay.git}
sed -i "s|__REPO_URL__|$REPO_URL|" "$STARTUP"

# ---- Instance ---------------------------------------------------------------
gcloud compute instances create "$NAME" \
    --zone "$ZONE" \
    --machine-type "$MACHINE_TYPE" \
    --image-family "$IMAGE_FAMILY" \
    --image-project debian-cloud \
    --network "$NETWORK" --subnet "$SUBNET" \
    --service-account "$SA_EMAIL" \
    --scopes cloud-platform \
    --tags ssh-relay \
    --metadata-from-file startup-script="$STARTUP"

rm -f "$STARTUP"

cat <<EOF

VM '$NAME' created in $ZONE.

Next steps:

1. Wait ~2 min for the startup script to install the relay. Check with:
     gcloud compute instances get-serial-port-output $NAME --zone $ZONE | tail -50

2. Create an unmanaged instance group + HTTPS LB:
     gcloud compute instance-groups unmanaged create ssh-relay-ig --zone $ZONE
     gcloud compute instance-groups unmanaged add-instances ssh-relay-ig --zone $ZONE --instances $NAME
     gcloud compute instance-groups unmanaged set-named-ports ssh-relay-ig --zone $ZONE --named-ports http:8080

     gcloud compute health-checks create http ssh-relay-hc \
         --request-path /healthz --port 8080

     gcloud compute backend-services create ssh-relay-backend \
         --protocol HTTP --port-name http \
         --health-checks ssh-relay-hc \
         --timeout 86400 \
         --global
     gcloud compute backend-services add-backend ssh-relay-backend \
         --instance-group ssh-relay-ig --instance-group-zone $ZONE --global

     # URL map + HTTPS proxy + managed cert + forwarding rule:
     gcloud compute url-maps create ssh-relay-urlmap --default-service ssh-relay-backend
     gcloud compute ssl-certificates create ssh-relay-cert \
         --domains ssh-relay.example.com --global
     gcloud compute target-https-proxies create ssh-relay-https \
         --url-map ssh-relay-urlmap --ssl-certificates ssh-relay-cert
     gcloud compute forwarding-rules create ssh-relay-fr \
         --global --target-https-proxy ssh-relay-https --ports 443

3. Enable IAP on ssh-relay-backend, grant IAP-secured Web App User to your group.

4. Read the audience and set it on the VM:
     PN=\$(gcloud projects describe $PROJECT --format='value(projectNumber)')
     BID=\$(gcloud compute backend-services describe ssh-relay-backend --global --format='value(id)')
     echo "RELAY_IAP_AUDIENCE=/projects/\$PN/global/backendServices/\$BID"
   Edit /etc/ssh-relay/env on the VM with that value and 'systemctl restart ssh-relay'.
EOF
