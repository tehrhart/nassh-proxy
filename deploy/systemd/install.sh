#!/usr/bin/env bash
# Install ssh-relay as a systemd service.
# Idempotent — safe to re-run.
set -euo pipefail

APP_USER=${APP_USER:-ssh-relay}
APP_HOME=${APP_HOME:-/opt/ssh-relay}
SRC_DIR=${SRC_DIR:-$APP_HOME/src}
VENV_DIR=${VENV_DIR:-$APP_HOME/.venv}
ENV_DIR=${ENV_DIR:-/etc/ssh-relay}
LOG_DIR=${LOG_DIR:-/var/log/ssh-relay}
REPO_URL=${REPO_URL:-}   # Optional; if empty, copy from the current checkout.

need_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Run as root (or via sudo)." >&2
        exit 1
    fi
}

ensure_user() {
    if ! id -u "$APP_USER" >/dev/null 2>&1; then
        useradd --system --home-dir "$APP_HOME" --shell /usr/sbin/nologin "$APP_USER"
    fi
}

ensure_dirs() {
    install -d -o "$APP_USER" -g "$APP_USER" -m 0750 "$APP_HOME" "$ENV_DIR" "$LOG_DIR"
}

fetch_source() {
    if [[ -n "$REPO_URL" ]]; then
        if [[ -d $SRC_DIR/.git ]]; then
            sudo -u "$APP_USER" git -C "$SRC_DIR" pull --ff-only
        else
            sudo -u "$APP_USER" git clone "$REPO_URL" "$SRC_DIR"
        fi
    else
        # Copy the repo the script is invoked from.
        local here
        here=$(cd "$(dirname "$0")/../.." && pwd)
        install -d -o "$APP_USER" -g "$APP_USER" "$SRC_DIR"
        rsync -a --delete --exclude '.venv' --exclude '.git' --exclude '__pycache__' \
              --exclude '.certs' --exclude '.pytest_cache' \
              "$here"/ "$SRC_DIR"/
        chown -R "$APP_USER:$APP_USER" "$SRC_DIR"
    fi
}

ensure_venv() {
    if [[ ! -x $VENV_DIR/bin/uvicorn ]]; then
        sudo -u "$APP_USER" python3 -m venv "$VENV_DIR"
    fi
    sudo -u "$APP_USER" "$VENV_DIR/bin/pip" install --quiet --upgrade pip
    sudo -u "$APP_USER" "$VENV_DIR/bin/pip" install --quiet -e "$SRC_DIR"
}

install_unit() {
    install -m 0644 "$(dirname "$0")/ssh-relay.service" /etc/systemd/system/ssh-relay.service
    systemctl daemon-reload
}

maybe_seed_env() {
    if [[ ! -f $ENV_DIR/env ]]; then
        install -m 0640 -o "$APP_USER" -g "$APP_USER" \
                "$SRC_DIR/.env.example" "$ENV_DIR/env"
        echo "Seeded $ENV_DIR/env from .env.example — edit before starting."
    fi
}

main() {
    need_root
    ensure_user
    ensure_dirs
    fetch_source
    ensure_venv
    install_unit
    maybe_seed_env
    cat <<EOF

Installed.

Next:
  sudoedit $ENV_DIR/env
  sudo systemctl enable --now ssh-relay
  journalctl -u ssh-relay -f
EOF
}

main "$@"
