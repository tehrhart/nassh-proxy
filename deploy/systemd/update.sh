#!/usr/bin/env bash
# Update an existing ssh-relay install in place.
# Pulls latest code, reinstalls deps only if pyproject.toml changed, restarts
# the service, and shows status. Idempotent — safe to re-run.
set -euo pipefail

APP_USER=${APP_USER:-ssh-relay}
APP_HOME=${APP_HOME:-/opt/ssh-relay}
SRC_DIR=${SRC_DIR:-$APP_HOME/src}
VENV_DIR=${VENV_DIR:-$APP_HOME/.venv}
SERVICE=${SERVICE:-ssh-relay}

need_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Run as root (or via sudo)." >&2
        exit 1
    fi
}

require_git_checkout() {
    if [[ ! -d $SRC_DIR/.git ]]; then
        cat >&2 <<EOF
$SRC_DIR is not a git checkout. This script only updates git-based installs.
For rsync-based installs, re-run deploy/systemd/install.sh from your source tree.
EOF
        exit 2
    fi
}

main() {
    need_root
    require_git_checkout

    local old_hash new_hash pyproject_changed=0

    old_hash=$(sudo -u "$APP_USER" git -C "$SRC_DIR" rev-parse HEAD)
    sudo -u "$APP_USER" git -C "$SRC_DIR" fetch --quiet origin
    sudo -u "$APP_USER" git -C "$SRC_DIR" pull --ff-only
    new_hash=$(sudo -u "$APP_USER" git -C "$SRC_DIR" rev-parse HEAD)

    if [[ $old_hash == "$new_hash" ]]; then
        echo "Already at $new_hash — nothing to do."
        systemctl status --no-pager "$SERVICE" | head -5 || true
        exit 0
    fi

    echo "Updated $old_hash → $new_hash"

    if sudo -u "$APP_USER" git -C "$SRC_DIR" diff --name-only "$old_hash" "$new_hash" \
            | grep -qx 'pyproject.toml'; then
        pyproject_changed=1
    fi

    if (( pyproject_changed )); then
        echo "pyproject.toml changed — reinstalling dependencies."
        sudo -u "$APP_USER" "$VENV_DIR/bin/pip" install --quiet -e "$SRC_DIR"
    fi

    systemctl restart "$SERVICE"
    sleep 1
    systemctl status --no-pager "$SERVICE" | head -10
    echo
    echo "Tail logs with: journalctl -u $SERVICE -fn 50"
}

main "$@"
