set shell := ["bash", "-euo", "pipefail", "-c"]

python     := "python3"
venv       := ".venv"
pip        := venv / "bin/pip"
uvicorn    := venv / "bin/uvicorn"
pytest     := venv / "bin/pytest"

relay_host     := env_var_or_default("RELAY_HOST", "127.0.0.1")
relay_port     := env_var_or_default("RELAY_PORT", "8080")
relay_tls_port := env_var_or_default("RELAY_TLS_PORT", "8443")

cert_dir := ".certs"
cert     := cert_dir / "relay.pem"
key      := cert_dir / "relay-key.pem"

export RELAY_PUBLIC_HOST      := relay_host
export RELAY_IDENTITY_PROVIDER := "none"
export RELAY_AUTH_REQUIRED    := "false"
export RELAY_LOG_SINKS        := "stderr"

default:
    @just --list

install:
    test -d {{venv}} || {{python}} -m venv {{venv}}
    {{pip}} install --quiet -e '.[dev]'

test: install
    {{pytest}} tests/ -v

dev: install
    RELAY_PUBLIC_PORT={{relay_port}} {{uvicorn}} ssh_relay.app:app --host {{relay_host}} --port {{relay_port}} --reload

dev-tls: install cert
    RELAY_PUBLIC_PORT={{relay_tls_port}} {{uvicorn}} ssh_relay.app:app \
        --host {{relay_host}} --port {{relay_tls_port}} \
        --ssl-certfile {{cert}} --ssl-keyfile {{key}} --reload

cert:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -f {{cert}} && -f {{key}} ]]; then exit 0; fi
    command -v mkcert >/dev/null || { echo "install mkcert: https://github.com/FiloSottile/mkcert"; exit 1; }
    mkdir -p {{cert_dir}}
    mkcert -install
    mkcert -cert-file {{cert}} -key-file {{key}} localhost 127.0.0.1 ::1

tunnel:
    cloudflared tunnel --url http://{{relay_host}}:{{relay_port}}

dev-tunnel: install
    #!/usr/bin/env bash
    set -euo pipefail
    trap 'kill 0' INT TERM
    {{uvicorn}} ssh_relay.app:app --host {{relay_host}} --port {{relay_port}} &
    cloudflared tunnel --url http://{{relay_host}}:{{relay_port}} &
    wait

clean:
    rm -rf {{venv}} .pytest_cache {{cert_dir}}
