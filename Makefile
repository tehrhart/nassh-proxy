PYTHON  ?= python3
VENV    := .venv
PIP     := $(VENV)/bin/pip
UVICORN := $(VENV)/bin/uvicorn
PYTEST  := $(VENV)/bin/pytest

RELAY_HOST     ?= 127.0.0.1
RELAY_PORT     ?= 8080
RELAY_TLS_PORT ?= 8443

CERT_DIR := .certs
CERT     := $(CERT_DIR)/relay.pem
KEY      := $(CERT_DIR)/relay-key.pem

DEV_ENV := \
	RELAY_PUBLIC_HOST=$(RELAY_HOST) \
	RELAY_PUBLIC_PORT=$(RELAY_PORT) \
	RELAY_IDENTITY_PROVIDER=none \
	RELAY_AUTH_REQUIRED=false \
	RELAY_LOG_SINKS=stderr

DEV_TLS_ENV := \
	RELAY_PUBLIC_HOST=$(RELAY_HOST) \
	RELAY_PUBLIC_PORT=$(RELAY_TLS_PORT) \
	RELAY_IDENTITY_PROVIDER=none \
	RELAY_AUTH_REQUIRED=false \
	RELAY_LOG_SINKS=stderr

.PHONY: install test dev dev-tls tunnel dev-tunnel clean

install: $(VENV)/.stamp

$(VENV)/.stamp: pyproject.toml
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --quiet -e '.[dev]'
	@touch $@

test: install
	$(PYTEST) tests/ -v

dev: install
	$(DEV_ENV) $(UVICORN) ssh_relay.app:app \
		--host $(RELAY_HOST) --port $(RELAY_PORT) --reload

dev-tls: install $(CERT)
	$(DEV_TLS_ENV) $(UVICORN) ssh_relay.app:app \
		--host $(RELAY_HOST) --port $(RELAY_TLS_PORT) \
		--ssl-certfile $(CERT) --ssl-keyfile $(KEY) --reload

$(CERT):
	@command -v mkcert >/dev/null || { \
		echo "mkcert not found. Install: https://github.com/FiloSottile/mkcert"; \
		exit 1; }
	@mkdir -p $(CERT_DIR)
	mkcert -install
	mkcert -cert-file $(CERT) -key-file $(KEY) localhost 127.0.0.1 ::1

tunnel:
	cloudflared tunnel --url http://$(RELAY_HOST):$(RELAY_PORT)

dev-tunnel: install
	@trap 'kill 0' INT TERM; \
	env $(DEV_ENV) $(UVICORN) ssh_relay.app:app --host $(RELAY_HOST) --port $(RELAY_PORT) & \
	cloudflared tunnel --url http://$(RELAY_HOST):$(RELAY_PORT) & \
	wait

clean:
	rm -rf $(VENV) .pytest_cache $(CERT_DIR)
