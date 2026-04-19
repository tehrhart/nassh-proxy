from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket
from fastapi.responses import HTMLResponse
from pydantic_settings import BaseSettings, SettingsConfigDict

from .events import EventBus, Sink, new_event_id, now
from .identity import Identity, IdentityProvider, build_provider
from .net import open_tcp
from .ports import NoPool, PortPool
from .session import Session, SessionGone, SessionLimits
from .sinks import PanUserIdSink, RotatingFileSink, SplunkHECSink, StderrSink

log = logging.getLogger("ssh_relay")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RELAY_", env_file=".env", extra="ignore")

    public_host: str
    public_port: int = 443

    # Identity: "none" | "cloudflare-access" | "gcp-iap"
    identity_provider: str = "none"
    auth_required: bool = True
    cf_team_domain: str | None = None
    cf_audience: str | None = None
    iap_audience: str | None = None

    # Session
    read_chunk_bytes: int = 64 * 1024
    max_frame_bytes: int = 1 * 1024 * 1024
    max_replay_buffer: int = 4 * 1024 * 1024
    grace_seconds: int = 120

    # Source-port binding (PAN User-ID mapping). Disabled when min/max unset.
    source_port_min: int | None = None
    source_port_max: int | None = None
    relay_ip: str | None = None  # Public IP used in PAN mappings.

    # Log sinks: comma-separated subset of {stderr, file, splunk, pan}.
    log_sinks: str = "stderr"
    log_file_path: str | None = None
    log_file_max_bytes: int = 100 * 1024 * 1024
    log_file_backup_count: int = 10

    # Splunk HEC
    splunk_url: str | None = None
    splunk_token: str | None = None
    splunk_index: str | None = None
    splunk_source: str = "ssh-relay"
    splunk_sourcetype: str = "_json"
    splunk_verify: bool = True

    # Palo Alto Networks User-ID
    pan_firewall_urls: str | None = None  # comma-separated
    pan_api_key: str | None = None
    pan_verify: bool = True
    pan_login_timeout_seconds: int = 0


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings()
    app.state.settings = settings
    app.state.provider = _build_identity(settings)
    app.state.port_pool = _build_port_pool(settings)
    app.state.bus = EventBus(_build_sinks(settings))
    await app.state.bus.start()
    app.state.sessions = {}
    try:
        yield
    finally:
        for sess in list(app.state.sessions.values()):
            await sess.close(reason="server_shutdown")
        app.state.sessions.clear()
        await app.state.bus.stop()


app = FastAPI(lifespan=lifespan)


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.get("/cookie")
async def cookie(
    request: Request,
    ext: str = Query(...),
    path: str = Query(...),
    version: str = Query("2"),
    method: str = Query("js-redirect"),
):
    identity = _require_identity(request)
    settings: Settings = request.app.state.settings
    if version != "2" or method != "js-redirect":
        raise HTTPException(400, "unsupported /cookie version/method")
    if not _is_safe_ext_id(ext) or not _is_safe_path(path):
        raise HTTPException(400, "invalid ext or path")

    bus: EventBus = request.app.state.bus
    ts_iso, ts = now()
    bus.emit({
        "event": "handshake",
        "event_id": new_event_id(),
        "ts": ts_iso,
        "ts_epoch": ts,
        "identity": _identity_dict(identity),
        "source_ip": _request_source_ip(request),
        "user_agent": request.headers.get("user-agent"),
        "extension_id": ext,
        "redirect_path": path,
    })

    payload = {"endpoint": f"{settings.public_host}:{settings.public_port}"}
    fragment = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    target = f"chrome-extension://{ext}/{path}#{fragment}"
    html = (
        "<!doctype html><html><body><script>"
        f"window.location.replace({json.dumps(target)});"
        "</script></body></html>"
    )
    return HTMLResponse(html)


@app.websocket("/v4/connect")
async def v4_connect(
    ws: WebSocket,
    host: str,
    port: int,
    dstUsername: str | None = None,  # noqa: N803 — nassh protocol field name
):
    identity = _identity_for_ws(ws)
    if identity is False:
        await ws.close(code=4401)
        return

    port_pool: PortPool | NoPool = ws.app.state.port_pool
    bus: EventBus = ws.app.state.bus
    settings: Settings = ws.app.state.settings

    source_port = await port_pool.acquire()
    dial_started = time.monotonic()
    try:
        reader, writer, actual_source_port = await open_tcp(host, port, source_port=source_port)
    except OSError as e:
        log.warning("dial failed %s:%s %s", host, port, e)
        await port_pool.release(source_port)
        await ws.accept(subprotocol="ssh")
        await ws.close(code=4502)
        return

    await ws.accept(subprotocol="ssh")
    sid = uuid.uuid4().hex
    identity_key = identity.principal if isinstance(identity, Identity) else None

    meta = _build_meta(
        ws=ws,
        identity=identity,
        target_host=host,
        target_port=port,
        target_username=dstUsername,
        source_port=actual_source_port,
        dial_seconds=round(time.monotonic() - dial_started, 4),
    )

    async def _release_port():
        await port_pool.release(actual_source_port)

    session = Session(
        sid=sid,
        identity_key=identity_key,
        tcp_reader=reader,
        tcp_writer=writer,
        limits=_limits(settings),
        meta=meta,
        emit=bus.emit,
        on_close=_release_port,
    )
    sessions: dict[str, Session] = ws.app.state.sessions
    sessions[sid] = session
    session.emit_start()

    await _run_session(ws, session, sessions, resume_from=None)


@app.websocket("/v4/reconnect")
async def v4_reconnect(ws: WebSocket, sid: str, ack: int):
    identity = _identity_for_ws(ws)
    if identity is False:
        await ws.close(code=4401)
        return

    sessions: dict[str, Session] = ws.app.state.sessions
    session = sessions.get(sid)
    identity_key = identity.principal if isinstance(identity, Identity) else None
    if session is None or session.closed or session.identity_key != identity_key:
        await ws.accept(subprotocol="ssh")
        await ws.close(code=4404)
        return

    session.cancel_grace()
    session.note_reconnect(
        source_ip=_source_ip(ws),
        user_agent=ws.headers.get("user-agent"),
        resume_ack=ack,
    )
    await ws.accept(subprotocol="ssh")
    await _run_session(ws, session, sessions, resume_from=ack)


async def _run_session(ws: WebSocket, session: Session, sessions: dict, resume_from: int | None):
    try:
        await session.handle(ws, resume_from=resume_from)
    except SessionGone as e:
        log.info("sid=%s gone: %s", session.sid, e)
        session._closed = True  # noqa: SLF001
        await session.close(reason="session_gone", error=str(e))
    except Exception as e:
        log.exception("sid=%s handler error", session.sid)
        session._closed = True  # noqa: SLF001
        await session.close(reason="handler_error", error=str(e))
    finally:
        if session.closed:
            sessions.pop(session.sid, None)
            await session.close(reason="closed")
        else:
            session.arm_grace(sessions)


def _build_identity(s: Settings) -> IdentityProvider:
    kind = s.identity_provider.lower()

    # Fail loudly when provider-specific credentials are set but the provider
    # isn't selected. A silent fall-through to the 'none' provider means every
    # request is unauthenticated — the opposite of what the operator intended.
    if kind != "cloudflare-access" and (s.cf_team_domain or s.cf_audience):
        raise RuntimeError(
            "RELAY_CF_TEAM_DOMAIN / RELAY_CF_AUDIENCE are set but "
            f"RELAY_IDENTITY_PROVIDER={s.identity_provider!r}. "
            "Set RELAY_IDENTITY_PROVIDER=cloudflare-access to activate, "
            "or unset the CF_* variables."
        )
    if kind != "gcp-iap" and s.iap_audience:
        raise RuntimeError(
            "RELAY_IAP_AUDIENCE is set but "
            f"RELAY_IDENTITY_PROVIDER={s.identity_provider!r}. "
            "Set RELAY_IDENTITY_PROVIDER=gcp-iap to activate, "
            "or unset RELAY_IAP_AUDIENCE."
        )

    if kind == "cloudflare-access":
        if not s.cf_team_domain or not s.cf_audience:
            raise RuntimeError("RELAY_CF_TEAM_DOMAIN and RELAY_CF_AUDIENCE required")
        return build_provider(
            kind,
            team_domain=s.cf_team_domain,
            audience=s.cf_audience,
            required=s.auth_required,
        )
    if kind == "gcp-iap":
        if not s.iap_audience:
            raise RuntimeError("RELAY_IAP_AUDIENCE required")
        return build_provider(kind, audience=s.iap_audience, required=s.auth_required)
    return build_provider("none")


def _build_port_pool(s: Settings) -> PortPool | NoPool:
    if s.source_port_min is None or s.source_port_max is None:
        return NoPool()
    return PortPool(s.source_port_min, s.source_port_max)


def _build_sinks(s: Settings) -> list[Sink]:
    names = [n.strip() for n in s.log_sinks.split(",") if n.strip()]
    sinks: list[Sink] = []
    for name in names:
        if name == "stderr":
            sinks.append(StderrSink())
        elif name == "file":
            if not s.log_file_path:
                raise RuntimeError("RELAY_LOG_FILE_PATH required for file sink")
            sinks.append(
                RotatingFileSink(
                    s.log_file_path,
                    max_bytes=s.log_file_max_bytes,
                    backup_count=s.log_file_backup_count,
                )
            )
        elif name == "splunk":
            if not s.splunk_url or not s.splunk_token:
                raise RuntimeError("RELAY_SPLUNK_URL and RELAY_SPLUNK_TOKEN required")
            sinks.append(
                SplunkHECSink(
                    url=s.splunk_url,
                    token=s.splunk_token,
                    index=s.splunk_index,
                    source=s.splunk_source,
                    sourcetype=s.splunk_sourcetype,
                    verify=s.splunk_verify,
                )
            )
        elif name == "pan":
            if not s.pan_firewall_urls or not s.pan_api_key or not s.relay_ip:
                raise RuntimeError(
                    "RELAY_PAN_FIREWALL_URLS, RELAY_PAN_API_KEY, RELAY_RELAY_IP required"
                )
            urls = [u.strip() for u in s.pan_firewall_urls.split(",") if u.strip()]
            sinks.append(
                PanUserIdSink(
                    firewall_urls=urls,
                    api_key=s.pan_api_key,
                    relay_ip=s.relay_ip,
                    verify=s.pan_verify,
                    login_timeout_seconds=s.pan_login_timeout_seconds,
                )
            )
        else:
            raise RuntimeError(f"unknown sink: {name}")
    return sinks


def _build_meta(
    ws: WebSocket,
    identity: Identity | None,
    target_host: str,
    target_port: int,
    target_username: str | None,
    source_port: int | None,
    dial_seconds: float,
) -> dict[str, Any]:
    return {
        "identity": _identity_dict(identity),
        "source_ip": _source_ip(ws),
        "source_port": source_port,
        "user_agent": ws.headers.get("user-agent"),
        "target_host": target_host,
        "target_port": target_port,
        "target_username": target_username,
        "dial_seconds": dial_seconds,
    }


def _source_ip(ws: WebSocket) -> str | None:
    ip = ws.headers.get("cf-connecting-ip")
    if ip:
        return ip
    xff = ws.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    client = ws.client
    return client.host if client else None


def _limits(settings: Settings) -> SessionLimits:
    return SessionLimits(
        read_chunk_bytes=settings.read_chunk_bytes,
        max_replay_buffer=settings.max_replay_buffer,
        max_frame_bytes=settings.max_frame_bytes,
        grace_seconds=settings.grace_seconds,
    )


def _require_identity(request: Request) -> Identity | None:
    provider: IdentityProvider = request.app.state.provider
    try:
        return provider.identify(request.headers)
    except PermissionError as e:
        raise HTTPException(401, str(e))
    except Exception as e:
        raise HTTPException(401, f"invalid identity assertion: {e}")


def _identity_dict(identity: Identity | None) -> dict[str, Any] | None:
    if isinstance(identity, Identity):
        return {"provider": identity.provider, "sub": identity.sub, "email": identity.email}
    return None


def _request_source_ip(request: Request) -> str | None:
    ip = request.headers.get("cf-connecting-ip")
    if ip:
        return ip
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    client = request.client
    return client.host if client else None


def _identity_for_ws(ws: WebSocket) -> Identity | None | bool:
    provider: IdentityProvider = ws.app.state.provider
    try:
        return provider.identify(ws.headers)
    except PermissionError:
        return False
    except Exception:
        return False


def _is_safe_ext_id(ext: str) -> bool:
    return len(ext) == 32 and all("a" <= c <= "p" for c in ext)


def _is_safe_path(path: str) -> bool:
    return ".." not in path and "\x00" not in path and "\r" not in path and "\n" not in path
