"""Log sinks: stderr JSONL, rotating file, Splunk HEC, Palo Alto Networks User-ID."""

from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
import sys
from html import escape

import httpx

log = logging.getLogger("ssh_relay.sinks")


class StderrSink:
    name = "stderr"

    async def emit(self, event: dict) -> None:
        sys.stderr.write(json.dumps(event, default=str) + "\n")
        sys.stderr.flush()

    async def close(self) -> None:
        pass


class RotatingFileSink:
    name = "file"

    def __init__(self, path: str, max_bytes: int = 100 * 1024 * 1024, backup_count: int = 10):
        self._handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
        )

    async def emit(self, event: dict) -> None:
        line = json.dumps(event, default=str)
        await asyncio.get_running_loop().run_in_executor(None, self._write, line)

    def _write(self, line: str) -> None:
        rec = logging.LogRecord(
            name=self.name,
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=line,
            args=(),
            exc_info=None,
        )
        self._handler.emit(rec)

    async def close(self) -> None:
        await asyncio.get_running_loop().run_in_executor(None, self._handler.close)


class SplunkHECSink:
    name = "splunk"

    def __init__(
        self,
        url: str,
        token: str,
        index: str | None = None,
        source: str = "ssh-relay",
        sourcetype: str = "_json",
        verify: bool = True,
        timeout: float = 10.0,
    ):
        self._url = url.rstrip("/") + "/services/collector/event"
        self._headers = {"Authorization": f"Splunk {token}"}
        self._index = index
        self._source = source
        self._sourcetype = sourcetype
        self._client = httpx.AsyncClient(verify=verify, timeout=timeout)

    async def emit(self, event: dict) -> None:
        payload: dict = {"event": event, "sourcetype": self._sourcetype, "source": self._source}
        if self._index:
            payload["index"] = self._index
        if "ts_unix" in event:
            payload["time"] = event["ts_unix"]
        resp = await self._client.post(self._url, json=payload, headers=self._headers)
        resp.raise_for_status()

    async def close(self) -> None:
        await self._client.aclose()


class PanUserIdSink:
    """Palo Alto Networks User-ID XML API: push per-session IP+port → user mappings."""

    name = "pan"

    def __init__(
        self,
        firewall_urls: list[str],
        api_key: str,
        relay_ip: str,
        timeout: float = 5.0,
        verify: bool = True,
        login_timeout_seconds: int = 0,
    ):
        self._urls = firewall_urls
        self._api_key = api_key
        self._relay_ip = relay_ip
        self._login_timeout = login_timeout_seconds
        self._client = httpx.AsyncClient(timeout=timeout, verify=verify)

    async def emit(self, event: dict) -> None:
        evt = event.get("event")
        if evt == "session.start":
            await self._push("login", event)
        elif evt == "session.close":
            await self._push("logout", event)

    async def _push(self, action: str, event: dict) -> None:
        identity = event.get("identity") or {}
        user = identity.get("email") or identity.get("sub")
        port = event.get("source_port")
        if not user or not port:
            return  # No meaningful mapping to push.
        xml = self._build_xml(action, user, int(port))
        for url in self._urls:
            try:
                resp = await self._client.post(
                    url.rstrip("/") + "/api/",
                    params={"type": "user-id", "key": self._api_key},
                    content=xml,
                    headers={"Content-Type": "application/xml"},
                )
                resp.raise_for_status()
            except Exception as e:
                log.warning("pan %s push to %s failed: %s", action, url, e)

    def _build_xml(self, action: str, user: str, port: int) -> str:
        u = escape(user, quote=True)
        ip = escape(self._relay_ip, quote=True)
        timeout_attr = (
            f' timeout="{self._login_timeout}"' if action == "login" and self._login_timeout else ""
        )
        return (
            "<uid-message><version>1.0</version><type>update</type><payload>"
            f'<{action}><entry name="{u}" ip="{ip}" '
            f'source-port-start="{port}" source-port-end="{port}"{timeout_attr}/></{action}>'
            "</payload></uid-message>"
        )

    async def close(self) -> None:
        await self._client.aclose()
