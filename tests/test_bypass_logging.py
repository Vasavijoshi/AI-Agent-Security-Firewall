"""Focused regression test for the verified M1 gap #3 follow-up: a bypass-listener denial must be
visible in the PEP's own container log (`docker compose logs pep`), not just a best-effort POST to
the eventstore container. Docker verification found `_log_bypass` denied correctly but never wrote
anything the PEP process itself would emit to stdout — this test pins the fix in place.
"""

from __future__ import annotations

import asyncio
import json
import logging

import httpx

import pep.bypass_proxy as bypass_proxy


def test_bypass_denial_is_logged_even_when_the_eventstore_is_unreachable(monkeypatch, caplog):
    """The stdout log line must not depend on eventstore reachability — that's the whole point:
    an operator watching `docker compose logs pep` during an eventstore outage still needs to see
    the denial and why."""

    def _unreachable(*_args, **_kwargs):
        raise httpx.HTTPError("simulated eventstore outage")

    monkeypatch.setattr(bypass_proxy.httpx, "post", _unreachable)

    with caplog.at_level(logging.INFO, logger="agentfw.pep"):
        bypass_proxy._log_bypass("evil.com:443", "CONNECT evil.com:443 HTTP/1.1")

    assert len(caplog.records) == 1
    event = json.loads(caplog.records[0].message)
    assert event["decision"] == "DENY"
    assert event["reason"] == "BYPASS_ATTEMPTED"
    assert event["destination"]["fqdn"] == "evil.com:443"


def test_bypass_listener_denies_connect_and_logs_it(monkeypatch, caplog):
    """End-to-end against the real asyncio listener — the same request shape the external Docker
    verification sent (a raw CONNECT), against the same `_handle` coroutine `serve()` runs."""
    monkeypatch.setattr(
        bypass_proxy.httpx,
        "post",
        lambda *a, **k: (_ for _ in ()).throw(httpx.HTTPError("down")),
    )

    async def _run() -> bytes:
        server = await asyncio.start_server(bypass_proxy._handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n")
            await writer.drain()
            response = await reader.read(200)
            writer.close()
            await writer.wait_closed()
        return response

    with caplog.at_level(logging.INFO, logger="agentfw.pep"):
        response = asyncio.run(_run())

    assert b"403 Forbidden" in response
    assert len(caplog.records) == 1
    event = json.loads(caplog.records[0].message)
    assert event["decision"] == "DENY"
    assert event["reason"] == "BYPASS_ATTEMPTED"
    assert "evil.com" in event["destination"]["fqdn"]
