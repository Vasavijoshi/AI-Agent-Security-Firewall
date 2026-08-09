"""Catches direct calls to HTTP_PROXY/HTTPS_PROXY and denies them, loud and attributable.

# WHY this exists instead of a real CONNECT-tunneling forward proxy: a forward proxy only ever
# sees (method, host, port). It cannot see tool, action, resource, data classification, or taint,
# so it cannot express AgentFW's rules (AGENTFW_CONTEXT.md §2) — that's why agent/tools.py calls
# the PEP's JSON API directly instead (pep/proxy.py). But HTTP_PROXY/HTTPS_PROXY still point here
# (docker-compose.yml §5) as a catch-all: any code path that tries a raw outbound call anyway — a
# library, an injected instruction, a compromised tool — hits this listener instead of silently
# failing to connect, and gets a loud, attributable DENY instead of an unexplained error.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import UTC, datetime

import httpx

EVENTSTORE_URL = os.environ.get("EVENTSTORE_URL", "http://eventstore:8090")
# WHY the same logger name as pep/proxy.py, not `__name__`: this listener is the same enforcement
# point as the main PEP, just on a second port — its events belong in the identical, single
# observable stream `docker compose logs pep` shows, not a same-shaped-but-separate one. Logging
# is configured once, in pep/proxy.py (which imports this module before the server starts); this
# just asks for the same named logger, per Python's usual getLogger-is-a-singleton behavior.
event_logger = logging.getLogger("agentfw.pep")
_STAGES = (
    "identity",
    "normalize",
    "policy",
    "threat_intel",
    "dlp",
    "risk",
    "decision",
    "log",
    "total",
)


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=5.0)
        request_line = line.decode("latin-1", errors="replace").strip()
        parts = request_line.split(" ")
        destination = parts[1] if len(parts) > 1 else "unknown"
        _log_bypass(destination, request_line)
        writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
    except (TimeoutError, OSError):
        pass
    finally:
        writer.close()


def _log_bypass(destination: str, request_line: str) -> None:
    event = {
        "schema_version": "1.0",
        "timestamp": datetime.now(UTC).isoformat(),
        "trace_id": str(uuid.uuid4()),
        "session_id": "unknown",
        "agent_id": "unknown",
        "role": "unknown",
        "tool": "network.bypass",
        "action": "connect",
        "destination": {"fqdn": destination, "ip": None, "port": None, "protocol": None},
        "resource": request_line[:200],
        "data_classification": "internal",
        "session_taint": "clean",
        "risk_score": 0,
        "risk_factors": [],
        "policy_id": "BYPASS_DENY",
        "policy_bundle_version": "m1-hardcoded",
        "decision": "DENY",
        "reason": "BYPASS_ATTEMPTED",
        "latency_ms": dict.fromkeys(_STAGES, 0.0),
    }
    # WHY stdout first, unconditionally: this is the fix for the verified gap — a bypass attempt
    # was being denied correctly but was invisible in `docker compose logs pep`, because the only
    # thing that ever happened was an HTTP POST to a different container. This makes the denial
    # attributable from the PEP's own container log alone, with no dependency on eventstore being
    # reachable (there is no decision left to protect by withholding this one — the connection is
    # already being denied either way).
    event_logger.info(json.dumps(event))
    try:
        httpx.post(f"{EVENTSTORE_URL}/events", json=event, timeout=5.0)
    except httpx.HTTPError:
        pass  # WHY still deny even if durable logging fails: nothing here to release regardless.


async def serve(host: str = "0.0.0.0", port: int = 8081) -> None:
    server = await asyncio.start_server(_handle, host, port)
    async with server:
        await server.serve_forever()
