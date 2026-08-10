"""A9 - Direct egress / raw proxy bypass. A raw HTTP request, bypassing agent/tools.py entirely,
aimed at the PEP's bypass-catch listener on :8081 (pep/bypass_proxy.py - what HTTP_PROXY/
HTTPS_PROXY actually point at, per docker-compose.yml §5):

    raw request -> PEP :8081 -> DENY -> decision=DENY, reason=BYPASS_ATTEMPTED

This is specifically the M1 gap #3 control, and the denial itself (a raw HTTPS request through
:8081 getting refused) has real Docker evidence already on record: docs/verification-log.md's
Verification 1, `docker compose exec agent curl -m 3 -x http://pep:8081 https://evil.com` ->
"Tunnel connection failed: 403 Forbidden". What is NOT yet independently re-verified is whether
BYPASS_ATTEMPTED is actually visible in `docker compose logs pep` after the later stdout-logging
fix - that log says so explicitly. This script does not overstate that gap: it reports
REAL_DOCKER_VERIFIED only when it can itself reach a live PEP :8081 in this run.

Run for real, after `docker compose up -d`:
    docker compose exec agent python -m attacks.a9
Then independently confirm attribution with:
    docker compose logs pep | Select-String "BYPASS_ATTEMPTED"
(agent-net has no route to eventstore, so this script cannot fetch the durable event itself even
when the live listener does answer - only the container's own stdout, read separately, can.)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys

import pep.bypass_proxy as bypass_proxy
from attacks.common import (
    REAL_DOCKER_VERIFIED,
    UNVERIFIED,
    AttackResult,
    print_report,
    try_live_raw_connect,
)

PEP_HOST = os.environ.get("PEP_HOST", "pep")
PEP_BYPASS_PORT = int(os.environ.get("PEP_BYPASS_PORT", "8081"))
TARGET = "https://evil.com/"
REQUEST_LINE = "CONNECT evil.com:443 HTTP/1.1"


class _CaptureHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.INFO)
        self.records: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record.getMessage())


async def _run_local_listener() -> tuple[str | None, dict | None]:
    """Starts the REAL pep/bypass_proxy.py `_handle` coroutine on a loopback ephemeral port (not
    the deployed container's :8081, since there is no Docker here) and sends it one raw request -
    same code, different binding. Captures the real event it logs via a temporary handler on the
    "agentfw.pep" logger, rather than reconstructing one by hand.

    WHY the read timeout below is generous (well past the request/response round trip itself):
    `_handle`'s own `_log_bypass()` makes a real, synchronous `httpx.post()` to EVENTSTORE_URL
    before returning - a genuine, existing property of the production code being exercised here,
    not something to work around by changing it. With no live eventstore in this environment, that
    call blocks the single event loop thread for close to its own 5-second timeout before
    `_handle` can write the 403 back - a short client-side read timeout would misreport a slow but
    real response as no response at all."""
    capture = _CaptureHandler()
    bypass_proxy.event_logger.addHandler(capture)
    bypass_proxy.event_logger.setLevel(logging.INFO)
    try:
        server = await asyncio.start_server(bypass_proxy._handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write((REQUEST_LINE + "\r\n\r\n").encode("latin-1"))
            await writer.drain()
            response = await asyncio.wait_for(reader.read(200), timeout=8.0)
            writer.close()
        decoded = response.decode("latin-1", errors="replace")
        response_line = decoded.splitlines()[0] if response else None
        event = json.loads(capture.records[-1]) if capture.records else None
        return response_line, event
    finally:
        bypass_proxy.event_logger.removeHandler(capture)


def run() -> AttackResult:
    notes: list[str] = []

    live_response = try_live_raw_connect(PEP_HOST, PEP_BYPASS_PORT, REQUEST_LINE)

    if live_response is not None:
        status = REAL_DOCKER_VERIFIED
        decision = "DENY" if "403" in live_response else "UNKNOWN"
        reason = (
            "BYPASS_ATTEMPTED" if decision == "DENY" else f"unexpected response: {live_response}"
        )
        event: dict = {}
        notes.append(f"live response line from {PEP_HOST}:{PEP_BYPASS_PORT}: {live_response!r}")
        notes.append(
            "the durable/attributed event itself is not fetchable from here (agent-net has no "
            "route to eventstore) - confirm attribution separately with "
            "`docker compose logs pep | Select-String BYPASS_ATTEMPTED`, per "
            "docs/verification-log.md's Verification 1."
        )
    else:
        response_line, local_event = asyncio.run(_run_local_listener())
        status = UNVERIFIED
        decision = "DENY" if response_line and "403" in response_line else "UNKNOWN"
        reason = "BYPASS_ATTEMPTED" if decision == "DENY" else "no_response"
        event = local_event or {}
        notes.append(
            f"REQUIRED real path unreachable: {PEP_HOST}:{PEP_BYPASS_PORT} did not respond - no "
            "Docker deployment in this environment. A9 is specifically about the deployed "
            "listener, so this is reported UNVERIFIED, not blocked. Run `docker compose up -d` "
            "then `docker compose exec agent python -m attacks.a9` to actually demonstrate it."
        )
        notes.append(
            f"supplementary only (does not count toward this attack's verification): the real "
            f"pep/bypass_proxy.py._handle() code, self-hosted on a local loopback port instead of "
            f"the deployed container, responded {response_line!r} and logged the real event shown "
            f"below - same code, different binding, not itself a Docker verification."
        )

    return AttackResult(
        attack_id="A9",
        description="Direct egress / raw proxy bypass via PEP's bypass-catch listener",
        category="raw_egress_bypass",
        attempted=f"raw {REQUEST_LINE!r} to {PEP_HOST}:{PEP_BYPASS_PORT} (target {TARGET})",
        identity_desc="none presented - this path bypasses agent/tools.py and identity entirely",
        destination=TARGET,
        stage="bypass-catch listener (pep/bypass_proxy.py, port 8081) - denies unconditionally",
        policy_id="BYPASS_DENY",
        reason=reason,
        risk_score=0,
        risk_factors=[],
        decision=decision,
        event=event,
        verification_status=status,
        notes=notes,
    )


if __name__ == "__main__":
    print_report(run())
    sys.exit(0)
