"""Thin FastAPI wrapper over events/store.py — the `eventstore` container's entrypoint.

WHY this file exists though AGENTFW_CONTEXT.md §4 only lists events/{schema.json,store.py}:
docker-compose.yml runs `eventstore` as its own container (agreed when the M0 scaffold was built,
to match the four-service topology in AgentFW_Build_Plan_v2.md §3) so `pep` and `dashboard` — two
different containers — can share one SQLite file without both mounting the same volume directly.
Something has to be the ASGI entrypoint that `build: ./events` starts; store.py is a plain library
module with no server of its own, by design, mirroring the pep/proxy.py (ASGI layer) vs
pep/pipeline.py (logic) split already used elsewhere in this repo.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from events.store import (
    EventWriteError,
    quarantine_enter,
    quarantine_list,
    quarantine_release,
    read_all_events,
    write_event,
)

DB_PATH = os.environ.get("EVENTSTORE_DB_PATH", "/data/events.db")

app = FastAPI(title="AgentFW Event Store")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/events", status_code=201)
def post_event(event: dict[str, Any]) -> dict[str, str]:
    # WHY a 4xx (not 5xx) on EventWriteError: this is almost always a malformed event from the
    # caller (missing required field), not a transient server fault — the PEP's log-or-deny logic
    # treats any non-2xx here as "could not durably log," so the distinction doesn't change PEP
    # behavior, but it does change what an operator sees in a log line.
    try:
        write_event(event, DB_PATH)
    except EventWriteError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"status": "written"}


@app.get("/events")
def get_events() -> JSONResponse:
    return JSONResponse(content=read_all_events(DB_PATH))


# --- quarantine admin surface (pre-M3 ruling, round 3) ---
# WHY these live here, on eventstore, and not on pep: this is where quarantine state is now
# durably persisted (a PEP restart must not clear it — see pep/quarantine.py's WHY), and eventstore
# sits on egress-net only, exactly like it always has. agent-net has zero route to egress-net —
# not a bind-address trick, the same network split the whole project's non-bypassability story
# already rests on. A prior version of this admin surface lived on the PEP container itself, bound
# to 127.0.0.1 — external verification showed that test going through pep's bypass-catch listener
# (HTTP_PROXY intercepts a plain curl before it ever reaches the target port) and getting back a
# misleading 403 that looked like "reachable but denied" instead of "not on this network at all."
# Moving the admin surface to a container agent-net cannot reach *at all* removes that ambiguity
# structurally instead of arguing about what a curl through a proxy actually proves.
@app.get("/quarantine")
def list_quarantined() -> dict[str, str]:
    return quarantine_list(DB_PATH)


@app.post("/quarantine/{agent_id}")
def enter_quarantine(agent_id: str, body: dict[str, str]) -> dict[str, str]:
    quarantine_enter(agent_id, body["reason"], datetime.now(UTC).isoformat(), DB_PATH)
    return {"status": "entered", "agent_id": agent_id}


@app.delete("/quarantine/{agent_id}")
def release_quarantine(agent_id: str) -> dict[str, str]:
    if not quarantine_release(agent_id, DB_PATH):
        raise HTTPException(status_code=404, detail=f"{agent_id!r} is not quarantined")
    return {"status": "released", "agent_id": agent_id}
