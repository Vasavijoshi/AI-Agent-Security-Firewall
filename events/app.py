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
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from events.store import EventWriteError, read_all_events, write_event

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
