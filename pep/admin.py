"""Admin-only quarantine control: list and manual release. Served on its own loopback-only
(127.0.0.1) uvicorn instance (see pep/proxy.py's lifespan) — deliberately NOT reachable via
agent-net, even though the agent shares that network with the PEP.

# WHY loopback binding, not an auth token: a quarantined agent calling its own release endpoint
# would defeat the entire feature, and agent-net has no notion of "this caller is an admin, that
# one isn't" short of adding a whole credential scheme. Binding this server to 127.0.0.1 means the
# only way to reach it at all is already inside the PEP container's own network namespace — e.g.
# `docker compose exec pep curl ...` — which is a human at a terminal, by construction, not
# anything the agent process can reach over the network no matter how compromised it is.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException

import pep.quarantine as quarantine

admin_app = FastAPI(title="AgentFW PEP Admin (loopback only)")


@admin_app.get("/admin/quarantine")
def list_quarantined() -> dict[str, str]:
    return quarantine.list_all()


@admin_app.post("/admin/quarantine/{agent_id}/release")
def release(agent_id: str) -> dict[str, str]:
    if not quarantine.release(agent_id):
        raise HTTPException(status_code=404, detail=f"{agent_id!r} is not quarantined")
    return {"status": "released", "agent_id": agent_id}
