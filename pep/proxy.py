"""FastAPI enforcement proxy: the agent's only route out, dual-homed on agent-net and egress-net."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import FastAPI, Header, Request
from pydantic import BaseModel

from pep.bypass_proxy import serve as serve_bypass_proxy
from pep.normalize import normalize_url
from pep.pipeline import ACTION_MAP, BUNDLE, PipelineResult, extract_target, run_pipeline
from policy.engine import EXECUTABLE_DECISIONS, Decision

EVENTSTORE_URL = os.environ.get("EVENTSTORE_URL", "http://eventstore:8090")
SCHEMA_VERSION = "1.0"

# WHY this exists: durable storage (the POST to eventstore below) and container-log observability
# are two different failure domains — `docker compose logs pep` was previously blind to every
# decision the PEP made, bypass-listener or not, because nothing was ever written to this
# process's own stdout. AGENTFW_CONTEXT.md §7 already calls for "one JSON event per decision";
# this is what actually makes that observable without needing the eventstore reachable at all.
# "agentfw.pep" (not `__name__`) so pep/bypass_proxy.py logs through the identical logger, not a
# same-shaped but distinct one — one mechanism, not two that happen to look alike.
logging.basicConfig(level=logging.INFO, format="%(message)s")
event_logger = logging.getLogger("agentfw.pep")


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    # WHY a background task in this process rather than a second container: the bypass proxy is
    # the same enforcement point, just listening on a second port (M1 gap #3 resolution) — it
    # shares the PEP's event-logging path and has no state of its own to isolate.
    task = asyncio.create_task(serve_bypass_proxy())
    yield
    task.cancel()


app = FastAPI(title="AgentFW PEP", lifespan=_lifespan)


class ToolCallRequest(BaseModel):
    session_id: str
    trace_id: str
    tool: str
    arguments: dict[str, Any]
    # WHY no agent_id field: identity comes entirely from the verified Authorization token
    # (AGENTFW_CONTEXT.md §2) — a field here would just be a claim an attacker fully controlling
    # the request body could lie about. The event's agent_id is the token's own identifier.


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/tool-call")
def tool_call(
    req: ToolCallRequest, request: Request, authorization: str | None = Header(default=None)
) -> dict[str, Any]:
    token = authorization.removeprefix("Bearer ") if authorization else None
    peer_ip = request.client.host if request.client else None

    result = run_pipeline(
        token=token,
        peer_ip=peer_ip,
        session_id=req.session_id,
        tool=req.tool,
        arguments=req.arguments,
    )

    t0 = time.perf_counter()
    event = _build_event(req, result)
    logged = _log_event(event)
    log_ms = (time.perf_counter() - t0) * 1000

    if not logged:
        # WHY: log-or-deny (AGENTFW_CONTEXT.md invariant §3.4) — an event that failed to write is
        # unauditable, so the action it describes must not be released regardless of what stage 3
        # decided. We still attempt to log the denial itself (best-effort); if that also fails,
        # the caller gets DENY either way, which is the only safe outcome.
        result = PipelineResult(
            Decision.DENY,
            "event_store_write_failed",
            result.policy_id,
            result.role,
            result.agent_key,
            result.session_taint,
            result.data_classification,
            result.risk_score,
            result.risk_factors,
            result.latency_ms,
            result.normalized_arguments,
        )
        # Best-effort: if this second write also fails, the caller still gets DENY below — there
        # is no third attempt, and no path back to releasing the original action.
        _log_event(_build_event(req, result))

    # WHY the persisted event's own `latency_ms.log` stays 0.0 even though we know better here: an
    # event can't durably record the time its own write took, since the write already happened
    # before that duration was known — logging it now would mean a second write for one event,
    # which log-or-deny doesn't call for. The corrected figure is only available for the API
    # response below, not for the audit trail; that asymmetry is inherent, not a bug to fix later.
    event["latency_ms"]["log"] = log_ms
    event["latency_ms"]["total"] += log_ms

    tool_result = None
    if result.decision in EXECUTABLE_DECISIONS:
        # WHY normalized_arguments, not req.arguments: the canonical form is what gets forwarded,
        # never the caller's original (AGENTFW_CONTEXT.md §2 stage 2) — this is the one place in
        # the whole request path where that distinction is actually load-bearing.
        tool_result = _execute(req.tool, result.normalized_arguments)

    return {
        "decision": result.decision.name,
        "reason": result.reason,
        "result": tool_result,
        "latency_ms": event["latency_ms"],
    }


def _build_event(req: ToolCallRequest, result: PipelineResult) -> dict[str, Any]:
    # WHY normalized_arguments here too, not req.arguments: an event describing what was actually
    # evaluated and forwarded must reflect the canonical form, not the caller's original — that's
    # the whole point of running normalization before policy (AGENTFW_CONTEXT.md §2 stage 2).
    arguments = result.normalized_arguments or req.arguments
    fqdn, resource = extract_target(req.tool, arguments)
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp": datetime.now(UTC).isoformat(),
        "trace_id": req.trace_id,
        "session_id": req.session_id,
        "agent_id": result.agent_key,
        "role": result.role or "unknown",
        "tool": req.tool,
        "action": ACTION_MAP.get(req.tool, "unknown"),
        "destination": _destination_dict(req.tool, arguments, fqdn),
        "resource": resource,
        "data_classification": result.data_classification,
        "session_taint": result.session_taint,
        "risk_score": result.risk_score,
        "risk_factors": result.risk_factors,
        "policy_id": result.policy_id,
        "policy_bundle_version": BUNDLE.version,
        "decision": result.decision.name,
        "reason": result.reason,
        "latency_ms": dict(result.latency_ms),
    }


def _destination_dict(tool: str, arguments: dict[str, Any], fqdn: str | None) -> dict[str, Any]:
    if not fqdn or not tool.startswith("http."):
        return {"fqdn": None, "ip": None, "port": None, "protocol": None}
    # WHY normalize_url again here rather than string-prefix-checking arguments["url"]: the
    # previous check (`url.startswith("https")`) was case-sensitive and would misclassify a
    # differently-cased scheme — normalize_url is idempotent (tests/test_normalize.py), so calling
    # it again on an already-canonical URL is cheap and correct rather than re-deriving by hand.
    canonical = normalize_url(arguments.get("url", ""))
    return {
        "fqdn": fqdn,
        "ip": None,  # WHY None: FQDN pinning (resolve-then-connect-to-that-IP) is not in scope.
        "port": canonical.port or (443 if canonical.scheme == "https" else 80),
        "protocol": canonical.scheme,
    }


def _log_event(event: dict[str, Any]) -> bool:
    # WHY logged to stdout before the durable-write attempt, unconditionally: container-log
    # observability must not depend on the eventstore being reachable — that's the exact failure
    # mode log-or-deny (invariant §3.4) already denies the action for, and an operator watching
    # `docker compose logs pep` during that outage still needs to see what was decided and why.
    event_logger.info(json.dumps(event))
    try:
        resp = httpx.post(f"{EVENTSTORE_URL}/events", json=event, timeout=5.0)
        return resp.status_code == 201
    except httpx.HTTPError:
        return False


def _execute(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Perform the allowed action. Only reached after an ALLOW/ALLOW_REDACTED verdict.

    WHY http.get/http.post genuinely call out and the other three don't: pep is the only
    dual-homed container (agent-net + egress-net), so it's the only place in this stack that CAN
    reach the real internet — that's the non-bypassability property this whole project exists to
    demonstrate, and faking it here would undercut the one thing that has to be real. db.query,
    file.read, and email.send have no real backend yet (mock tool APIs are M3 scope,
    AgentFW_Build_Plan_v2.md §5) — they return a labeled canned result rather than pretending.
    """
    if tool in ("http.get", "http.post"):
        try:
            if tool == "http.get":
                resp = httpx.get(arguments["url"], timeout=10.0)
            else:
                resp = httpx.post(arguments["url"], content=arguments.get("body", ""), timeout=10.0)
            return {"status_code": resp.status_code, "body": resp.text[:2000]}
        except httpx.HTTPError as exc:
            return {"error": str(exc)}
    return {
        "mock": True,
        "tool": tool,
        "note": "no real backend until M3 (AgentFW_Build_Plan_v2.md §5 mock tool APIs)",
    }
