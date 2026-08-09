"""FastAPI enforcement proxy: the agent's only route out, dual-homed on agent-net and egress-net."""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Header
from pydantic import BaseModel

from pep.pipeline import PipelineResult, run_pipeline
from policy.engine import Decision

EVENTSTORE_URL = os.environ.get("EVENTSTORE_URL", "http://eventstore:8090")
SCHEMA_VERSION = "1.0"
# WHY "m1-hardcoded", not a version number: real policy_bundle_version is a strictly monotonic
# version stamped on a signed YAML bundle (M2). M1 has no bundle to version — this sentinel makes
# that visible in every logged event rather than faking a version that doesn't exist.
POLICY_BUNDLE_VERSION = "m1-hardcoded"

ACTION_MAP = {
    "http.get": "read",
    "http.post": "write",
    "db.query": "read",
    "file.read": "read",
    "email.send": "write",
}

app = FastAPI(title="AgentFW PEP")


class ToolCallRequest(BaseModel):
    agent_id: str
    session_id: str
    trace_id: str
    tool: str
    arguments: dict[str, Any]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/tool-call")
def tool_call(
    req: ToolCallRequest, x_agent_id: str | None = Header(default=None)
) -> dict[str, Any]:
    result = run_pipeline(req.agent_id, req.tool, header_agent_id=x_agent_id)

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
            result.latency_ms,
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
    if result.decision in (Decision.ALLOW, Decision.ALLOW_REDACTED):
        tool_result = _execute(req.tool, req.arguments)

    return {
        "decision": result.decision.name,
        "reason": result.reason,
        "result": tool_result,
        "latency_ms": event["latency_ms"],
    }


def _build_event(req: ToolCallRequest, result: PipelineResult) -> dict[str, Any]:
    destination = _extract_destination(req.tool, req.arguments)
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp": datetime.now(UTC).isoformat(),
        "trace_id": req.trace_id,
        "session_id": req.session_id,
        "agent_id": req.agent_id,
        "role": result.role or "unknown",
        "tool": req.tool,
        "action": ACTION_MAP.get(req.tool, "unknown"),
        "destination": destination,
        "resource": _extract_resource(req.tool, req.arguments),
        # WHY "internal" as the M1 default, not "public": DLP-driven classification (stage 5) is
        # M2 scope. Until real classification exists, defaulting to a middling, non-public value
        # is the fail-static choice — an under-classified event is a bigger problem than an
        # over-classified one.
        "data_classification": "internal",
        # WHY "clean" fixed: taint tracking (invariant §3.5) is M2 scope (identity/issuer.py +
        # taint state don't exist yet). Fixing it at "clean" rather than modeling it keeps this
        # field honest — it says "not evaluated," not "evaluated and safe."
        "session_taint": "clean",
        "risk_score": 0,
        "risk_factors": [],
        "policy_id": result.policy_id,
        "policy_bundle_version": POLICY_BUNDLE_VERSION,
        "decision": result.decision.name,
        "reason": result.reason,
        "latency_ms": dict(result.latency_ms),
    }


def _extract_destination(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    url = arguments.get("url") if tool.startswith("http.") else None
    if not url:
        return {"fqdn": None, "ip": None, "port": None, "protocol": None}
    parsed = urlparse(url)
    return {
        "fqdn": parsed.hostname,
        "ip": None,  # WHY None: FQDN pinning (resolve-then-connect-to-that-IP) is M2 scope.
        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
        "protocol": parsed.scheme or None,
    }


def _extract_resource(tool: str, arguments: dict[str, Any]) -> str | None:
    if tool.startswith("http."):
        parsed = urlparse(arguments.get("url", ""))
        return parsed.path or None
    if tool == "db.query":
        return arguments.get("query")
    if tool == "file.read":
        return arguments.get("path")
    if tool == "email.send":
        return arguments.get("to")
    return None


def _log_event(event: dict[str, Any]) -> bool:
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
