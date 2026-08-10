"""Quarantine state, persisted to the eventstore (pre-M3 ruling, round 3) — not held only in the
PEP process's memory. Entry is automatic (risk CRITICAL, a threat-intel hit, or >=5 denials within
60 seconds — checked in pep/pipeline.py after each call completes). Exit is manual only, via the
eventstore's `/quarantine/{agent_id}` DELETE endpoint (events/app.py) — never a timer.

# WHY persisted, not process-memory: a PEP restart is not a human decision. Security state that
# clears itself on crash or redeploy is availability-triggered privilege restoration — an agent
# that earned quarantine keeps it exactly as long as a human says it should, independent of
# whatever else happens to the PEP process in the meantime.

# WHY no in-memory cache of quarantine membership: a cache is only correct until something else
# changes the underlying state without telling it — and the whole point of persisting to the
# eventstore is that release can happen from *outside this process* (an operator hitting
# eventstore's endpoint directly). Checking live avoids a second, harder problem: cache
# invalidation across processes with no shared memory. The cost is a network round trip on every
# call; accepted because every call already depends on the eventstore being reachable to be
# logged at all (log-or-deny) — this doesn't add a new single point of failure, it just asks the
# same dependency one question earlier.

Keyed by the stable workload key (identity/issuer.py's "service" claim — a compose service name,
not the ephemeral per-restart container_id), so a compromised agent cannot escape quarantine by
simply being restarted into a fresh container identity.
"""

from __future__ import annotations

import json
import logging
import os
import time

import httpx

EVENTSTORE_URL = os.environ.get("EVENTSTORE_URL", "http://eventstore:8090")
event_logger = logging.getLogger("agentfw.pep")  # same logger pep/proxy.py configures

# --- denial-rate window: deliberately NOT persisted (see module WHY) ---
# WHY this one stays in-memory when quarantine membership doesn't: it's 60 seconds of recent-call
# bookkeeping, not a security decision in its own right — losing it on restart just means the
# counter restarts from zero, which is a far smaller and differently-shaped concern than losing
# quarantine *membership* itself (the thing the user's "availability-triggered privilege
# restoration" objection is actually about).
_DENIAL_TIMES: dict[str, list[float]] = {}

DENIAL_WINDOW_SECONDS = 60
DENIAL_THRESHOLD = 5


class QuarantineCheckUnavailable(Exception):
    """Raised when the persisted quarantine state can't be reached. Callers must treat this as
    DENY (same reasoning as log-or-deny, invariant §3.4) but with a reason that says so — folding
    "genuinely quarantined" and "couldn't check, failing safe" into the same AGENT_QUARANTINED
    reason would hide an eventstore outage behind a misleading label."""


def is_quarantined(workload_key: str) -> bool:
    try:
        resp = httpx.get(f"{EVENTSTORE_URL}/quarantine", timeout=5.0)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise QuarantineCheckUnavailable(str(exc)) from exc
    return workload_key in resp.json()


def enter(workload_key: str, reason: str) -> None:
    """Idempotent at the storage layer (events/store.py's INSERT OR IGNORE) — quarantining an
    already-quarantined agent keeps its original reason. Best-effort: if the eventstore write
    fails, this call doesn't raise (the triggering request is already being denied via the normal
    log-or-deny path regardless), but the failure is logged so it isn't silent."""
    try:
        httpx.post(
            f"{EVENTSTORE_URL}/quarantine/{workload_key}", json={"reason": reason}, timeout=5.0
        )
    except httpx.HTTPError as exc:
        event_logger.warning(
            json.dumps(
                {"event": "quarantine_persist_failed", "agent_id": workload_key, "error": str(exc)}
            )
        )


def release(workload_key: str) -> bool:
    """The only way out. Returns True if the agent was actually quarantined."""
    try:
        resp = httpx.delete(f"{EVENTSTORE_URL}/quarantine/{workload_key}", timeout=5.0)
        return resp.status_code == 200
    except httpx.HTTPError:
        return False


def list_all() -> dict[str, str]:
    resp = httpx.get(f"{EVENTSTORE_URL}/quarantine", timeout=5.0)
    resp.raise_for_status()
    return resp.json()


def record_denial(workload_key: str) -> bool:
    """Track a DENY toward the rolling-window trigger. Returns True the moment this call crosses
    the threshold (>=5 denials in 60s) — the caller (pep/pipeline.py) decides what to do with that;
    this function only tracks and reports, so the actual trigger logic for all three conditions
    (risk CRITICAL, threat-intel hit, denial rate) stays visible in one place in run_pipeline
    rather than split across modules."""
    now = time.time()
    times = _DENIAL_TIMES.setdefault(workload_key, [])
    times.append(now)
    recent = [t for t in times if now - t <= DENIAL_WINDOW_SECONDS]
    _DENIAL_TIMES[workload_key] = recent
    return len(recent) >= DENIAL_THRESHOLD
