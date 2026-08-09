"""PEP-held quarantine state. Entry is automatic (risk CRITICAL, a threat-intel hit, or >=5
denials within 60 seconds — checked in pep/pipeline.py after each call completes). Exit is manual
only, via an explicit admin endpoint (pep/admin.py) — never a timer.

# WHY exit is never automatic: recovery from a security event is a decision that requires
# organizational context no in-band signal can supply — the same reasoning
# AgentFW_Architecture_v1.md §15 gives for routing high-consequence actions to a human rather
# than a model. A timer that
# un-quarantines an agent on a schedule is indistinguishable, from the agent's point of view, from
# "wait it out" — which defeats the point of quarantining it at all.

Keyed by the stable workload key (identity/issuer.py's "service" claim — a compose service name,
not the ephemeral per-restart container_id), so a compromised agent cannot escape quarantine by
simply being restarted into a fresh container identity.
"""

from __future__ import annotations

import time

_QUARANTINED: dict[str, str] = {}  # workload_key -> reason it was quarantined
_DENIAL_TIMES: dict[str, list[float]] = {}  # workload_key -> recent DENY timestamps

DENIAL_WINDOW_SECONDS = 60
DENIAL_THRESHOLD = 5


def is_quarantined(workload_key: str) -> bool:
    return workload_key in _QUARANTINED


def enter(workload_key: str, reason: str) -> None:
    """Idempotent: quarantining an already-quarantined agent keeps the original reason. There is
    nothing time-based to restart, since exit is manual — a second trigger firing isn't a reason
    to treat the agent as "freshly" quarantined."""
    _QUARANTINED.setdefault(workload_key, reason)


def release(workload_key: str) -> bool:
    """The only way out. Returns True if the agent was actually quarantined (so the admin caller
    gets a real answer, not a silent no-op on a typo'd agent_id)."""
    return _QUARANTINED.pop(workload_key, None) is not None


def list_all() -> dict[str, str]:
    return dict(_QUARANTINED)


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
