"""Explainable additive risk scorer: bounded, per-category capped, every score returns its
factor vector.

WHY the behavioral factors (rate, bigram novelty, active window, denial streak) are approximated
from in-memory, single-process state rather than a real historical store: this project has no
durable per-agent history database, and building one is disproportionate to what M2 asks for. The
factor table below is complete (every row from AgentFW_Architecture_v1.md §8 is represented) but
three of the ten rows are honestly weaker than a production deployment's would be — each says so at
its definition. All state resets on process restart; that's the concrete cost of the simplification.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from policy.engine import Decision

# --- factor point values (AgentFW_Architecture_v1.md §8) ---
THREAT_INTEL_HIT = 60
DEST_NEVER_SEEN_BY_AGENT = 10
DEST_UNKNOWN_TO_ORG = 15
ACTION_POINTS = {"read": 0, "write": 10, "delete": 25, "cred_access": 30}
DATA_CLASS_POINTS = {"public": 0, "internal": 10, "confidential": 25, "secret": 40}
TAINTED_AND_EXTERNAL = 30
RATE_ANOMALY = 20
UNSEEN_BIGRAM = 15
OUTSIDE_ACTIVE_WINDOW = 10
DENIAL_STREAK_PER_HIT = 5
DENIAL_STREAK_CAP = 25

CATEGORY_CAP = 60  # no single category may exceed this
TOTAL_CAP = 100

_RATE_WINDOW_SECONDS = 60
_RATE_THRESHOLD = 5  # calls in the window before it's "anomalous"

# --- in-memory behavioral state (per-process, reset on restart — see module docstring) ---
_SEEN_BY_AGENT: dict[str, set[str]] = {}
_SEEN_BY_ORG: set[str] = set()
_CALL_TIMES: dict[str, list[float]] = {}
_LAST_TOOL: dict[str, str] = {}  # keyed by role: last tool called by that role
_SEEN_BIGRAMS: dict[str, set[tuple[str, str]]] = {}  # keyed by role
_DENIAL_STREAK: dict[str, int] = {}  # keyed by agent_id


@dataclass(frozen=True)
class Factor:
    code: str
    points: int
    human_reason: str


@dataclass(frozen=True)
class ScoreResult:
    score: int
    band: str
    factors: list[Factor] = field(default_factory=list)
    decision_ceiling: Decision = Decision.ALLOW


def score(
    *,
    agent_id: str,
    role: str,
    tool: str,
    destination_key: str | None,
    action: str,
    data_class: str,
    session_taint: str,
    threat_intel_hit: bool,
) -> ScoreResult:
    """Compute a risk score from current state. Read-only — does not update behavioral state; call
    record_outcome() after the final decision is known (AGENTFW_CONTEXT.md §2 stage 7/8 ordering:
    the streak factor must reflect denials *before* this call, not including it)."""
    raw_factors: list[Factor] = []

    if threat_intel_hit:
        raw_factors.append(
            Factor(
                "THREAT_INTEL_HIT",
                THREAT_INTEL_HIT,
                "destination is on the local threat-intel list",
            )
        )

    if destination_key is not None:
        if destination_key not in _SEEN_BY_ORG:
            raw_factors.append(
                Factor(
                    "DEST_UNKNOWN_TO_ORG",
                    DEST_UNKNOWN_TO_ORG,
                    "no agent has ever called this destination",
                )
            )
        elif destination_key not in _SEEN_BY_AGENT.get(agent_id, set()):
            raw_factors.append(
                Factor(
                    "DEST_NEVER_SEEN_BY_AGENT",
                    DEST_NEVER_SEEN_BY_AGENT,
                    "new destination for this agent",
                )
            )

    action_points = ACTION_POINTS.get(action, 0)
    if action_points:
        raw_factors.append(
            Factor(
                "ACTION_CLASS", action_points, f"action class {action!r} carries blast-radius risk"
            )
        )

    data_points = DATA_CLASS_POINTS.get(data_class, 0)
    if data_points:
        raw_factors.append(Factor("DATA_CLASS", data_points, f"data classification {data_class!r}"))

    if session_taint == "tainted" and tool.startswith("http."):
        raw_factors.append(
            Factor(
                "TAINTED_EXTERNAL",
                TAINTED_AND_EXTERNAL,
                "tainted session attempting an external call",
            )
        )

    if _is_rate_anomalous(agent_id):
        raw_factors.append(
            Factor(
                "RATE_ANOMALY",
                RATE_ANOMALY,
                f">{_RATE_THRESHOLD} calls in {_RATE_WINDOW_SECONDS}s (in-process proxy for a "
                "7-day baseline)",
            )
        )

    if _is_unseen_bigram(role, tool):
        raw_factors.append(
            Factor(
                "UNSEEN_BIGRAM",
                UNSEEN_BIGRAM,
                f"role {role!r} has never called {tool!r} right after its previous tool",
            )
        )

    # WHY always False: no persisted per-agent activity histogram exists in this project (see
    # module docstring) — this factor never fires here, but stays in the table for completeness.
    raw_factors.append(
        Factor(
            "OUTSIDE_ACTIVE_WINDOW",
            0,
            "not evaluated — no historical activity store in this deployment",
        )
    )

    streak = _DENIAL_STREAK.get(agent_id, 0)
    if streak:
        points = min(streak * DENIAL_STREAK_PER_HIT, DENIAL_STREAK_CAP)
        raw_factors.append(
            Factor("DENIAL_STREAK", points, f"{streak} consecutive prior denial(s) for this agent")
        )

    capped_factors = [
        Factor(f.code, min(f.points, CATEGORY_CAP), f.human_reason) for f in raw_factors
    ]
    total = min(sum(f.points for f in capped_factors), TOTAL_CAP)
    band, ceiling = _band_and_ceiling(total)
    return ScoreResult(score=total, band=band, factors=capped_factors, decision_ceiling=ceiling)


def record_outcome(
    *, agent_id: str, role: str, tool: str, destination_key: str | None, decision: Decision
) -> None:
    """Update behavioral state after the final decision is known. Called once per completed
    pipeline run (AGENTFW_CONTEXT.md §2 stage 8), never before — scoring the *next* call must see
    this call's outcome, not this one."""
    now = time.time()
    _CALL_TIMES.setdefault(agent_id, []).append(now)
    _CALL_TIMES[agent_id] = [t for t in _CALL_TIMES[agent_id] if now - t <= _RATE_WINDOW_SECONDS]

    if destination_key is not None:
        _SEEN_BY_ORG.add(destination_key)
        _SEEN_BY_AGENT.setdefault(agent_id, set()).add(destination_key)

    last = _LAST_TOOL.get(role)
    if last is not None:
        _SEEN_BIGRAMS.setdefault(role, set()).add((last, tool))
    _LAST_TOOL[role] = tool

    if decision == Decision.DENY:
        _DENIAL_STREAK[agent_id] = _DENIAL_STREAK.get(agent_id, 0) + 1
    else:
        _DENIAL_STREAK[agent_id] = 0


def _is_rate_anomalous(agent_id: str) -> bool:
    now = time.time()
    recent = [t for t in _CALL_TIMES.get(agent_id, []) if now - t <= _RATE_WINDOW_SECONDS]
    return len(recent) >= _RATE_THRESHOLD


def _is_unseen_bigram(role: str, tool: str) -> bool:
    last = _LAST_TOOL.get(role)
    if last is None:
        return False  # first call for this role ever — nothing to compare against
    return (last, tool) not in _SEEN_BIGRAMS.get(role, set())


def _band_and_ceiling(total: int) -> tuple[str, Decision]:
    if total >= 75:
        return "CRITICAL", Decision.QUARANTINE
    if total >= 50:
        return "HIGH", Decision.REQUIRE_APPROVAL
    if total >= 25:
        return "MODERATE", Decision.RATE_LIMIT
    return "LOW", Decision.ALLOW
