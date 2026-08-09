"""The fixed 8-stage decision pipeline: identity, normalize, policy, threat intel, DLP, risk,
decide, log."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from policy.engine import Decision

# WHY hardcoded here instead of in policy/engine.py: the real YAML-bundle-driven engine (rules
# with priority, conflict/shadow detection) is M2 scope (AGENTFW_CONTEXT.md §9). This table IS
# M1's stated deliverable ("hardcoded allow/deny"), not a stand-in for one — it gets deleted, not
# refactored, when policy/engine.py grows a real evaluator.
#
# WHY this identity check is deliberately weak, and known to be: AGENTFW_CONTEXT.md §2 now
# specifies the real mechanism (issuer container attests callers via the Docker API against
# /var/run/docker.sock, mints Ed25519 tokens the agent never self-asserts) — that's identity/
# issuer.py, M2 scope. Until it exists, this stage trusts a caller-supplied header matching a
# static table, which any caller can forge by setting the header themselves. Stage 1 is real code
# with a real (if temporary) gap, not a `# TODO: implement` stub — the gap is named so it can't be
# mistaken for the finished mechanism.
AGENT_REGISTRY: dict[str, str] = {
    "research-agent-01": "research_agent",
}

# (role, tool) -> (Decision, policy_id). Anything not in this table is default-deny (invariant
# §3.2, no-implicit-allow) — there is no fallback branch that grants access.
HARDCODED_RULES: dict[tuple[str, str], tuple[Decision, str]] = {
    ("research_agent", "http.get"): (Decision.ALLOW, "R-M1-001"),
    ("research_agent", "http.post"): (Decision.DENY, "R-M1-002"),
}

PIPELINE_STAGES = (
    "identity",
    "normalize",
    "policy",
    "threat_intel",
    "dlp",
    "risk",
    "decision",
    "log",
)


@dataclass
class PipelineResult:
    decision: Decision
    reason: str
    policy_id: str
    role: str | None
    latency_ms: dict[str, float] = field(default_factory=dict)


def run_pipeline(agent_id: str, tool: str, *, header_agent_id: str | None) -> PipelineResult:
    """Run the M1 pipeline stand-in and return a verdict. Never raises for a bad/unknown caller or
    tool — those are DENY outcomes, not exceptions; exceptions are reserved for genuine faults."""
    latency: dict[str, float] = {}

    # --- Stage 1: identity verification ---
    t0 = time.perf_counter()
    role = AGENT_REGISTRY.get(agent_id) if header_agent_id == agent_id else None
    latency["identity"] = _elapsed_ms(t0)
    if role is None:
        return PipelineResult(
            Decision.DENY,
            "identity_verification_failed",
            "IDENTITY_DENY",
            None,
            _finalize(latency),
        )

    # --- Stage 2: request normalization (no-op until M2 — pep/normalize.py) ---
    t0 = time.perf_counter()
    latency["normalize"] = _elapsed_ms(t0)

    # --- Stage 3: policy evaluation ---
    t0 = time.perf_counter()
    decision, policy_id = HARDCODED_RULES.get((role, tool), (Decision.DENY, "DEFAULT_DENY"))
    if decision == Decision.ALLOW:
        reason = "matched_explicit_allow"
    elif policy_id == "DEFAULT_DENY":
        reason = "no_matching_rule"
    else:
        reason = "matched_explicit_deny"
    latency["policy"] = _elapsed_ms(t0)

    # --- Stages 4-6: threat intel / DLP / risk (no-op until M2) ---
    # WHY these stay no-ops rather than being skipped entirely: every event must carry a latency
    # figure for every pipeline stage (events/schema.json `latency_ms`), so the shape of the
    # output is already what M2 will fill in — only the values change from 0.0 to real work.
    for stage in ("threat_intel", "dlp", "risk"):
        latency[stage] = 0.0

    # --- Stage 7: decision ---
    # final = min(policy_verdict, risk_verdict) — risk is a no-op ceiling of ALLOW in M1, so the
    # policy verdict always wins here. The min() is written explicitly, not assumed, so the
    # monotonicity invariant (§3.1) is visibly upheld rather than incidentally true.
    t0 = time.perf_counter()
    risk_verdict = Decision.ALLOW  # no risk scoring yet — never narrows in M1
    decision = min(decision, risk_verdict)
    latency["decision"] = _elapsed_ms(t0)

    return PipelineResult(decision, reason, policy_id, role, _finalize(latency))


def _elapsed_ms(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000


def _finalize(latency: dict[str, float]) -> dict[str, float]:
    for stage in PIPELINE_STAGES:
        latency.setdefault(stage, 0.0)
    latency["total"] = sum(latency[stage] for stage in PIPELINE_STAGES)
    return latency
