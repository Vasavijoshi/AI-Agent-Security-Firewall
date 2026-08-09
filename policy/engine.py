"""Deterministic policy evaluation: explicit DENY > explicit ALLOW > implicit DENY, priority
tie-break by rule ID."""

from __future__ import annotations

from enum import IntEnum


class Decision(IntEnum):
    """The monotonic decision lattice (AGENTFW_CONTEXT.md §2 / invariant §3.1).

    Ordering is the invariant, not decoration: `decide(policy, risk) = min(policy, risk)`, so any
    stage downstream of a deterministic policy verdict can only move a decision to a *lower*
    member of this enum, never a higher one. `DENY` is index 0 on purpose — it must never be
    outranked by an accident of dict ordering or a missing case in a comparison.
    """

    DENY = 0
    QUARANTINE = 1
    REQUIRE_APPROVAL = 2
    RATE_LIMIT = 3
    ALLOW_REDACTED = 4
    ALLOW = 5


# WHY: rule-based evaluation (YAML bundle -> compiled decision tree, conflict/shadow detection) is
# M2 scope (AGENTFW_CONTEXT.md §9). M1's PEP uses a small hardcoded table instead — see
# pep/pipeline.py — because M1's stated deliverable is "hardcoded allow/deny", not a stand-in for
# the real engine. Only the Decision vocabulary is shared ahead of time, since events/schema.json,
# pep/pipeline.py, and tests/test_invariants.py all need one common definition of it.
