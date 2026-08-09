"""Deterministic policy evaluation: explicit DENY > explicit ALLOW > implicit DENY, priority
tie-break by rule ID."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import yaml


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


# WHY RATE_LIMIT is in this set and REQUIRE_APPROVAL/QUARANTINE are not: per the lattice's own
# semantics (AgentFW_Architecture_v1.md §15), RATE_LIMIT and ALLOW_REDACTED are both "the call
# happens, with a caveat" — throttled or redacted, but not held. REQUIRE_APPROVAL means "a human
# has to say yes" and QUARANTINE means the agent itself is being cut off; neither of those is
# something this project has a workflow for yet (no approval queue, no quarantine automation), so
# for now they simply don't execute — which is the safe default for "not yet implemented," not a
# silent behavior gap. Actual rate-limiting (throttling repeat calls) also isn't implemented here;
# RATE_LIMIT executes the call now and narrows future risk scoring via the denial-streak-style
# factors, which is the honest scope for this milestone.
EXECUTABLE_DECISIONS = frozenset({Decision.ALLOW, Decision.ALLOW_REDACTED, Decision.RATE_LIMIT})

# --- eval verdict taxonomy (pre-M3 ruling, settled here so M3's scorer imports it rather than
# invents it) ---
# WHY REQUIRE_APPROVAL is "permitted" here despite not being in EXECUTABLE_DECISIONS above: these
# two groupings answer different questions. EXECUTABLE_DECISIONS asks "does pep/proxy.py call
# _execute() today" — no, there's no approval workflow yet, so it doesn't. BLOCKED/PERMITTED asks
# "was this verdict the firewall's *intent* to stop the action" — REQUIRE_APPROVAL means "ask a
# human," which is not a stop, so it counts as permitted-with-friction, not blocked. A benign call
# landing on REQUIRE_APPROVAL is friction the firewall imposes, not a false positive; the fact
# that nothing executes it automatically yet is a separate, honestly-scoped implementation gap
# (see EXECUTABLE_DECISIONS' own WHY above), not a reason to reclassify the verdict itself.
BLOCKED_DECISIONS = frozenset({Decision.DENY, Decision.QUARANTINE})
PERMITTED_DECISIONS = frozenset(
    {Decision.ALLOW, Decision.ALLOW_REDACTED, Decision.RATE_LIMIT, Decision.REQUIRE_APPROVAL}
)
# WHY a further split out of PERMITTED, not a third independent bucket: friction is a subset of
# permitted (the call wasn't blocked) that still isn't free — reporting it separately keeps it
# from ever being silently absorbed into either "the firewall let this through cleanly" or "the
# firewall blocked this," which is exactly the ruling's point.
FRICTION_DECISIONS = frozenset({Decision.RATE_LIMIT, Decision.REQUIRE_APPROVAL})

# WHY exactly these two tools: they're the only "write"-shaped tools in the actual 5-tool set
# (agent/tools.py) — db.write/db.delete/http.put appear in the architecture doc but were never
# implemented as real tools, so including them here would be untestable dead weight.
WRITE_TOOLS = frozenset({"http.post", "email.send"})
_HIGH_DATA_CLASSES = frozenset({"confidential", "secret"})


@dataclass(frozen=True)
class Rule:
    id: str
    priority: int
    role: str
    tool: tuple[str, ...]
    effect: Decision
    critical_path: bool = False
    destination: tuple[str, ...] | None = None
    resource: tuple[str, ...] | None = None
    max_data_class: str | None = None
    session_taint: tuple[str, ...] | None = None
    inspect: bool = False
    reason: str = ""


@dataclass(frozen=True)
class Bundle:
    version: str
    not_valid_after: str
    fail_safe_after: int
    rules: tuple[Rule, ...]


@dataclass(frozen=True)
class EvalResult:
    decision: Decision
    policy_id: str
    reason: str
    max_data_class: str | None
    inspect: bool


def load_bundle(path: str | Path) -> Bundle:
    """Parse a policy bundle YAML file. Raises ValueError on structurally invalid rules.

    WHY this stays separate from policy/compiler.py: loading a bundle into usable Rule objects and
    *validating that the ruleset makes sense* (conflicts, shadowing, unknown roles) are different
    jobs with different audiences — the engine needs the former at request time, the compiler needs
    the latter at build/CI time. Conflating them would make the engine pay compiler costs on every
    request.
    """
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    rules = tuple(_parse_rule(r) for r in raw["rules"])
    meta = raw["metadata"]
    return Bundle(
        version=str(meta["version"]),
        not_valid_after=str(meta["not_valid_after"]),
        fail_safe_after=int(meta["fail_safe_after"]),
        rules=rules,
    )


def _parse_rule(raw: dict[str, Any]) -> Rule:
    effect = raw["effect"]
    if effect not in ("ALLOW", "DENY"):
        raise ValueError(f"rule {raw.get('id')!r}: effect must be ALLOW or DENY, got {effect!r}")
    conditions = raw.get("conditions") or {}
    return Rule(
        id=raw["id"],
        priority=int(raw["priority"]),
        role=raw["role"],
        tool=tuple(raw["tool"]),
        effect=Decision[effect],
        critical_path=bool(raw.get("critical_path", False)),
        destination=tuple(raw["destination"]) if "destination" in raw else None,
        resource=tuple(raw["resource"]) if "resource" in raw else None,
        max_data_class=conditions.get("max_data_class"),
        session_taint=tuple(conditions["session_taint"]) if "session_taint" in conditions else None,
        inspect=bool(raw.get("inspect", False)),
        reason=str(raw.get("reason", "")),
    )


def evaluate(
    bundle: Bundle,
    *,
    role: str,
    tool: str,
    fqdn: str | None,
    resource: str | None,
    session_taint: str,
) -> EvalResult:
    """Evaluate one request against a loaded bundle. Deterministic: same inputs, same bundle,
    same output — matching walks `bundle.rules` in file order and the winner is chosen by an
    explicit sort key, never by dict/set iteration (invariant §3.3)."""
    candidates = [
        r
        for r in bundle.rules
        if r.role == role
        and tool in r.tool
        and _matches_target(r, fqdn, resource)
        and _matches_taint(r, session_taint)
    ]
    deny = [r for r in candidates if r.effect == Decision.DENY]
    allow = [r for r in candidates if r.effect == Decision.ALLOW]

    if deny:
        winner = _pick_winner(deny)
        return EvalResult(
            Decision.DENY, winner.id, "matched_explicit_deny", winner.max_data_class, winner.inspect
        )
    if not allow:
        return EvalResult(Decision.DENY, "DEFAULT_DENY", "no_matching_rule", None, False)

    winner = _pick_winner(allow)

    # --- taint ceiling: structural and non-overridable (AGENTFW_CONTEXT.md §10) ---
    # WHY this lives here and not as another rule condition only: a rule author forgetting to add
    # a session_taint condition must not accidentally open an exfil path. This check runs
    # regardless of what any individual rule declares — rule-level session_taint conditions (used
    # throughout default.yaml) are an *additional*, finer-grained restriction on top of this, not
    # a substitute for it.
    if session_taint == "tainted" and (
        tool in WRITE_TOOLS or winner.max_data_class in _HIGH_DATA_CLASSES
    ):
        return EvalResult(
            Decision.DENY, winner.id, "taint_ceiling", winner.max_data_class, winner.inspect
        )

    return EvalResult(
        Decision.ALLOW, winner.id, "matched_explicit_allow", winner.max_data_class, winner.inspect
    )


def _matches_target(rule: Rule, fqdn: str | None, resource: str | None) -> bool:
    if rule.destination is not None:
        return fqdn is not None and any(fnmatch(fqdn, pat) for pat in rule.destination)
    if rule.resource is not None:
        return resource is not None and any(fnmatch(resource, pat) for pat in rule.resource)
    return True  # no restriction declared -> matches any target for this role+tool


def _matches_taint(rule: Rule, session_taint: str) -> bool:
    return rule.session_taint is None or session_taint in rule.session_taint


def _pick_winner(rules: list[Rule]) -> Rule:
    # WHY -priority (not priority) as the primary sort key: `min()` with this key picks the
    # *highest* priority number first, then the lexicographically smallest id as the deterministic
    # tie-break — both are stated requirements, not incidental.
    return min(rules, key=lambda r: (-r.priority, r.id))
