"""Bundle validation: conflict detection, shadow-rule detection, unknown-role checks — fails the
CI build, not runtime."""

from __future__ import annotations

import sys
from dataclasses import dataclass

from policy.engine import Bundle, Decision, Rule, load_bundle

KNOWN_ROLES = frozenset({"research_agent", "finance_agent", "support_agent", "admin_agent"})
# WHY this set is hardcoded here rather than derived from a deployed-agent registry: only one role
# (research_agent) has a live container in docker-compose.yml today. The compiler validates the
# *bundle* against which roles are allowed to exist in this project, not against what happens to
# be deployed right now.


@dataclass(frozen=True)
class CompileError:
    code: str
    message: str


@dataclass(frozen=True)
class CompileWarning:
    code: str
    message: str


class BundleInvalidError(Exception):
    """Raised by compile_bundle() when validation fails. str(exc) lists every error found, not
    just the first — a policy author fixing one at a time against real CI turnaround is worse
    than seeing the whole list up front."""


def compile_bundle(path: str) -> tuple[Bundle, list[CompileWarning]]:
    """Load and validate a bundle. Raises BundleInvalidError on any hard failure; returns
    (bundle, warnings) on success."""
    bundle = load_bundle(path)
    errors = (
        _unknown_role_errors(bundle)
        + _overlap_errors(bundle)
        + _missing_critical_path_errors(bundle)
    )
    if errors:
        summary = "\n".join(f"  [{e.code}] {e.message}" for e in errors)
        raise BundleInvalidError(
            f"policy bundle failed validation ({len(errors)} error(s)):\n{summary}"
        )
    return bundle, _find_shadowed(bundle)


def _unknown_role_errors(bundle: Bundle) -> list[CompileError]:
    return [
        CompileError("UNKNOWN_ROLE", f"rule {r.id!r} references unknown role {r.role!r}")
        for r in bundle.rules
        if r.role not in KNOWN_ROLES
    ]


def _overlap_errors(bundle: Bundle) -> list[CompileError]:
    """Same-priority rules for the same role, with intersecting tool sets and *identical* target
    restrictions (or both unrestricted), but different effects.

    WHY "identical", not full glob-intersection: deciding whether two arbitrary glob patterns
    (e.g. "*.arxiv.org" vs "sub.*.org") can ever match the same string is a much bigger problem
    than this project needs solved. Exact-restriction matching still catches the common authoring
    mistake — copy a rule, flip the effect, forget to change the priority — without false-
    positiving on rules that merely happen to share a tool.
    """
    errors: list[CompileError] = []
    by_role: dict[str, list[Rule]] = {}
    for r in bundle.rules:
        by_role.setdefault(r.role, []).append(r)
    for role, rules in by_role.items():
        for i, r1 in enumerate(rules):
            for r2 in rules[i + 1 :]:
                if (
                    r1.priority == r2.priority
                    and r1.effect != r2.effect
                    and set(r1.tool) & set(r2.tool)
                    and r1.destination == r2.destination
                    and r1.resource == r2.resource
                ):
                    errors.append(
                        CompileError(
                            "CONFLICTING_RULES",
                            f"{r1.id!r} and {r2.id!r} (role {role!r}) share priority "
                            f"{r1.priority}, overlapping tools, and identical targets, but "
                            "one is ALLOW and the other DENY",
                        )
                    )
    return errors


def _missing_critical_path_errors(bundle: Bundle) -> list[CompileError]:
    covered = {r.role for r in bundle.rules if r.critical_path}
    return [
        CompileError(
            "NO_CRITICAL_PATH",
            f"role {role!r} has no critical_path rule — it would be fully stranded in "
            "fail-tight mode (AGENTFW_CONTEXT.md §16)",
        )
        for role in sorted(KNOWN_ROLES - covered)
    ]


def _find_shadowed(bundle: Bundle) -> list[CompileWarning]:
    """A rule R is shadowed if some other same-role, same-or-broader-tool, unrestricted-target
    rule R' wins the resolution every time R matches — either because R' is a DENY (which beats
    an ALLOW R regardless of priority) or because R' shares R's effect and outranks it on the same
    (priority, id) tie-break the engine uses. Only unrestricted rules (no destination/resource) are
    checked as potential shadowers — a restricted rule doesn't provably cover everything a
    narrower rule matches, so it's excluded to avoid false positives.
    """
    warnings: list[CompileWarning] = []
    for r in bundle.rules:
        for other in bundle.rules:
            if other is r or other.role != r.role:
                continue
            if other.destination is not None or other.resource is not None:
                continue
            if not set(r.tool) <= set(other.tool):
                continue
            outranks = other.priority > r.priority or (
                other.priority == r.priority and other.id < r.id
            )
            shadows = (other.effect == Decision.DENY and r.effect == Decision.ALLOW) or (
                other.effect == r.effect and outranks
            )
            if shadows:
                warnings.append(
                    CompileWarning(
                        "SHADOWED_RULE",
                        f"{r.id!r} is shadowed by {other.id!r} — every request {r.id!r} "
                        f"matches, {other.id!r} also matches and wins resolution",
                    )
                )
                break
    return warnings


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "policy/bundles/default.yaml"
    try:
        _, warnings = compile_bundle(path)
    except BundleInvalidError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    for w in warnings:
        print(f"WARNING [{w.code}] {w.message}")
    print(f"policy bundle OK: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
