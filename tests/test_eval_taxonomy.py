"""Tests for the pre-M3 eval verdict taxonomy: policy.engine's BLOCKED/PERMITTED/FRICTION
decision sets, and evals/score.py's block_rate/false_positive_rate/friction_rate."""

from __future__ import annotations

from evals.score import block_rate, false_positive_rate, friction_rate
from policy.engine import BLOCKED_DECISIONS, FRICTION_DECISIONS, PERMITTED_DECISIONS, Decision


def test_blocked_and_permitted_partition_the_whole_lattice():
    """Every Decision value is classified exactly once — no gaps, no double-counting."""
    assert BLOCKED_DECISIONS | PERMITTED_DECISIONS == set(Decision)
    assert BLOCKED_DECISIONS & PERMITTED_DECISIONS == set()


def test_blocked_is_exactly_deny_and_quarantine():
    assert BLOCKED_DECISIONS == {Decision.DENY, Decision.QUARANTINE}


def test_permitted_is_exactly_the_other_four():
    assert PERMITTED_DECISIONS == {
        Decision.ALLOW,
        Decision.ALLOW_REDACTED,
        Decision.RATE_LIMIT,
        Decision.REQUIRE_APPROVAL,
    }


def test_friction_is_a_subset_of_permitted_not_a_third_bucket():
    assert FRICTION_DECISIONS <= PERMITTED_DECISIONS
    assert FRICTION_DECISIONS == {Decision.RATE_LIMIT, Decision.REQUIRE_APPROVAL}


def test_block_rate_on_a_mixed_attack_corpus():
    decisions = [Decision.DENY, Decision.DENY, Decision.QUARANTINE, Decision.ALLOW]
    assert block_rate(decisions) == 0.75


def test_false_positive_rate_on_a_mixed_benign_corpus():
    decisions = [Decision.ALLOW, Decision.ALLOW, Decision.ALLOW, Decision.DENY]
    assert false_positive_rate(decisions) == 0.25


def test_friction_rate_counts_rate_limit_and_require_approval_only():
    decisions = [
        Decision.ALLOW,
        Decision.RATE_LIMIT,
        Decision.REQUIRE_APPROVAL,
        Decision.ALLOW_REDACTED,
    ]
    assert friction_rate(decisions) == 0.5


def test_friction_is_never_counted_as_a_false_positive():
    """The one property that matters most here: a benign corpus made entirely of RATE_LIMIT/
    REQUIRE_APPROVAL verdicts must show 0% false positives and 100% friction — not the reverse,
    and not split arbitrarily between the two."""
    decisions = [Decision.RATE_LIMIT, Decision.REQUIRE_APPROVAL, Decision.RATE_LIMIT]
    assert false_positive_rate(decisions) == 0.0
    assert friction_rate(decisions) == 1.0


def test_empty_corpus_does_not_divide_by_zero():
    assert block_rate([]) == 0.0
    assert false_positive_rate([]) == 0.0
    assert friction_rate([]) == 0.0
