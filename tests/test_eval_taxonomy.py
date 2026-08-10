"""Tests for the pre-M3 eval verdict taxonomy: policy.engine's BLOCKED/PERMITTED/FRICTION
decision sets, and evals/score.py's block_rate/false_positive_rate/approval_rate/throttle_rate.

WHY approval_rate and throttle_rate, not one combined friction_rate (M3 correction, after review):
FRICTION_DECISIONS (RATE_LIMIT + REQUIRE_APPROVAL) is still a real grouping in policy/engine.py —
both are "permitted, not free" — but they are not the same kind of event for reporting purposes.
REQUIRE_APPROVAL genuinely stops the call (no approval workflow exists yet); RATE_LIMIT is
designed-not-implemented and executes the call exactly like ALLOW. A single number averaging "a
human was stopped" with "logged and proceeded anyway" cannot inform any decision.
"""

from __future__ import annotations

from evals.score import approval_rate, block_rate, false_positive_rate, throttle_rate
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
    """FRICTION_DECISIONS itself is unchanged — still a valid concept in policy/engine.py, just no
    longer reported as one aggregate eval metric (see module WHY)."""
    assert FRICTION_DECISIONS <= PERMITTED_DECISIONS
    assert FRICTION_DECISIONS == {Decision.RATE_LIMIT, Decision.REQUIRE_APPROVAL}


def test_block_rate_on_a_mixed_attack_corpus():
    decisions = [Decision.DENY, Decision.DENY, Decision.QUARANTINE, Decision.ALLOW]
    assert block_rate(decisions) == 0.75


def test_false_positive_rate_on_a_mixed_benign_corpus():
    decisions = [Decision.ALLOW, Decision.ALLOW, Decision.ALLOW, Decision.DENY]
    assert false_positive_rate(decisions) == 0.25


def test_approval_rate_counts_require_approval_only():
    decisions = [
        Decision.ALLOW,
        Decision.RATE_LIMIT,
        Decision.REQUIRE_APPROVAL,
        Decision.ALLOW_REDACTED,
    ]
    assert approval_rate(decisions) == 0.25


def test_throttle_rate_counts_rate_limit_only():
    decisions = [
        Decision.ALLOW,
        Decision.RATE_LIMIT,
        Decision.REQUIRE_APPROVAL,
        Decision.ALLOW_REDACTED,
    ]
    assert throttle_rate(decisions) == 0.25


def test_approval_and_throttle_never_counted_as_false_positives():
    """The property that matters most here: a benign corpus made entirely of RATE_LIMIT/
    REQUIRE_APPROVAL verdicts must show 0% false positives, split correctly between approval and
    throttle — not folded into one number, and not miscounted as a block."""
    decisions = [Decision.RATE_LIMIT, Decision.REQUIRE_APPROVAL, Decision.RATE_LIMIT]
    assert false_positive_rate(decisions) == 0.0
    assert approval_rate(decisions) == 1 / 3
    assert throttle_rate(decisions) == 2 / 3


def test_approval_and_throttle_do_not_double_count_each_other():
    """A corpus of pure RATE_LIMIT must show 0% approval; a corpus of pure REQUIRE_APPROVAL must
    show 0% throttle — the whole point of splitting them is that neither absorbs the other."""
    all_throttled = [Decision.RATE_LIMIT, Decision.RATE_LIMIT]
    assert throttle_rate(all_throttled) == 1.0
    assert approval_rate(all_throttled) == 0.0

    all_approval_held = [Decision.REQUIRE_APPROVAL, Decision.REQUIRE_APPROVAL]
    assert approval_rate(all_approval_held) == 1.0
    assert throttle_rate(all_approval_held) == 0.0


def test_empty_corpus_does_not_divide_by_zero():
    assert block_rate([]) == 0.0
    assert false_positive_rate([]) == 0.0
    assert approval_rate([]) == 0.0
    assert throttle_rate([]) == 0.0
