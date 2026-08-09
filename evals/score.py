"""Scores the attack/benign corpora against the running stack: block rate, false-positive rate,
latency percentiles.

Verdict taxonomy (pre-M3 ruling, settled here before the corpus-processing loop is M3's to build):

    Blocked   = DENY or QUARANTINE           (policy.engine.BLOCKED_DECISIONS)
    Permitted = ALLOW, ALLOW_REDACTED,
                RATE_LIMIT, REQUIRE_APPROVAL  (policy.engine.PERMITTED_DECISIONS)

    Block rate            = blocked / attack corpus
    False-positive rate   = blocked / benign corpus
    Friction rate          = benign calls landing on RATE_LIMIT or REQUIRE_APPROVAL, over the
                              benign corpus — NOT a false positive (the call wasn't blocked), but
                              not free either. Reported on its own, never folded into either the
                              false-positive or the "clean permit" bucket.
"""

from __future__ import annotations

from policy.engine import BLOCKED_DECISIONS, FRICTION_DECISIONS, Decision
from risk.scorer import RiskScorer


def _blocked_fraction(decisions: list[Decision]) -> float:
    if not decisions:
        return 0.0
    return sum(1 for d in decisions if d in BLOCKED_DECISIONS) / len(decisions)


def block_rate(attack_corpus_decisions: list[Decision]) -> float:
    """Block rate = blocked / attack corpus."""
    return _blocked_fraction(attack_corpus_decisions)


def false_positive_rate(benign_corpus_decisions: list[Decision]) -> float:
    """False-positive rate = blocked / benign corpus.

    WHY this isn't just block_rate() called on a different list: the formula is identical, but
    naming it separately is the point — conflating "block rate measured on attacks" with "block
    rate measured on benign traffic" behind one ambiguous function is exactly the kind of mixup
    this taxonomy exists to rule out before M3's scorer gets written.
    """
    return _blocked_fraction(benign_corpus_decisions)


def friction_rate(benign_corpus_decisions: list[Decision]) -> float:
    """Friction rate = benign calls landing on RATE_LIMIT or REQUIRE_APPROVAL, over the benign
    corpus. Never added into false_positive_rate()'s numerator — a held-for-approval benign call
    is friction the firewall imposes, not a misclassification of it as an attack."""
    if not benign_corpus_decisions:
        return 0.0
    friction = sum(1 for d in benign_corpus_decisions if d in FRICTION_DECISIONS)
    return friction / len(benign_corpus_decisions)


if __name__ == "__main__":
    # WHY only warm_up() here, nothing else: the corpus-processing loop itself is M3 scope
    # (AGENTFW_CONTEXT.md §9) — this is the one piece of M3's eventual startup sequence the
    # pre-M3 ruling asked to have in place now, so it isn't forgotten once M3 builds the rest.
    RiskScorer.warm_up()
