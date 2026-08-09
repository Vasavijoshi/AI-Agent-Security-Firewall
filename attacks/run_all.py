"""Runs all 7 attack scenarios against the running stack and prints a block/allow summary — the
money script."""

from risk.scorer import RiskScorer

if __name__ == "__main__":
    # WHY only warm_up() here, nothing else: the attack scenarios themselves are M3 scope
    # (AGENTFW_CONTEXT.md §9) — this is the one piece of M3's eventual startup sequence the
    # pre-M3 ruling asked to have in place now, so it isn't forgotten once M3 builds the rest.
    RiskScorer.warm_up()
