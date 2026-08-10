"""Runs all nine M3 attack demonstrations (attacks/a1.py .. a9.py) and prints a recruiter-facing
summary table plus a final N/9 BLOCKED line.

WHY "blocked" here is not just AttackResult.blocked: for A4 and A9 specifically, the milestone's
own requirement is the real, live Docker path — a local pipeline replay is explicitly disclosed as
supplementary, not proof (see each script's own module docstring). An attack whose
verification_status is UNVERIFIED has not reached the security boundary it was built to test, so
it does not count toward the total here even if a supplementary local check happened to show a
denial — counting it would be exactly the "count an exception as automatically meaning blocked"
mistake this milestone explicitly rules out, just relocated to a different field.

Exit code is 0 only when all nine genuinely counted as blocked; non-zero otherwise — including,
honestly, a normal run of this script in an environment with no Docker, where A4 and A9 cannot
reach REAL_DOCKER_VERIFIED and are correctly reported as not (yet) demonstrated.
"""

from __future__ import annotations

import sys

import attacks.a1 as a1
import attacks.a2 as a2
import attacks.a3 as a3
import attacks.a4 as a4
import attacks.a5 as a5
import attacks.a6 as a6
import attacks.a7 as a7
import attacks.a8 as a8
import attacks.a9 as a9
from attacks.common import UNVERIFIED, AttackResult, print_report
from risk.scorer import RiskScorer

ATTACKS = (a1, a2, a3, a4, a5, a6, a7, a8, a9)


def _counts_as_blocked(r: AttackResult) -> bool:
    return r.blocked and r.verification_status != UNVERIFIED


def main() -> int:
    # WHY only warm_up() here besides the attacks themselves: this is the one piece of M3's
    # startup sequence the pre-M3 ruling asked to have in place ahead of time (see the module's
    # prior docstring, preserved in spirit) — seeds org/role-level novelty state from
    # risk/baseline.jsonl so every attack's risk score reflects a deployment with real history
    # behind it, not a cold-started process.
    RiskScorer.warm_up()

    results: list[AttackResult] = []
    for module in ATTACKS:
        result = module.run()
        print_report(result)
        results.append(result)

    header = (
        f"{'Attack':<7}{'Category':<27}{'Blocked':<9}{'Stage':<16}{'Reason/Policy':<40}{'Risk':<5}"
    )
    print("\n" + "=" * len(header))
    print(header)
    print("-" * len(header))
    for r in results:
        stage_short = r.stage.split(" ")[0].split("(")[0].strip()
        reason_policy = f"{r.policy_id}/{r.reason}"[:38]
        blocked_mark = "YES" if _counts_as_blocked(r) else ("NO*" if r.blocked else "NO")
        print(
            f"{r.attack_id:<7}{r.category:<27}{blocked_mark:<9}{stage_short:<16}"
            f"{reason_policy:<40}{r.risk_score:<5}"
        )
    print("-" * len(header))
    print("NO* = a supplementary local check showed a denial, but this attack's own required")
    print("      verification (real Docker) was not reached in this run — not counted as blocked.")

    blocked_count = sum(1 for r in results if _counts_as_blocked(r))
    total = len(results)
    unverified = [r.attack_id for r in results if r.verification_status == UNVERIFIED]
    print(f"\n{blocked_count}/{total} BLOCKED")
    if unverified:
        joined = ", ".join(unverified)
        print(f"UNVERIFIED (real Docker required, not demonstrated in this run): {joined}")
        print(
            "Run `docker compose up -d` then `docker compose exec agent python -m attacks.run_all` "
            "to attempt the real path for every attack, including these."
        )

    return 0 if blocked_count == total else 1


if __name__ == "__main__":
    sys.exit(main())
