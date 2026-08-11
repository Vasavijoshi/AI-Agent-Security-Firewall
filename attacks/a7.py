"""A7 - Malicious tool / threat-intel-flagged destination. A compromised or misdirected tool call
targets a domain already known bad (threat_intel/lists/malicious_fqdns.txt's "known-c2.example" -
a distinct entry from A6's evil.example.com, kept separate so the two attacks don't share a
destination). This exercises stage 4 (threat intel), the one pipeline stage none of A1-A6 makes
the headline signal for: a local, O(1) set lookup that runs before the more expensive DLP/risk
work and, on a hit, both scores heavily (THREAT_INTEL_HIT, 60 of the 100-point cap) and
independently triggers automatic quarantine entry for the calling workload - a real side effect of
pep/pipeline.py's own logic (`if ti_hit: quarantine.enter(...)`), captured here rather than
silently discarded, since quarantine has no live eventstore to persist against outside Docker.

research_agent has no allow rule for this destination either, so policy alone would already deny
it - the threat-intel hit is not the only wall, but it is the one this script is built to surface,
consistent with "prefer architectural diversity, not cosmetic diversity."
"""

from __future__ import annotations

import os
import sys

from attacks.common import (
    REAL_DOCKER_VERIFIED,
    UNVERIFIED,
    AttackResult,
    assess_mechanism,
    emit_result_json,
    mechanism_exit_code,
    print_report,
    reset_process_state,
    run_locally,
    try_live_pep_call_verified,
)

PEP_URL = os.environ.get("PEP_URL", "http://pep:8080")
IDENTITY_URL = os.environ.get("IDENTITY_ISSUER_URL", "http://identity:8082")

TOOL = "http.get"
ARGUMENTS = {"url": "https://known-c2.example/beacon"}
SESSION_ID = "a7-malicious-tool"

# WHY expected_reason is "no_matching_rule", not something threat-intel-shaped: research_agent has
# no allow rule for this destination either, so policy's default-deny is the primary wall (min() in
# pep/pipeline.py always prefers the policy candidate on a tie) - the threat-intel hit is a real,
# independently-triggered side effect (quarantine.enter()), not the `reason` string itself. Run
# with quarantine already cleared (see run_all.py), this call's OWN mechanism is the default-deny;
# what it demonstrates about threat intel is that the NEXT call from this workload gets quarantined
# — exactly what A10 demonstrates on purpose.
EXPECTED_ROLE = "research_agent"
EXPECTED_DECISION = "DENY"
EXPECTED_REASON = "no_matching_rule"


def run() -> AttackResult:
    reset_process_state()
    notes: list[str] = []

    live = try_live_pep_call_verified(
        pep_url=PEP_URL,
        identity_url=IDENTITY_URL,
        tool=TOOL,
        arguments=ARGUMENTS,
        session_id=SESSION_ID,
        expected_role=EXPECTED_ROLE,
    )
    quarantine_calls: list[tuple[str, str]] = []
    local_result, local_event = run_locally(
        role="research_agent",
        service="agent",
        tool=TOOL,
        arguments=ARGUMENTS,
        session_id=SESSION_ID,
        quarantine_calls=quarantine_calls,
    )

    mechanism_match: bool | None = None
    if live.reachable and live.role_ok:
        status = REAL_DOCKER_VERIFIED
        decision, reason = live.decision, live.reason
        mechanism_match = assess_mechanism(decision, reason, EXPECTED_DECISION, EXPECTED_REASON)
        notes.append(
            f"decision/reason above came from the live PEP, after genuinely verifying this "
            f"container attested as role={live.attested_role!r}; risk_score/risk_factors/full "
            "event below, and the quarantine side effect note, are from an identical local replay."
        )
    else:
        status = UNVERIFIED
        decision, reason = "NOT_ATTEMPTED", "real_docker_path_unreachable"
        notes.append(
            f"REQUIRED real path not reached: {live.error} Reported UNVERIFIED, not blocked — "
            "run via `docker compose run --rm agent python -m attacks.a7` (the container that "
            "genuinely attests as research_agent) to actually demonstrate it."
        )
        notes.append(
            f"supplementary only (does not count toward this attack's verification): a local "
            f"replay produced decision={local_result.decision.name} reason={local_result.reason!r} "
            f"policy_id={local_result.policy_id!r} — not itself a Docker attestation."
        )

    if quarantine_calls:
        for workload_key, quarantine_reason in quarantine_calls:
            notes.append(
                f"real side effect: pep/pipeline.py called quarantine.enter({workload_key!r}, "
                f"{quarantine_reason!r}) - in a live deployment this persists to the eventstore "
                "and every subsequent call from this workload is denied with "
                "reason=AGENT_QUARANTINED until a human releases it, regardless of what it asks "
                "for next. Captured here (no live eventstore in this run) rather than silently "
                "discarded."
            )
    else:
        notes.append("no quarantine.enter() call was triggered by this single request.")

    return AttackResult(
        attack_id="A7",
        description="Malicious tool - request targets a known-bad, threat-intel-listed destination",
        category="threat_intel_hit",
        attempted=f"{TOOL} {ARGUMENTS['url']}",
        identity_desc=f"role={EXPECTED_ROLE}, service=agent (genuinely attested and verified)",
        destination=ARGUMENTS["url"],
        stage="threat intel (stage 4) - local blocklist hit; policy also denies independently",
        policy_id=local_result.policy_id,
        reason=reason,
        risk_score=local_result.risk_score,
        risk_factors=local_result.risk_factors,
        decision=decision,
        event=local_event,
        verification_status=status,
        notes=notes,
        expected_decision=EXPECTED_DECISION,
        expected_reason=EXPECTED_REASON,
        mechanism_match=mechanism_match,
    )


if __name__ == "__main__":
    _result = run()
    print_report(_result)
    emit_result_json(_result)
    sys.exit(mechanism_exit_code(_result))
