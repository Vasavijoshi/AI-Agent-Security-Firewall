"""A4 - Real multi-agent lateral movement. research_agent, running as the actual deployed `agent`
compose service, obtains its own valid workload token through the real attestation path (a live
POST to identity/issuer.py's /attest, resolved via the Docker API from the actual calling
container - see AGENTFW_CONTEXT.md §2) and attempts agent.invoke against finance-agent.

This script does not forge a token, does not construct a fake identity, does not pretend to be
finance-agent, and does not treat a local pipeline replay as proof of the Docker path (per this
milestone's own instruction) - it only calls the real, live identity and PEP services. If they are
unreachable, the result is reported UNVERIFIED, not silently claimed. A supplementary local
pipeline replay is shown separately, clearly labeled as not satisfying this attack's own
requirement, since it demonstrates the same policy logic without the real Docker attestation the
Definition of Done for A4 specifically asks for.

Run for real via, after `docker compose up -d`:
    docker compose run --rm agent python -m attacks.a4
(`run`, not `exec` - `agent` is a one-shot batch job with no long-running container for `exec` to
target once its default scenario finishes. agent-net hostnames "identity"/"pep" only resolve
inside the compose network, so running this from the host or without Docker running structurally
cannot reach REAL_DOCKER_VERIFIED.)
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

TOOL = "agent.invoke"
ARGUMENTS = {
    "target_service": "finance-agent",
    "tool": "db.query",
    "arguments": {"table": "ledger"},
}
SESSION_ID = "a4-lateral-movement"

EXPECTED_ROLE = "research_agent"
EXPECTED_DECISION = "DENY"
EXPECTED_REASON = "no_matching_east_west_rule"


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

    # Supplementary only - not the source of truth for this attack's verification_status. Uses the
    # exact real-pipeline mechanism tests/test_east_west.py already validates: a genuinely signed,
    # genuinely verified token for service="agent" (research_agent), presented to the real
    # pep.pipeline.run_pipeline() for a real evaluate_east_west() call.
    local_result, local_event = run_locally(
        role="research_agent",
        service="agent",
        tool=TOOL,
        arguments=ARGUMENTS,
        session_id=SESSION_ID,
    )

    mechanism_match: bool | None = None
    if live.reachable and live.role_ok:
        status = REAL_DOCKER_VERIFIED
        decision, reason = live.decision, live.reason
        policy_id = local_result.policy_id  # not exposed by the live API; supplementary only
        risk_score, risk_factors = local_result.risk_score, local_result.risk_factors
        mechanism_match = assess_mechanism(decision, reason, EXPECTED_DECISION, EXPECTED_REASON)
        notes.append(
            f"decision/reason above came from the live PEP, reached after genuinely verifying "
            f"this container attested as role={live.attested_role!r} against the actual deployed "
            "'agent' container's identity. policy_id/risk detail below are from the supplementary "
            "local replay - not exposed by the live API."
        )
    else:
        status = UNVERIFIED
        decision, reason = "NOT_ATTEMPTED", "real_docker_path_unreachable"
        policy_id, risk_score, risk_factors = "N/A", 0, []
        notes.append(
            f"REQUIRED real path not reached: {live.error} This milestone's own instructions "
            "forbid treating a local pipeline replay as proof for A4 - so this attack is reported "
            "UNVERIFIED, not blocked, in this environment. Run `docker compose up -d` then "
            "`docker compose run --rm agent python -m attacks.a4` to actually demonstrate it."
        )
        notes.append(
            f"supplementary only (does not count toward this attack's verification): a local "
            f"replay of the identical call against the real pipeline (research_agent's own "
            f"genuinely signed, correctly bound token, presented for agent.invoke against "
            f"finance-agent) produced decision={local_result.decision.name} "
            f"reason={local_result.reason!r} policy_id={local_result.policy_id!r} - consistent "
            f"with tests/test_east_west.py's own verified behavior, but not itself a Docker "
            f"attestation."
        )

    return AttackResult(
        attack_id="A4",
        description="Multi-agent lateral movement - research_agent invoking finance-agent",
        category="lateral_movement",
        attempted=f"agent.invoke target={ARGUMENTS['target_service']!r} tool={ARGUMENTS['tool']!r}",
        identity_desc="source_workload=agent (research_agent) -> dest_workload=finance-agent",
        destination="finance-agent (east-west, not a network destination)",
        stage="east-west policy (stage 3, evaluate_east_west()) - no rule grants this pair",
        policy_id=policy_id,
        reason=reason,
        risk_score=risk_score,
        risk_factors=risk_factors,
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
