"""A3 - Taint-driven containment. admin_agent legitimately fetches its own internal console page
(R-ADMIN-001, http.get to internal-admin.internal, ALLOWED under both clean and tainted sessions)
- this is real PEP-owned session state (pep/pipeline.py's `_SESSION_TAINT`, keyed by session_id,
set by the pipeline itself on any executed http.get, never by the agent). The agent never sets its
own taint; it is a side effect the pipeline imposes on the *session*, regardless of how trusted the
fetched destination is ("an allowlisted domain is still someone else's content" - pep/pipeline.py's
own comment).

With that same session now tainted, admin_agent attempts to read a secret-classified table
(R-ADMIN-002, db.query, resource=["*"], max_data_class=secret) - a query that rule would have
ALLOWED had the session stayed clean. R-ADMIN-002 explicitly requires `session_taint: [clean]`; once
tainted it is no longer a matching candidate at all, so the call falls through to implicit
default-deny. This is a genuine, intentional design choice documented inline in
policy/bundles/default.yaml (R-ADMIN-001's own comment): admin_agent's *console* stays reachable
even tainted (it's only internal-sensitivity), but the truly secret operations behind R-ADMIN-002
require an untainted session - the taint ceiling is enforced at the rule level here, not by
policy/engine.py's separate structural override (that code path exists for exactly this class of
rule and would fire for, e.g., R-FINANCE-002's confidential ledger read if finance_agent's session
were ever tainted - a second, rule-author-independent backstop, not exercised by this scenario).
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

FETCH_TOOL = "http.get"
FETCH_ARGUMENTS = {"url": "https://internal-admin.internal/console"}
QUERY_TOOL = "db.query"
QUERY_ARGUMENTS = {"table": "credentials"}
SESSION_ID = "a3-taint-ceiling"

# WHY this can never reach REAL_DOCKER_VERIFIED, structurally, and that is intentional: admin_agent
# has no deployed compose service and no identity/issuer.py AGENT_REGISTRY entry (only
# agent/finance-agent/support-agent are real containers in this project's current topology). This
# script does NOT invent an admin-agent service to make itself pass — per this milestone's own
# instruction, a role that genuinely doesn't exist in the deployed topology is reported UNVERIFIED,
# honestly, every time. Whichever real container this script happens to be run from will attest as
# THAT container's own real role, which is never "admin_agent" — try_live_pep_call_verified's role
# check rejects that correctly, the same mechanism that catches every other role mismatch.
EXPECTED_ROLE = "admin_agent"
EXPECTED_DECISION = "DENY"
EXPECTED_REASON = "no_matching_rule"


def run() -> AttackResult:
    reset_process_state()
    notes: list[str] = []

    live_query = try_live_pep_call_verified(
        pep_url=PEP_URL,
        identity_url=IDENTITY_URL,
        tool=QUERY_TOOL,
        arguments=QUERY_ARGUMENTS,
        session_id=SESSION_ID,
        expected_role=EXPECTED_ROLE,
    )

    # Local replay: same session_id for both calls, so taint set by the first genuinely carries
    # into the second, exactly as pep/pipeline.py's in-memory _SESSION_TAINT would in one real
    # agent session.
    local_fetch_result, _ = run_locally(
        role="admin_agent",
        service="admin-agent",
        tool=FETCH_TOOL,
        arguments=FETCH_ARGUMENTS,
        session_id=SESSION_ID,
    )
    local_query_result, local_query_event = run_locally(
        role="admin_agent",
        service="admin-agent",
        tool=QUERY_TOOL,
        arguments=QUERY_ARGUMENTS,
        session_id=SESSION_ID,
    )

    notes.append(
        f"first call (fetch internal-admin.internal) decision: {local_fetch_result.decision.name} "
        f"/ {local_fetch_result.reason} - this is expected to succeed and is what taints the "
        "session; the attack under test is the second call."
    )
    notes.append(
        "admin_agent has no deployed compose service and no identity/issuer.py AGENT_REGISTRY "
        "entry in this project's current topology (only agent/finance-agent/support-agent are "
        "real containers) - this attack's live identity/attestation layer therefore cannot reach "
        "REAL_DOCKER_VERIFIED regardless of whether Docker is running, and is reported UNVERIFIED "
        "every time on purpose, not worked around by inventing a container for it. Only the "
        "pipeline stages downstream of identity are exercised for real here, via local replay."
    )

    mechanism_match: bool | None = None
    if live_query.reachable and live_query.role_ok:
        # Structurally unreachable in this project's current topology (see the module docstring) —
        # kept here, not special-cased away, so a future real admin-agent service would correctly
        # flow through the exact same path as every other attack.
        status = REAL_DOCKER_VERIFIED
        decision, reason = live_query.decision, live_query.reason
        mechanism_match = assess_mechanism(decision, reason, EXPECTED_DECISION, EXPECTED_REASON)
        notes.append(
            "decision/reason above came from the live PEP for the second (db.query) call; "
            "risk_score/risk_factors/full event below are from an identical local replay."
        )
    else:
        status = UNVERIFIED
        decision, reason = "NOT_ATTEMPTED", "real_docker_path_unreachable"
        notes.append(
            f"REQUIRED real path not reached: {live_query.error} Reported UNVERIFIED, not "
            "blocked — a local replay is not accepted as proof of this scenario's own live "
            "mechanism."
        )
        notes.append(
            f"supplementary only (does not count toward this attack's verification): a local "
            f"replay produced decision={local_query_result.decision.name} "
            f"reason={local_query_result.reason!r} policy_id={local_query_result.policy_id!r} — "
            "not itself a Docker attestation."
        )

    return AttackResult(
        attack_id="A3",
        description="Taint ceiling - secret-table read denied after the session was tainted",
        category="taint_containment",
        attempted=f"{QUERY_TOOL} table={QUERY_ARGUMENTS['table']!r} (session now tainted)",
        identity_desc="role=admin_agent, service=admin-agent (no deployed workload — see notes)",
        destination=f"db table: {QUERY_ARGUMENTS['table']}",
        stage="policy (stage 3) - R-ADMIN-002 requires clean taint, excluded once tainted",
        policy_id=local_query_result.policy_id,
        reason=reason,
        risk_score=local_query_result.risk_score,
        risk_factors=local_query_result.risk_factors,
        decision=decision,
        event=local_query_event,
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
