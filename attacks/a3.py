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
    TEST_ONLY,
    AttackResult,
    print_report,
    reset_process_state,
    run_locally,
    try_live_pep_call,
)

PEP_URL = os.environ.get("PEP_URL", "http://pep:8080")
IDENTITY_URL = os.environ.get("IDENTITY_ISSUER_URL", "http://identity:8082")

FETCH_TOOL = "http.get"
FETCH_ARGUMENTS = {"url": "https://internal-admin.internal/console"}
QUERY_TOOL = "db.query"
QUERY_ARGUMENTS = {"table": "credentials"}
SESSION_ID = "a3-taint-ceiling"


def run() -> AttackResult:
    reset_process_state()
    notes: list[str] = []

    live_fetch = try_live_pep_call(
        pep_url=PEP_URL,
        identity_url=IDENTITY_URL,
        tool=FETCH_TOOL,
        arguments=FETCH_ARGUMENTS,
        session_id=SESSION_ID,
    )
    live_query = (
        try_live_pep_call(
            pep_url=PEP_URL,
            identity_url=IDENTITY_URL,
            tool=QUERY_TOOL,
            arguments=QUERY_ARGUMENTS,
            session_id=SESSION_ID,
        )
        if live_fetch is not None
        else None
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
        "real containers) - so this attack's identity/attestation layer cannot reach "
        "REAL_DOCKER_VERIFIED regardless of whether Docker is running; only the pipeline stages "
        "downstream of identity (normalize/policy/threat-intel/DLP/risk/decision) can be, if a "
        "real research_agent/finance_agent/support_agent token were substituted. This is disclosed "
        "here rather than worked around, since admin_agent is the only role in the current bundle "
        "whose own rules produce a clean, single-session taint-ceiling demonstration."
    )

    if live_query is not None:
        status = REAL_DOCKER_VERIFIED
        decision, reason = live_query["decision"], live_query["reason"]
        notes.append(
            "decision/reason above came from the live PEP for the second (db.query) call; "
            "risk_score/risk_factors/full event below are from an identical local replay."
        )
    else:
        status = TEST_ONLY
        decision, reason = local_query_result.decision.name, local_query_result.reason
        notes.append(
            f"live identity ({IDENTITY_URL}) / PEP ({PEP_URL}) unreachable - no Docker deployment "
            "in this environment. Both calls above were replayed in-process against the real "
            "pep.pipeline code, sharing one session_id so taint genuinely carried between them."
        )

    return AttackResult(
        attack_id="A3",
        description="Taint ceiling - secret-table read denied after the session was tainted",
        category="taint_containment",
        attempted=f"{QUERY_TOOL} table={QUERY_ARGUMENTS['table']!r} (session now tainted)",
        identity_desc="role=admin_agent, service=admin-agent (genuinely signed token)",
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
    )


if __name__ == "__main__":
    print_report(run())
    sys.exit(0)
