"""A1 — Unauthorized API access. research_agent (read-only, charter limited to
api.trusted-news.com and *.arxiv.org — policy/bundles/default.yaml's R-RESEARCH-001) attempts to
call a third-party market-data API that is not on its allowlist. No rule matches the destination,
so this falls through to implicit default-deny (invariant §3.2 in AGENTFW_CONTEXT.md: no matching
rule -> DENY) — stopped at stage 3, policy evaluation, before threat intel, DLP, or risk ever run.
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

TOOL = "http.get"
ARGUMENTS = {"url": "https://api.premium-market-data.example.com/v1/reports"}
SESSION_ID = "a1-unauthorized-api"


def run() -> AttackResult:
    reset_process_state()
    notes: list[str] = []

    live = try_live_pep_call(
        pep_url=PEP_URL,
        identity_url=IDENTITY_URL,
        tool=TOOL,
        arguments=ARGUMENTS,
        session_id=SESSION_ID,
    )
    local_result, local_event = run_locally(
        role="research_agent",
        service="agent",
        tool=TOOL,
        arguments=ARGUMENTS,
        session_id=SESSION_ID,
    )

    if live is not None:
        status = REAL_DOCKER_VERIFIED
        decision, reason = live["decision"], live["reason"]
        notes.append(
            "decision/reason above came from the live PEP's /v1/tool-call response; "
            "risk_score/risk_factors/full event below are from an identical local replay "
            "(same role, tool, arguments) because the PEP's public API deliberately does not "
            "expose per-decision risk internals to the caller."
        )
    else:
        status = TEST_ONLY
        decision, reason = local_result.decision.name, local_result.reason
        notes.append(
            f"live identity ({IDENTITY_URL}) / PEP ({PEP_URL}) unreachable — no Docker deployment "
            "in this environment. This run used an in-process replay of the real pep.pipeline "
            "code with a genuinely signed token instead of the live attestation + proxy path."
        )

    return AttackResult(
        attack_id="A1",
        description="Unauthorized API access - destination outside role charter",
        category="unauthorized_destination",
        attempted=f"{TOOL} {ARGUMENTS['url']}",
        identity_desc="role=research_agent, service=agent (genuinely signed token)",
        destination=ARGUMENTS["url"],
        stage="policy (stage 3) — implicit default-deny, no matching rule",
        policy_id=local_result.policy_id,
        reason=reason,
        risk_score=local_result.risk_score,
        risk_factors=local_result.risk_factors,
        decision=decision,
        event=local_event,
        verification_status=status,
        notes=notes,
    )


if __name__ == "__main__":
    print_report(run())
    sys.exit(0)
