"""A10 - Deliberate quarantine-cascade demonstration (the C2 fix, docs/hostile-review.md).

This is NOT a tenth independent attack demonstrating its own novel enforcement mechanism, and it
must never be reported or counted as one. It exists to show, on purpose and under a controlled
setup, the exact behavior that Verification 5 and Verification 6 caught by accident: once a
workload is quarantined, pep/pipeline.py's quarantine gate (checked before stage 3, absolute,
`if quarantined: return _deny_early("AGENT_QUARANTINED", ...)`) takes precedence over every other
mechanism a later request from that same workload would otherwise trigger — regardless of what
policy/DLP/risk would have said on their own.

Two calls, same workload (research_agent, the `agent` compose service), run back-to-back with
quarantine deliberately NOT cleared between them:

  call 1 (same request A7 makes): http.get to a threat-intel-listed destination. Expected to be
    denied on its OWN mechanism (policy default-deny) and, as a real side effect, to trigger
    quarantine.enter() — this call itself is not yet quarantined when it starts (quarantine only
    ever affects the *next* call from a workload), so it demonstrates its own claimed mechanism.

  call 2 (same request A1 makes): http.get to an unrelated unauthorized destination, sent
    immediately after call 1 with no quarantine release in between. Expected to be denied
    specifically because of AGENT_QUARANTINED, NOT because of policy default-deny — proving that
    the earlier quarantine entry genuinely persists and genuinely takes precedence, exactly the
    property Design decision 1 (fail-closed enforcement) and the quarantine gate are built to
    provide.

Run for real, after clearing quarantine first (run_all.py's orchestrator does this automatically;
see docs/verification-log.md for the exact commands):
    docker compose run --rm agent python -m attacks.a10
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any

from attacks.common import (
    REAL_DOCKER_VERIFIED,
    UNVERIFIED,
    assess_mechanism,
    reset_process_state,
    try_live_pep_call_verified,
)

PEP_URL = os.environ.get("PEP_URL", "http://pep:8080")
IDENTITY_URL = os.environ.get("IDENTITY_ISSUER_URL", "http://identity:8082")

EXPECTED_ROLE = "research_agent"

CALL_1_TOOL = "http.get"
CALL_1_ARGUMENTS = {"url": "https://known-c2.example/beacon"}
CALL_1_SESSION_ID = "a10-cascade-call-1"
CALL_1_EXPECTED_DECISION = "DENY"
CALL_1_EXPECTED_REASON = "no_matching_rule"

CALL_2_TOOL = "http.get"
CALL_2_ARGUMENTS = {"url": "https://api.premium-market-data.example.com/v1/reports"}
CALL_2_SESSION_ID = "a10-cascade-call-2"
CALL_2_EXPECTED_DECISION = "DENY"
CALL_2_EXPECTED_REASON = "AGENT_QUARANTINED"


@dataclass
class CascadeCallResult:
    label: str
    tool: str
    url: str
    verification_status: str
    decision: str
    reason: str
    expected_decision: str
    expected_reason: str
    mechanism_match: bool | None
    notes: list[str] = field(default_factory=list)


@dataclass
class CascadeDemoResult:
    """Two calls, not one AttackResult — this scenario's whole point is the relationship between
    them, not either call in isolation."""

    attack_id: str = "A10"
    description: str = (
        "Deliberate quarantine-cascade demonstration - NOT independent evidence for either call"
    )
    call_1: CascadeCallResult | None = None
    call_2: CascadeCallResult | None = None

    @property
    def demonstrates_cascade(self) -> bool:
        """True only if BOTH calls genuinely happened live, as the right role, call 1 showed its
        own mechanism, and call 2 was denied specifically by AGENT_QUARANTINED — anything else
        (e.g. call 2 denied for some other reason, or either call UNVERIFIED) means this run did
        not actually demonstrate the cascade, and must not be reported as if it did."""
        return (
            self.call_1 is not None
            and self.call_2 is not None
            and self.call_1.verification_status == REAL_DOCKER_VERIFIED
            and self.call_1.mechanism_match is True
            and self.call_2.verification_status == REAL_DOCKER_VERIFIED
            and self.call_2.mechanism_match is True
        )


def _run_one_call(
    *,
    label: str,
    tool: str,
    arguments: dict[str, Any],
    session_id: str,
    expected_decision: str,
    expected_reason: str,
) -> CascadeCallResult:
    notes: list[str] = []
    live = try_live_pep_call_verified(
        pep_url=PEP_URL,
        identity_url=IDENTITY_URL,
        tool=tool,
        arguments=arguments,
        session_id=session_id,
        expected_role=EXPECTED_ROLE,
    )

    mechanism_match: bool | None = None
    if live.reachable and live.role_ok:
        status = REAL_DOCKER_VERIFIED
        decision, reason = live.decision, live.reason
        mechanism_match = assess_mechanism(decision, reason, expected_decision, expected_reason)
        notes.append(
            f"decision/reason came from the live PEP, after genuinely verifying this container "
            f"attested as role={live.attested_role!r}."
        )
    else:
        status = UNVERIFIED
        decision, reason = "NOT_ATTEMPTED", "real_docker_path_unreachable"
        notes.append(f"REQUIRED real path not reached: {live.error} Reported UNVERIFIED.")

    return CascadeCallResult(
        label=label,
        tool=tool,
        url=arguments.get("url", ""),
        verification_status=status,
        decision=decision,
        reason=reason,
        expected_decision=expected_decision,
        expected_reason=expected_reason,
        mechanism_match=mechanism_match,
        notes=notes,
    )


def run() -> CascadeDemoResult:
    """WHY no quarantine-clear call here: this scenario is specifically about what happens when
    quarantine is NOT cleared between two calls — clearing here would defeat the point. run_all.py's
    orchestrator clears quarantine once, immediately BEFORE calling this function (so call 1 starts
    from a genuinely clean state and its own denial is real, not itself contaminated), and does not
    clear again until after both calls have run."""
    reset_process_state()

    call_1 = _run_one_call(
        label="call 1 (A7-style: threat-intel-listed destination; expected to trigger quarantine "
        "as a side effect, but to be denied on its OWN mechanism first)",
        tool=CALL_1_TOOL,
        arguments=CALL_1_ARGUMENTS,
        session_id=CALL_1_SESSION_ID,
        expected_decision=CALL_1_EXPECTED_DECISION,
        expected_reason=CALL_1_EXPECTED_REASON,
    )
    call_2 = _run_one_call(
        label="call 2 (A1-style: unrelated unauthorized destination; run immediately after call 1 "
        "with quarantine deliberately NOT cleared - expected to be denied by AGENT_QUARANTINED, "
        "not by its own default-deny mechanism)",
        tool=CALL_2_TOOL,
        arguments=CALL_2_ARGUMENTS,
        session_id=CALL_2_SESSION_ID,
        expected_decision=CALL_2_EXPECTED_DECISION,
        expected_reason=CALL_2_EXPECTED_REASON,
    )
    return CascadeDemoResult(call_1=call_1, call_2=call_2)


def print_cascade_report(r: CascadeDemoResult) -> None:
    print(f"\n=== {r.attack_id}: {r.description} ===")
    print(
        "*** This is a deliberate demonstration of quarantine PERSISTENCE, not a tenth "
        "independent attack. It does not count toward the A1-A9 independent-verification total. ***"
    )
    for call in (r.call_1, r.call_2):
        if call is None:
            continue
        print(f"\n-- {call.label} --")
        print(f"tool/url:            {call.tool} {call.url}")
        print(f"verification_status: {call.verification_status}")
        print(f"decision/reason:     {call.decision} / {call.reason}")
        print(f"expected:            {call.expected_decision} / {call.expected_reason}")
        print(f"mechanism_match:     {call.mechanism_match}")
        for note in call.notes:
            print(f"note: {note}")
    print(f"\ndemonstrates_cascade: {r.demonstrates_cascade}")
    if r.demonstrates_cascade:
        print(
            "Confirmed live: call 1 was denied by its own mechanism, and call 2 - run "
            "immediately after with quarantine deliberately not cleared - was denied specifically "
            "because of AGENT_QUARANTINED, not its own default-deny mechanism. This is the "
            "containment-persistence property working as designed, not a methodology flaw."
        )
    else:
        print(
            "Cascade NOT confirmed in this run (see verification_status/mechanism_match above for "
            "each call) - reported honestly rather than assumed."
        )


def emit_cascade_result_json(r: CascadeDemoResult) -> None:
    def _call_payload(call: CascadeCallResult | None) -> dict[str, Any] | None:
        if call is None:
            return None
        return {
            "label": call.label,
            "verification_status": call.verification_status,
            "decision": call.decision,
            "reason": call.reason,
            "expected_decision": call.expected_decision,
            "expected_reason": call.expected_reason,
            "mechanism_match": call.mechanism_match,
        }

    payload = {
        "attack_id": r.attack_id,
        "is_cascade_demo": True,
        "demonstrates_cascade": r.demonstrates_cascade,
        "call_1": _call_payload(r.call_1),
        "call_2": _call_payload(r.call_2),
    }
    print(f"RESULT_JSON:{json.dumps(payload)}")


if __name__ == "__main__":
    _result = run()
    print_cascade_report(_result)
    emit_cascade_result_json(_result)
    sys.exit(0 if _result.demonstrates_cascade else 1)
