"""A2 - Data exfiltration via DLP. finance_agent POSTs to api.approved-erp.com, a destination its
own charter explicitly allows (R-FINANCE-001, policy would say ALLOW) - but the request body
carries an AWS-access-key-shaped credential. Policy alone would let this through; DLP (stage 5)
is what actually stops it (dlp/detectors.py's AWS_ACCESS_KEY_ID regex, a structured high-confidence
BLOCK match), narrowing the final decision below what policy alone decided. The matched secret
value itself is never printed - only the detector name and severity (dlp/detectors.py's own stated
rule: "a DLP log that records the secret it found is a secret store with worse access control").
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

TOOL = "http.post"
# WHY this exact value: AKIA + 16 chars is dlp/detectors.py's highest-precision, deterministic
# BLOCK trigger - no Luhn/entropy randomness, so the demo is stable across runs. It is a
# syntactically valid-shaped but non-functional placeholder, never a real credential.
_PLACEHOLDER_SECRET = "AKIAABCDEFGHIJKLMNOP"
ARGUMENTS = {
    "url": "https://api.approved-erp.com/invoices",
    "body": f"vendor=acme&amount=4200&internal_note=key={_PLACEHOLDER_SECRET}",
}
SESSION_ID = "a2-dlp-exfiltration"


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
        role="finance_agent",
        service="finance-agent",
        tool=TOOL,
        arguments=ARGUMENTS,
        session_id=SESSION_ID,
    )

    if live is not None:
        status = REAL_DOCKER_VERIFIED
        decision, reason = live["decision"], live["reason"]
        notes.append(
            "decision/reason above came from the live PEP; risk_score/risk_factors/full event "
            "below are from an identical local replay, since the PEP's public API does not "
            "expose per-decision risk internals to the caller."
        )
    else:
        status = TEST_ONLY
        decision, reason = local_result.decision.name, local_result.reason
        notes.append(
            f"live identity ({IDENTITY_URL}) / PEP ({PEP_URL}) unreachable - no Docker deployment "
            "in this environment. This run used an in-process replay of the real pep.pipeline "
            "code (including the real dlp.detectors.scan() call) instead."
        )
    notes.append(
        "the matched secret value is never printed by this script or by dlp/detectors.py - only "
        "the detector name (AWS_ACCESS_KEY_ID) and its severity (BLOCK) are logged/reported."
    )

    return AttackResult(
        attack_id="A2",
        description="Data exfiltration - structured secret caught by DLP despite policy ALLOW",
        category="dlp_exfiltration",
        attempted=f"{TOOL} {ARGUMENTS['url']} (body contains an AWS-key-shaped secret, redacted)",
        identity_desc="role=finance_agent, service=finance-agent (genuinely signed token)",
        destination=ARGUMENTS["url"],
        stage="DLP (stage 5) - policy alone would ALLOW; DLP narrows to DENY",
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
