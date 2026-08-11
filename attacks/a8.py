"""A8 - Normalization bypass (userinfo confusion). Attack URL, exactly as specified:
    http://evil.com@api.trusted-news.com/
Per URL syntax, the real host is whatever follows '@' - api.trusted-news.com - and "evil.com" is
discarded userinfo. pep/normalize.py's normalize_url() derives the canonical host from
urlsplit(...).hostname (RFC-3986-correct), never from a naive prefix/substring check, and rebuilds
the canonical URL from that host alone - userinfo never survives into what gets evaluated or
forwarded. That is the property this script demonstrates: the confusing prefix has zero influence
on the destination policy actually sees.

The calling role is finance_agent, which has no http.get charter at all (R-FINANCE-003 denies every
http.get, unconditionally, regardless of destination) - so this attack is genuinely blocked
regardless of which host the URL resolves to, and the demonstration is precise: normalization
still runs and still produces the correct canonical destination (shown below), it just isn't what
saves this particular call, because policy would have denied it either way. A second, mirror-image
check (http://api.trusted-news.com@evil.com/, evil.com moved to the REAL-host position) confirms
the same correct resolution in the other direction - the canonical host is genuinely evil.com
there, not the trusted-looking string that appears first in the raw text.
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
from pep.normalize import normalize_url

PEP_URL = os.environ.get("PEP_URL", "http://pep:8080")
IDENTITY_URL = os.environ.get("IDENTITY_ISSUER_URL", "http://identity:8082")

TOOL = "http.get"
RAW_URL = "http://evil.com@api.trusted-news.com/"
ARGUMENTS = {"url": RAW_URL}
SESSION_ID = "a8-normalization-bypass"
MIRROR_URL = "http://api.trusted-news.com@evil.com/"

EXPECTED_ROLE = "finance_agent"
EXPECTED_DECISION = "DENY"
EXPECTED_REASON = "matched_explicit_deny"


def run() -> AttackResult:
    reset_process_state()
    notes: list[str] = []

    canonical = normalize_url(RAW_URL)
    mirror_canonical = normalize_url(MIRROR_URL)
    notes.append(f"raw input:            {RAW_URL!r}")
    notes.append(f"canonical destination: fqdn={canonical.fqdn!r}, url={canonical.url!r}")
    notes.append(
        f"mirror check ({MIRROR_URL!r}) canonicalizes to fqdn={mirror_canonical.fqdn!r} - "
        "confirms the real host is always taken from what follows '@', in either direction, "
        "never from whichever string appears first in the raw text."
    )

    live = try_live_pep_call_verified(
        pep_url=PEP_URL,
        identity_url=IDENTITY_URL,
        tool=TOOL,
        arguments=ARGUMENTS,
        session_id=SESSION_ID,
        expected_role=EXPECTED_ROLE,
    )
    local_result, local_event = run_locally(
        role="finance_agent",
        service="finance-agent",
        tool=TOOL,
        arguments=ARGUMENTS,
        session_id=SESSION_ID,
    )

    mechanism_match: bool | None = None
    if live.reachable and live.role_ok:
        status = REAL_DOCKER_VERIFIED
        decision, reason = live.decision, live.reason
        mechanism_match = assess_mechanism(decision, reason, EXPECTED_DECISION, EXPECTED_REASON)
        notes.append(
            f"decision/reason above came from the live PEP (which itself normalizes stage 2 "
            f"before evaluating/forwarding - AGENTFW_CONTEXT.md §2), after genuinely verifying "
            f"this container attested as role={live.attested_role!r}; risk detail below is a "
            "local replay."
        )
    else:
        status = UNVERIFIED
        decision, reason = "NOT_ATTEMPTED", "real_docker_path_unreachable"
        notes.append(
            f"REQUIRED real path not reached: {live.error} Reported UNVERIFIED, not blocked — "
            "run via `docker compose run --rm finance-agent python -m attacks.a8` (the container "
            "that genuinely attests as finance_agent) to actually demonstrate it."
        )
        notes.append(
            f"supplementary only (does not count toward this attack's verification): a local "
            f"replay produced decision={local_result.decision.name} reason={local_result.reason!r} "
            f"policy_id={local_result.policy_id!r} — not itself a Docker attestation."
        )
    notes.append(
        "finance_agent has no http.get charter at all (R-FINANCE-003) - this call is denied "
        "regardless of which host the confusing URL resolves to; normalization is shown "
        "independently above because policy alone does not prove normalization ran correctly."
    )

    return AttackResult(
        attack_id="A8",
        description="Normalization bypass - userinfo cannot fool destination/policy evaluation",
        category="normalization_bypass",
        attempted=f"{TOOL} {RAW_URL}",
        identity_desc=f"role={EXPECTED_ROLE}, service=finance-agent (attested and verified)",
        destination=canonical.url,
        stage="normalization (stage 2) produces the real destination; policy (stage 3) denies it",
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
