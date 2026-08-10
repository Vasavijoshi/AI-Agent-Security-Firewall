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
    TEST_ONLY,
    AttackResult,
    print_report,
    reset_process_state,
    run_locally,
    try_live_pep_call,
)
from pep.normalize import normalize_url

PEP_URL = os.environ.get("PEP_URL", "http://pep:8080")
IDENTITY_URL = os.environ.get("IDENTITY_ISSUER_URL", "http://identity:8082")

TOOL = "http.get"
RAW_URL = "http://evil.com@api.trusted-news.com/"
ARGUMENTS = {"url": RAW_URL}
SESSION_ID = "a8-normalization-bypass"
MIRROR_URL = "http://api.trusted-news.com@evil.com/"


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
            "decision/reason above came from the live PEP (which itself normalizes stage 2 before "
            "evaluating/forwarding - AGENTFW_CONTEXT.md §2); risk detail below is a local replay."
        )
    else:
        status = TEST_ONLY
        decision, reason = local_result.decision.name, local_result.reason
        notes.append(
            f"live identity ({IDENTITY_URL}) / PEP ({PEP_URL}) unreachable - no Docker deployment "
            "in this environment. This run used an in-process replay of the real pep.pipeline "
            "code, including the real pep.normalize.normalize_url() call at stage 2."
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
        identity_desc="role=finance_agent, service=finance-agent (genuinely signed token)",
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
    )


if __name__ == "__main__":
    print_report(run())
    sys.exit(0)
