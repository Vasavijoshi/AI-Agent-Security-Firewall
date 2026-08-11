"""Shared plumbing for the ten M3/C1-C2-fix attack demonstrations (attacks/a1.py .. a10.py).

Three things every script needs, factored out so each attack file stays focused on *what* it's
attacking rather than *how* to talk to the pipeline:

1. A way to route a request through the real enforcement code, AND to verify the identity that
   route actually used. Every script attempts the real, live Docker deployment first — a genuine
   HTTP call to identity's /attest, a genuine cryptographic verification of the returned token
   against the issuer's real /public-key, and only then the PEP's /v1/tool-call — and reports
   REAL_DOCKER_VERIFIED only when the attested role genuinely matches what the scenario requires
   (the C1 fix: docs/hostile-review.md). It falls back to an in-process call into
   pep.pipeline.run_pipeline() as supplementary, clearly-labeled evidence only, never counted
   toward verification_status — see try_live_pep_call_verified()'s docstring.

2. A way to grade the outcome against what the scenario is actually supposed to prove
   (assess_mechanism(), the C2 fix): being denied is not the same claim as being denied for the
   scenario's own intended reason. AGENT_QUARANTINED substituting for a scenario's real mechanism
   is a mismatch, not a pass — the same rule A10 exists to demonstrate on purpose.

3. A uniform report format (AttackResult + print_report() + emit_result_json()) so run_all.py can
   build one summary table out of ten differently-shaped attacks, whether run in-process or
   dispatched via `docker compose run` to the correct container, without each one inventing its
   own printout or parsing format.

# WHY the real event is built via pep.proxy._build_event(), not a hand-rolled dict: that function
# is the actual code that turns a PipelineResult into the JSON object written to the eventstore —
# reusing it means every attack's "resulting event" is the real artifact, conforming to
# events/schema.json, not a lookalike a reader would have to take on faith.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

import pep.pipeline as pipeline
import pep.proxy as proxy
import pep.quarantine as quarantine
import risk.scorer as risk_scorer
from identity.tokens import (
    TokenInvalidError,
    generate_keypair,
    mint_token,
    public_key_from_b64,
    verify_token,
)
from policy.engine import BLOCKED_DECISIONS

PEER_IP = "10.0.1.5"
CONTAINER_ID = "deadbeefcafe1234567890abcdef"

REAL_DOCKER_VERIFIED = "REAL_DOCKER_VERIFIED"
TEST_ONLY = "TEST_ONLY"
UNVERIFIED = "UNVERIFIED"

# WHY a short, fixed timeout: these are LAN calls to a container on the same compose network when
# they work at all — if the live stack isn't up, failing fast matters more than being patient.
_LIVE_TIMEOUT = 2.0

# compose service name a scenario actually needs to run inside to genuinely attest as that role —
# the C1 fix (docs/hostile-review.md): a role this table has no entry for (admin_agent) has no real
# deployed workload, on purpose (AGENTFW_CONTEXT.md's own scope) — that scenario's live path is
# structurally UNVERIFIED, not worked around by inventing a container for it.
ROLE_TO_SERVICE: dict[str, str] = {
    "research_agent": "agent",
    "finance_agent": "finance-agent",
    "support_agent": "support-agent",
}


@dataclass
class AttackResult:
    attack_id: str
    description: str
    category: str
    attempted: str
    identity_desc: str
    destination: str
    stage: str
    policy_id: str
    reason: str
    risk_score: int
    risk_factors: list[dict[str, Any]]
    decision: str
    event: dict[str, Any]
    verification_status: str
    notes: list[str] = field(default_factory=list)
    # WHY these three are separate from decision/reason, not folded in: decision/reason state what
    # actually happened; these three state what this scenario is *supposed* to prove, so a reader
    # (or run_all.py) can tell "denied" apart from "denied for the right reason" without re-deriving
    # policy/bundles/default.yaml by hand. mechanism_match is None when verification_status is
    # UNVERIFIED — there's no live outcome to grade against an expectation in that case.
    expected_decision: str | None = None
    expected_reason: str | None = None
    mechanism_match: bool | None = None

    @property
    def blocked(self) -> bool:
        return self.decision in {d.name for d in BLOCKED_DECISIONS}

    @property
    def genuinely_verified(self) -> bool:
        """True only when this attack reached a live, correctly-identified measurement AND that
        measurement showed the exact mechanism the scenario claims to demonstrate. Everything this
        milestone's C1/C2 fix cares about collapses into this one property: REAL_DOCKER_VERIFIED
        alone is not enough (that only means "we reached the real PEP as the right role") — a
        denial for the wrong reason (AGENT_QUARANTINED standing in for a specific policy/DLP/risk
        mechanism, or any other mismatch) must not count as this scenario's own proof."""
        return self.verification_status == REAL_DOCKER_VERIFIED and self.mechanism_match is True


@dataclass
class LiveCallOutcome:
    """Result of a role-verified attempt at the real live path (attest, verify the returned token
    against the issuer's real public key, check the claimed role, then call the real PEP) — see
    try_live_pep_call_verified()'s docstring for why every one of those steps is real, not a
    shortcut."""

    reachable: bool
    attested_role: str | None
    role_ok: bool
    decision: str | None = None
    reason: str | None = None
    result: Any = None
    latency_ms: dict[str, float] = field(default_factory=dict)
    error: str | None = None


def reset_process_state() -> None:
    """Clear the in-memory behavioral/session state pep/pipeline.py and risk/scorer.py keep
    per-process (documented in each module) between attack runs, so running all nine in one
    `run_all.py` process doesn't let one attack's novelty/rate history bleed into the next one's
    score — each attack should be judged on its own, same as a fresh container would see it."""
    pipeline._SESSION_TAINT.clear()
    risk_scorer._SEEN_BY_AGENT.clear()
    risk_scorer._SEEN_BY_ORG.clear()
    risk_scorer._CALL_TIMES.clear()
    risk_scorer._LAST_TOOL.clear()
    risk_scorer._SEEN_BIGRAMS.clear()
    risk_scorer._DENIAL_STREAK.clear()
    quarantine._DENIAL_TIMES.clear()


def mint_local_token(role: str, service: str, ip: str = PEER_IP, **extra_claims: Any) -> str:
    """Mint a genuinely valid Ed25519-signed token — correct signature, correct claim shape,
    correctly bound to `ip` — and install its public key so pep/pipeline.py's verify step accepts
    it. Same pattern tests/test_pipeline_m2.py and tests/test_east_west.py use, for the same
    reason: identity/issuer.py's real Docker-socket attestation can't run without a real Docker
    daemon, but everything pep/pipeline.py itself does with the resulting token — signature check,
    expiry, container binding — is exercised for real either way."""
    private_key, public_key = generate_keypair()
    pipeline._ISSUER_PUBLIC_KEY = public_key
    claims = {
        "spiffe_id": f"spiffe://agentfw.internal/ns/{role}/agent/{CONTAINER_ID[:12]}",
        "role": role,
        "container_id": CONTAINER_ID,
        "image_digest": "sha256:deadbeef",
        "service": service,
        "attested_ip": ip,
        **extra_claims,
    }
    return mint_token(claims, private_key)


def run_locally(
    *,
    role: str,
    service: str,
    tool: str,
    arguments: dict[str, Any],
    session_id: str,
    ip: str = PEER_IP,
    quarantine_calls: list[tuple[str, str]] | None = None,
) -> tuple[pipeline.PipelineResult, dict[str, Any]]:
    """Drive one call through the real pep.pipeline.run_pipeline(), in-process, with a genuine
    freshly-minted token. Quarantine's own network dependency (events/app.py) is stubbed to "not
    quarantined" / "no-op enter" — the same substitution tests/test_pipeline_m2.py makes — since
    there is no live eventstore to ask in this mode; every other stage (identity verification,
    normalization, policy, threat intel, DLP, risk, decision) runs unmodified.

    Returns (result, event) — event is the real artifact pep/proxy.py would have logged, built by
    the same _build_event() function, not a lookalike.

    If `quarantine_calls` is given, quarantine.enter() calls are recorded into it as
    (workload_key, reason) instead of being silently discarded — used by attacks that want to show
    quarantine's real automatic-entry side effect (pep/pipeline.py's CRITICAL-band / threat-intel
    / denial-streak triggers) without a live eventstore to persist against.

    WHY the patch is saved and restored in a finally block, not left in place: this module is
    imported by both standalone attack scripts (one call, process exits, no cleanup needed) and by
    pytest (tests/test_attacks.py, tests/test_eval_corpus.py), which shares one process across every
    test file. Reassigning quarantine.is_quarantined/enter without restoring them previously leaked
    into tests/test_quarantine.py, which runs later in the same session and needs the real,
    unpatched functions — a genuine regression, caught by running the full suite, not a
    hypothetical."""
    original_is_quarantined = quarantine.is_quarantined
    original_enter = quarantine.enter
    quarantine.is_quarantined = lambda _workload_key: False  # type: ignore[assignment]
    if quarantine_calls is not None:
        quarantine.enter = lambda workload_key, reason: quarantine_calls.append(  # type: ignore[assignment]
            (workload_key, reason)
        )
    else:
        quarantine.enter = lambda _workload_key, _reason: None  # type: ignore[assignment]

    try:
        token = mint_local_token(role, service, ip=ip)
        result = pipeline.run_pipeline(
            token=token, peer_ip=ip, session_id=session_id, tool=tool, arguments=arguments
        )
        req = proxy.ToolCallRequest(
            session_id=session_id, trace_id=f"attack-{session_id}", tool=tool, arguments=arguments
        )
        event = proxy._build_event(req, result)
        return result, event
    finally:
        quarantine.is_quarantined = original_is_quarantined
        quarantine.enter = original_enter


def attest_and_verify_role(*, identity_url: str) -> tuple[str | None, str | None, str | None]:
    """The real attestation path, exercised for real: POST /attest against the live issuer (role
    derived from Docker-socket lookup on whichever container's IP is actually calling — never a
    claim this code makes about itself), then GET /public-key and cryptographically verify the
    returned token with identity.tokens.verify_token — the same signature check pep/pipeline.py
    itself performs on every real request. This is what makes the returned role trustworthy enough
    to gate REAL_DOCKER_VERIFIED on: it is not read off an unverified JWT payload, and it is not
    asserted by this script — it is the issuer's own signed claim, checked against the issuer's own
    currently-published key.

    Returns (role, token, error). `role` is None if attestation itself failed or the token didn't
    verify — in both cases `error` explains why and the caller must not report REAL_DOCKER_VERIFIED.
    """
    try:
        with httpx.Client(trust_env=False, timeout=_LIVE_TIMEOUT) as client:
            attest_resp = client.post(f"{identity_url}/attest")
            attest_resp.raise_for_status()
            token = attest_resp.json()["token"]
            key_resp = client.get(f"{identity_url}/public-key")
            key_resp.raise_for_status()
            public_key = public_key_from_b64(key_resp.json()["public_key"])
    except httpx.HTTPError as exc:
        return None, None, f"identity issuer unreachable or refused attestation: {exc}"

    try:
        claims = verify_token(token, public_key)
    except TokenInvalidError as exc:
        return None, None, f"attested token failed real signature verification: {exc}"
    return claims["role"], token, None


def try_live_pep_call_verified(
    *,
    pep_url: str,
    identity_url: str,
    tool: str,
    arguments: dict[str, Any],
    session_id: str,
    expected_role: str,
) -> LiveCallOutcome:
    """The C1 fix: attempt the real live path AND verify the identity it actually attested as
    matches the role this scenario requires, before ever calling it REAL_DOCKER_VERIFIED.

    Three distinct outcomes, none of them silently collapsed into another:
      1. reachable=False — the issuer or PEP didn't answer at all (no Docker in this environment,
         or the stack isn't up). Caller reports UNVERIFIED.
      2. reachable=True, role_ok=False — the live stack IS up and DID answer, but the container this
         script is actually running in attested as a different role than the scenario needs (the
         exact C1 bug: a script invoked from the wrong container cannot make itself into a different
         identity by wanting to). Caller reports UNVERIFIED, never REAL_DOCKER_VERIFIED — this is
         the specific case the hostile review's C1 finding is about.
      3. reachable=True, role_ok=True — genuinely attested as the required role; decision/reason
         below came from the real /v1/tool-call response for that real identity.
    """
    role, token, attest_error = attest_and_verify_role(identity_url=identity_url)
    if role is None:
        return LiveCallOutcome(
            reachable=False, attested_role=None, role_ok=False, error=attest_error
        )
    if role != expected_role:
        return LiveCallOutcome(
            reachable=True,
            attested_role=role,
            role_ok=False,
            error=(
                f"this scenario requires role={expected_role!r}, but the calling container "
                f"genuinely attested as role={role!r} — this container is not the one this "
                "scenario needs (see ROLE_TO_SERVICE / run_all.py's dispatch table)"
            ),
        )

    try:
        with httpx.Client(trust_env=False, timeout=_LIVE_TIMEOUT) as client:
            call_resp = client.post(
                f"{pep_url}/v1/tool-call",
                json={
                    "session_id": session_id,
                    "trace_id": f"attack-{session_id}",
                    "tool": tool,
                    "arguments": arguments,
                },
                headers={"Authorization": f"Bearer {token}"},
            )
            call_resp.raise_for_status()
            body = call_resp.json()
    except httpx.HTTPError as exc:
        return LiveCallOutcome(
            reachable=False,
            attested_role=role,
            role_ok=True,
            error=f"real attestation succeeded (role={role!r}) but the PEP call failed: {exc}",
        )

    return LiveCallOutcome(
        reachable=True,
        attested_role=role,
        role_ok=True,
        decision=body["decision"],
        reason=body["reason"],
        result=body.get("result"),
        latency_ms=body.get("latency_ms", {}),
    )


def try_live_raw_connect(host: str, port: int, request_line: str) -> str | None:
    """Open a raw TCP connection and send one request line — used by A9 against the live PEP's
    :8081 bypass-catch listener. Returns the first response line, or None if unreachable."""
    import socket

    try:
        with socket.create_connection((host, port), timeout=_LIVE_TIMEOUT) as sock:
            sock.sendall((request_line + "\r\n\r\n").encode("latin-1"))
            sock.settimeout(_LIVE_TIMEOUT)
            data = sock.recv(256)
            return data.decode("latin-1", errors="replace").splitlines()[0] if data else None
    except OSError:
        return None


def timed(fn, *args: Any, **kwargs: Any) -> tuple[Any, float]:
    """Run fn and return (result, elapsed_ms) — used so latency numbers printed anywhere in the
    attack demos come from an actual measured call, never a made-up figure."""
    t0 = time.perf_counter()
    out = fn(*args, **kwargs)
    return out, (time.perf_counter() - t0) * 1000


def emit_result_json(r: AttackResult) -> None:
    """Print one machine-parseable line after the human-readable report — this is what
    run_all.py's host-side dispatcher (subprocess `docker compose run --rm <service> python -m
    attacks.aN`) parses out of captured stdout to build its summary table and assert each
    attack's mechanism, instead of scraping the pretty-printed report text."""
    payload = {
        "attack_id": r.attack_id,
        "category": r.category,
        "verification_status": r.verification_status,
        "decision": r.decision,
        "reason": r.reason,
        "policy_id": r.policy_id,
        "stage": r.stage,
        "expected_decision": r.expected_decision,
        "expected_reason": r.expected_reason,
        "mechanism_match": r.mechanism_match,
        "blocked": r.blocked,
        "genuinely_verified": r.genuinely_verified,
        "identity_desc": r.identity_desc,
        "attempted": r.attempted,
        "destination": r.destination,
        "risk_score": r.risk_score,
    }
    print(f"RESULT_JSON:{json.dumps(payload)}")


def mechanism_exit_code(r: AttackResult) -> int:
    """0 unless this attack reached a genuine, correctly-identified live measurement AND that
    measurement showed the wrong mechanism (mechanism_match is False, not None) — that specific
    case is the one this milestone's C1/C2 fix exists to catch loudly. UNVERIFIED alone (Docker
    not reachable, or the wrong container) is not itself a failure exit — that is the honest,
    expected result of running a role-specific script from the wrong place or with no Docker up."""
    if r.verification_status == REAL_DOCKER_VERIFIED and r.mechanism_match is False:
        return 1
    return 0


def assess_mechanism(
    result_decision: str, result_reason: str, expected_decision: str, expected_reason: str
) -> bool:
    """The C2 fix's core rule, in one place so every attack applies it identically: a denial is
    only a pass for THIS scenario if both the decision and the reason match what this scenario is
    specifically built to demonstrate. AGENT_QUARANTINED (or any other decision/reason this
    scenario didn't ask for) is a mismatch, full stop — being blocked is not the same claim as
    being blocked for the intended reason."""
    return result_decision == expected_decision and result_reason == expected_reason


def print_report(r: AttackResult) -> None:
    print(f"\n=== {r.attack_id}: {r.description} ===")
    print(f"category:            {r.category}")
    print(f"attempted:           {r.attempted}")
    print(f"identity:            {r.identity_desc}")
    print(f"destination/resource:{r.destination}")
    print(f"stopping stage:      {r.stage}")
    print(f"policy_id / reason:  {r.policy_id} / {r.reason}")
    print(f"risk_score:          {r.risk_score}")
    print("risk_factors:")
    if r.risk_factors:
        for f in r.risk_factors:
            print(f"  - {f['code']} (+{f['points']}): {f['human_reason']}")
    else:
        print("  (none)")
    print(f"decision:            {r.decision}")
    print(f"blocked:             {r.blocked}")
    print("event:")
    for key in (
        "trace_id",
        "agent_id",
        "role",
        "tool",
        "action",
        "destination",
        "resource",
        "decision",
        "reason",
        "policy_id",
    ):
        if key in r.event:
            print(f"  {key}: {r.event[key]}")
    print(f"verification_status: {r.verification_status}")
    if r.expected_decision is not None or r.expected_reason is not None:
        print(f"expected mechanism:  {r.expected_decision} / {r.expected_reason}")
        if r.mechanism_match is True:
            print("mechanism check:     MATCH — this scenario's own claimed mechanism was proven")
        elif r.mechanism_match is False:
            print("mechanism check:     *** MISMATCH ***")
            print(
                f"                     expected decision/reason = "
                f"{r.expected_decision}/{r.expected_reason}"
            )
            print(f"                     actual   decision/reason = {r.decision}/{r.reason}")
            print(
                "                     this attack does NOT count as demonstrating its own "
                "claimed mechanism — see docs/hostile-review.md C1/C2."
            )
    for note in r.notes:
        print(f"note: {note}")
