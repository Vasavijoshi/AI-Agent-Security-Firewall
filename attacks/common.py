"""Shared plumbing for the nine M3 attack demonstrations (attacks/a1.py .. a9.py).

Two things every script needs, factored out so each attack file stays focused on *what* it's
attacking rather than *how* to talk to the pipeline:

1. A way to route a request through the real enforcement code. Every script tries the real,
   live Docker deployment first (a genuine HTTP call to identity's /attest and the PEP's
   /v1/tool-call, over the actual container network) and only falls back to an in-process call
   into pep.pipeline.run_pipeline() when that's unreachable — which it will be in any environment
   without Docker running, this repo's own included (see AGENTFW_CONTEXT.md's standing caveat).
   The fallback still exercises the real pipeline code end to end, with a genuinely signed,
   genuinely verified token minted the same way tests/test_pipeline_m2.py already does — it is
   not a fake event dict and not a direct call into policy/engine.py bypassing identity/DLP/risk.
   It is labeled TEST_ONLY, never REAL_DOCKER_VERIFIED, and every script says so.

2. A uniform report format (AttackResult + print_report()) so run_all.py can build one summary
   table out of nine differently-shaped attacks without each one inventing its own printout.

# WHY the real event is built via pep.proxy._build_event(), not a hand-rolled dict: that function
# is the actual code that turns a PipelineResult into the JSON object written to the eventstore —
# reusing it means every attack's "resulting event" is the real artifact, conforming to
# events/schema.json, not a lookalike a reader would have to take on faith.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx

import pep.pipeline as pipeline
import pep.proxy as proxy
import pep.quarantine as quarantine
import risk.scorer as risk_scorer
from identity.tokens import generate_keypair, mint_token
from policy.engine import BLOCKED_DECISIONS

PEER_IP = "10.0.1.5"
CONTAINER_ID = "deadbeefcafe1234567890abcdef"

REAL_DOCKER_VERIFIED = "REAL_DOCKER_VERIFIED"
TEST_ONLY = "TEST_ONLY"
UNVERIFIED = "UNVERIFIED"

# WHY a short, fixed timeout: these are LAN calls to a container on the same compose network when
# they work at all — if the live stack isn't up, failing fast matters more than being patient.
_LIVE_TIMEOUT = 2.0


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

    @property
    def blocked(self) -> bool:
        return self.decision in {d.name for d in BLOCKED_DECISIONS}


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


def try_live_pep_call(
    *, pep_url: str, identity_url: str, tool: str, arguments: dict[str, Any], session_id: str
) -> dict[str, Any] | None:
    """Attempt the real path: attest against a live identity/issuer.py, then call the live PEP's
    /v1/tool-call, exactly as agent/tools.py's dispatch() does. Returns the PEP's JSON response, or
    None if the live stack isn't reachable — callers fall back to run_locally() in that case and
    must label the result TEST_ONLY, not REAL_DOCKER_VERIFIED. trust_env=False for the same reason
    agent/tools.py uses it: these calls target the PEP/identity directly, not through the
    bypass-catch proxy HTTP_PROXY points at."""
    try:
        with httpx.Client(trust_env=False, timeout=_LIVE_TIMEOUT) as client:
            attest_resp = client.post(f"{identity_url}/attest")
            attest_resp.raise_for_status()
            token = attest_resp.json()["token"]
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
            return call_resp.json()
    except httpx.HTTPError:
        return None


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
    for note in r.notes:
        print(f"note: {note}")
