"""Integration tests for pep/pipeline.py's real stages 1-7 — the pieces that only exist once the
pipeline is wired end-to-end (identity verification, taint state, DLP/risk narrowing an
otherwise-ALLOW policy verdict). Policy matching itself is covered by tests/test_policy_cases.py.

WHY tokens are minted directly with identity.tokens.mint_token() instead of going through a live
identity/issuer.py /attest call: the issuer's Docker-socket attestation can't run in a test
environment without a real Docker daemon (see AGENTFW_CONTEXT.md §2 and the M2 summary — this is
the same gap, not a new one). Minting directly exercises everything pep/pipeline.py actually does
with a token (signature check, expiry, container binding) without needing Docker to produce one.
"""

from __future__ import annotations

import pytest

import pep.pipeline as pipeline
import risk.scorer as risk_scorer
from identity.tokens import generate_keypair, mint_token
from policy.engine import Decision

CONTAINER_ID = "deadbeefcafe1234567890abcdef"
PEER_IP = "10.0.1.5"


@pytest.fixture(autouse=True)
def _reset_process_state():
    """Pipeline and risk-scorer behavioral state is process-lifetime, in-memory (documented in
    both modules). Tests must not leak taint/behavioral state into each other."""
    pipeline._SESSION_TAINT.clear()
    risk_scorer._SEEN_BY_AGENT.clear()
    risk_scorer._SEEN_BY_ORG.clear()
    risk_scorer._CALL_TIMES.clear()
    risk_scorer._LAST_TOOL.clear()
    risk_scorer._SEEN_BIGRAMS.clear()
    risk_scorer._DENIAL_STREAK.clear()
    yield


@pytest.fixture
def keypair():
    return generate_keypair()


@pytest.fixture(autouse=True)
def _install_issuer_key(keypair):
    _, public_key = keypair
    pipeline._ISSUER_PUBLIC_KEY = public_key
    yield
    pipeline._ISSUER_PUBLIC_KEY = None


def _token(keypair, role: str, ip: str = PEER_IP, **extra) -> str:
    private_key, _ = keypair
    claims = {
        "spiffe_id": f"spiffe://agentfw.internal/ns/{role}/agent/{CONTAINER_ID[:12]}",
        "role": role,
        "container_id": CONTAINER_ID,
        "image_digest": "sha256:deadbeef",
        "attested_ip": ip,
        **extra,
    }
    return mint_token(claims, private_key)


def test_valid_token_allowed_call(keypair):
    result = pipeline.run_pipeline(
        token=_token(keypair, "research_agent"),
        peer_ip=PEER_IP,
        session_id="s1",
        tool="http.get",
        arguments={"url": "https://api.trusted-news.com/x"},
    )
    assert result.decision in (Decision.ALLOW, Decision.RATE_LIMIT)  # policy said ALLOW either way
    assert result.policy_id == "R-RESEARCH-001"
    assert result.role == "research_agent"


def test_no_token_denied_at_identity_stage():
    result = pipeline.run_pipeline(
        token=None,
        peer_ip=PEER_IP,
        session_id="s1",
        tool="http.get",
        arguments={"url": "https://x"},
    )
    assert result.decision == Decision.DENY
    assert "identity_verification_failed" in result.reason
    assert result.role is None


def test_tampered_token_denied(keypair):
    bad = _token(keypair, "research_agent")[:-4] + "XXXX"
    result = pipeline.run_pipeline(
        token=bad, peer_ip=PEER_IP, session_id="s1", tool="http.get", arguments={"url": "https://x"}
    )
    assert result.decision == Decision.DENY
    assert "identity_verification_failed" in result.reason


def test_container_binding_mismatch_denied(keypair):
    """A token attested for one IP, presented from a different one, must fail — this is what
    stops a stolen token from being replayed off-box (AGENTFW_CONTEXT.md §2)."""
    token = _token(keypair, "research_agent", ip="10.0.1.99")
    result = pipeline.run_pipeline(
        token=token,
        peer_ip=PEER_IP,
        session_id="s1",
        tool="http.get",
        arguments={"url": "https://x"},
    )
    assert result.decision == Decision.DENY
    assert "container binding mismatch" in result.reason


def test_allowed_http_get_taints_the_session(keypair):
    """Taints on RATE_LIMIT too, not just a clean ALLOW: the very first call to any destination
    scores into the MODERATE risk band on novelty alone (see the cold-start test below) and
    narrows to RATE_LIMIT — the fetch still happens, so the session still has to become tainted."""
    assert pipeline._SESSION_TAINT.get("s1", False) is False
    result = pipeline.run_pipeline(
        token=_token(keypair, "research_agent"),
        peer_ip=PEER_IP,
        session_id="s1",
        tool="http.get",
        arguments={"url": "https://api.trusted-news.com/x"},
    )
    assert result.decision in pipeline.EXECUTABLE_DECISIONS
    assert pipeline._SESSION_TAINT["s1"] is True


def test_taint_is_monotonic_within_a_session(keypair):
    pipeline._SESSION_TAINT["s1"] = True
    pipeline.run_pipeline(
        token=_token(keypair, "research_agent"),
        peer_ip=PEER_IP,
        session_id="s1",
        tool="http.get",
        arguments={"url": "https://api.trusted-news.com/x"},
    )
    assert pipeline._SESSION_TAINT["s1"] is True  # never cleared, only ever set


def test_dlp_blocks_a_secret_even_though_policy_would_allow(keypair):
    """finance_agent's POST to the approved ERP is a policy ALLOW — DLP still has to catch a
    structured secret in the body and narrow it to DENY (AGENTFW_CONTEXT.md §2 stage 5)."""
    result = pipeline.run_pipeline(
        token=_token(keypair, "finance_agent"),
        peer_ip=PEER_IP,
        session_id="s2",
        tool="http.post",
        arguments={"url": "https://api.approved-erp.com/x", "body": "key=AKIAABCDEFGHIJKLMNOP"},
    )
    assert result.decision == Decision.DENY
    assert result.reason == "dlp_block"


def test_threat_intel_hit_is_recorded_even_when_policy_already_denies(keypair):
    result = pipeline.run_pipeline(
        token=_token(keypair, "research_agent"),
        peer_ip=PEER_IP,
        session_id="s3",
        tool="http.get",
        arguments={"url": "https://evil.example.com/x"},
    )
    assert result.decision == Decision.DENY  # DEFAULT_DENY — evil.example.com isn't allowlisted
    # WHY assert on risk_factors here rather than on the decision changing: policy already denies
    # this destination on its own, so a threat-intel hit can't narrow the verdict any further —
    # but stage 4 still has to run and stage 6 still has to record what it found.
    assert any(f["code"] == "THREAT_INTEL_HIT" for f in result.risk_factors)


def test_cold_start_destination_narrows_allow_to_rate_limit(keypair):
    """Documents real, intended behavior (not a bug): a brand-new destination for a brand-new
    deployment scores in the MODERATE risk band purely from novelty + data-class factors
    (AgentFW_Architecture_v1.md §8 bands), which narrows ALLOW to RATE_LIMIT on the very first
    call. The *second* call still scores an unseen-bigram factor — (http.get, http.get) is a
    transition that has only happened once so far, so it can't be "seen" until this call's own
    outcome is recorded — and only settles to a clean ALLOW from the third call on, once both the
    destination and the tool-chain bigram are warm."""
    calls = [
        pipeline.run_pipeline(
            token=_token(keypair, "research_agent"),
            peer_ip=PEER_IP,
            session_id=f"s{i}",
            tool="http.get",
            arguments={"url": "https://api.trusted-news.com/x"},
        )
        for i in range(3)
    ]
    assert calls[0].decision == Decision.RATE_LIMIT
    assert calls[0].reason == "risk_band_moderate"
    assert calls[2].decision == Decision.ALLOW
