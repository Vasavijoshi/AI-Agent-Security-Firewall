"""Tests for the pre-M3 multi-agent ruling: east-west policy (policy/engine.py's
evaluate_east_west()) and its wiring into pep/pipeline.py via the "agent.invoke" tool.

The headline property: a valid credential for the wrong identity is still a denial. research_agent
presenting its own genuinely-issued, correctly-signed, correctly-bound token still cannot reach
finance_agent — not because the token is bad, but because nothing in the bundle says it may.
"""

from __future__ import annotations

import pytest

import pep.pipeline as pipeline
import pep.quarantine as quarantine
import risk.scorer as risk_scorer
from identity.tokens import generate_keypair, mint_token
from policy.engine import Decision, evaluate_east_west, load_bundle

TEST_BUNDLE = load_bundle("policy/bundles/default.yaml")
CONTAINER_ID = "deadbeefcafe1234567890abcdef"
PEER_IP = "10.0.1.5"


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch):
    pipeline._SESSION_TAINT.clear()
    risk_scorer._SEEN_BY_AGENT.clear()
    risk_scorer._SEEN_BY_ORG.clear()
    risk_scorer._CALL_TIMES.clear()
    risk_scorer._LAST_TOOL.clear()
    risk_scorer._SEEN_BIGRAMS.clear()
    risk_scorer._DENIAL_STREAK.clear()
    quarantine._DENIAL_TIMES.clear()
    monkeypatch.setattr(quarantine, "is_quarantined", lambda _workload_key: False)
    monkeypatch.setattr(quarantine, "enter", lambda _workload_key, _reason: None)


def _token(keypair, role: str, service: str, ip: str = PEER_IP) -> str:
    private_key, _ = keypair
    return mint_token(
        {
            "spiffe_id": f"spiffe://agentfw.internal/ns/{role}/agent/{CONTAINER_ID[:12]}",
            "role": role,
            "container_id": CONTAINER_ID,
            "image_digest": "sha256:deadbeef",
            "service": service,
            "attested_ip": ip,
        },
        private_key,
    )


# =====================================================================================
# policy/engine.py — unit-level
# =====================================================================================


def test_default_bundle_has_no_east_west_allow_rules():
    """The bundle's own charter: nobody is allowed to invoke anybody, by design (see
    policy/bundles/default.yaml's WHY on its empty east_west_rules list)."""
    assert TEST_BUNDLE.east_west_rules == ()


def test_east_west_defaults_to_deny_with_no_rules():
    result = evaluate_east_west(
        TEST_BUNDLE, source_workload="agent", dest_workload="finance-agent", action="invoke"
    )
    assert result.decision == Decision.DENY
    assert result.policy_id == "DEFAULT_DENY_EAST_WEST"
    assert result.reason == "no_matching_east_west_rule"


def test_east_west_explicit_deny_beats_explicit_allow(monkeypatch):
    from dataclasses import replace

    from policy.engine import EastWestRule

    bundle = replace(
        TEST_BUNDLE,
        east_west_rules=(
            EastWestRule("EW-ALLOW", 100, "agent", "finance-agent", "invoke", Decision.ALLOW),
            EastWestRule("EW-DENY", 50, "agent", "finance-agent", "invoke", Decision.DENY),
        ),
    )
    result = evaluate_east_west(
        bundle, source_workload="agent", dest_workload="finance-agent", action="invoke"
    )
    assert result.decision == Decision.DENY
    assert result.policy_id == "EW-DENY"


def test_east_west_wildcard_source_matches_any_caller():
    from dataclasses import replace

    from policy.engine import EastWestRule

    bundle = replace(
        TEST_BUNDLE,
        east_west_rules=(
            EastWestRule("EW-1", 100, "*", "finance-agent", "invoke", Decision.ALLOW),
        ),
    )
    result = evaluate_east_west(
        bundle, source_workload="literally-anything", dest_workload="finance-agent", action="invoke"
    )
    assert result.decision == Decision.ALLOW
    assert result.policy_id == "EW-1"


# =====================================================================================
# Wired into pep/pipeline.py, through the real pipeline with real tokens
# =====================================================================================


def test_research_agents_own_valid_token_cannot_invoke_finance_agent():
    """The exact scenario asked for. research_agent's token is genuinely valid — correct
    signature, not expired, correct container binding, minted by the real attestation flow's
    claim shape — and the call is still denied, because no east-west rule grants it."""
    keypair = generate_keypair()
    pipeline._ISSUER_PUBLIC_KEY = keypair[1]
    token = _token(keypair, "research_agent", service="agent")

    result = pipeline.run_pipeline(
        token=token,
        peer_ip=PEER_IP,
        session_id="s1",
        tool="agent.invoke",
        arguments={
            "target_service": "finance-agent",
            "tool": "db.query",
            "arguments": {"table": "ledger"},
        },
    )
    assert result.decision == Decision.DENY
    assert result.policy_id == "DEFAULT_DENY_EAST_WEST"
    assert result.reason == "no_matching_east_west_rule"
    pipeline._ISSUER_PUBLIC_KEY = None


def test_finance_agent_also_cannot_invoke_research_agent():
    """Not a one-directional fluke — the same default-deny applies regardless of which real,
    registered workload is asking."""
    keypair = generate_keypair()
    pipeline._ISSUER_PUBLIC_KEY = keypair[1]
    token = _token(keypair, "finance_agent", service="finance-agent")

    result = pipeline.run_pipeline(
        token=token,
        peer_ip=PEER_IP,
        session_id="s1",
        tool="agent.invoke",
        arguments={
            "target_service": "agent",
            "tool": "http.get",
            "arguments": {"url": "https://api.trusted-news.com/x"},
        },
    )
    assert result.decision == Decision.DENY
    assert result.policy_id == "DEFAULT_DENY_EAST_WEST"
    pipeline._ISSUER_PUBLIC_KEY = None


def test_unregistered_agent_id_still_denied_not_a_type_error():
    """A target_service that isn't even a real registered workload must still resolve to a normal
    denial, not a crash — east-west matching is string comparison, not a registry lookup."""
    keypair = generate_keypair()
    pipeline._ISSUER_PUBLIC_KEY = keypair[1]
    token = _token(keypair, "research_agent", service="agent")

    result = pipeline.run_pipeline(
        token=token,
        peer_ip=PEER_IP,
        session_id="s1",
        tool="agent.invoke",
        arguments={"target_service": "nonexistent-agent", "tool": "http.get", "arguments": {}},
    )
    assert result.decision == Decision.DENY
    pipeline._ISSUER_PUBLIC_KEY = None


# =====================================================================================
# DLP must cover agent.invoke's nested arguments (pre-M3 round-4 ruling)
# =====================================================================================


def test_agent_invoke_nested_arguments_are_dlp_scanned(monkeypatch):
    """The default bundle default-denies every east-west call, so DLP never gets a chance to run
    against one in the deployed configuration — this test grants a temporary ALLOW specifically to
    prove stage 5 itself covers agent.invoke's nested payload, not just that stage 3 blocks it."""
    from dataclasses import replace

    from policy.engine import EastWestRule

    permissive_bundle = replace(
        pipeline.BUNDLE,
        east_west_rules=(
            EastWestRule("EW-TEST-ALLOW", 100, "agent", "finance-agent", "invoke", Decision.ALLOW),
        ),
    )
    monkeypatch.setattr(pipeline, "BUNDLE", permissive_bundle)

    keypair = generate_keypair()
    pipeline._ISSUER_PUBLIC_KEY = keypair[1]
    token = _token(keypair, "research_agent", service="agent")

    result = pipeline.run_pipeline(
        token=token,
        peer_ip=PEER_IP,
        session_id="s1",
        tool="agent.invoke",
        arguments={
            "target_service": "finance-agent",
            "tool": "db.query",
            # WHY this specific value: AKIA + 16 chars is DLP's highest-precision, deterministic
            # BLOCK trigger (dlp/detectors.py's AWS_ACCESS_KEY_ID regex) — no Luhn/entropy
            # randomness to keep the test stable.
            "arguments": {"table": "ledger", "filter": "key=AKIAABCDEFGHIJKLMNOP"},
        },
    )
    # East-west policy alone would ALLOW this call — DLP is what has to catch the exfiltration
    # attempt riding inside it, and DENY wins the final min() over the lattice.
    assert result.decision == Decision.DENY
    assert result.reason == "dlp_block"
    pipeline._ISSUER_PUBLIC_KEY = None


def test_agent_invoke_without_a_secret_is_unaffected_by_the_dlp_change(monkeypatch):
    from dataclasses import replace

    from policy.engine import EastWestRule

    permissive_bundle = replace(
        pipeline.BUNDLE,
        east_west_rules=(
            EastWestRule("EW-TEST-ALLOW", 100, "agent", "finance-agent", "invoke", Decision.ALLOW),
        ),
    )
    monkeypatch.setattr(pipeline, "BUNDLE", permissive_bundle)

    keypair = generate_keypair()
    pipeline._ISSUER_PUBLIC_KEY = keypair[1]
    token = _token(keypair, "research_agent", service="agent")

    result = pipeline.run_pipeline(
        token=token,
        peer_ip=PEER_IP,
        session_id="s1",
        tool="agent.invoke",
        arguments={
            "target_service": "finance-agent",
            "tool": "db.query",
            "arguments": {"table": "ledger"},
        },
    )
    assert result.decision == Decision.ALLOW
    pipeline._ISSUER_PUBLIC_KEY = None
