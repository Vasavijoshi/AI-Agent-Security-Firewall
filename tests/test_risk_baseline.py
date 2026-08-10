"""Tests for the pre-M3 risk baseline seeding: risk/baseline.jsonl + RiskScorer.warm_up()."""

from __future__ import annotations

import json

import pytest

import pep.pipeline as pipeline
import pep.quarantine as quarantine
import risk.scorer as risk_scorer
from identity.tokens import generate_keypair, mint_token
from risk.scorer import RiskScorer


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch):
    risk_scorer._SEEN_BY_AGENT.clear()
    risk_scorer._SEEN_BY_ORG.clear()
    risk_scorer._CALL_TIMES.clear()
    risk_scorer._LAST_TOOL.clear()
    risk_scorer._SEEN_BIGRAMS.clear()
    risk_scorer._DENIAL_STREAK.clear()
    pipeline._SESSION_TAINT.clear()
    quarantine._DENIAL_TIMES.clear()
    # Quarantine membership is eventstore-persisted (pre-M3 ruling, round 3); this sandbox has no
    # live instance. Stubbed to "nobody is quarantined" — only one test in this file drives the
    # real pipeline, and it isn't testing quarantine behavior.
    monkeypatch.setattr(quarantine, "is_quarantined", lambda _workload_key: False)
    monkeypatch.setattr(quarantine, "enter", lambda _workload_key, _reason: None)


def test_warm_up_replays_the_real_baseline_file():
    count = RiskScorer.warm_up()
    assert count == 200
    assert "api.trusted-news.com" in risk_scorer._SEEN_BY_ORG


def test_warm_up_suppresses_dest_unknown_to_org_for_a_seeded_destination():
    RiskScorer.warm_up()
    result = risk_scorer.score(
        agent_id="brand-new-agent-id",
        role="research_agent",
        tool="http.get",
        destination_key="api.trusted-news.com",
        action="read",
        data_class="internal",
        session_taint="clean",
        threat_intel_hit=False,
    )
    codes = {f.code for f in result.factors}
    assert "DEST_UNKNOWN_TO_ORG" not in codes
    # WHY DEST_NEVER_SEEN_BY_AGENT is still expected here specifically: "brand-new-agent-id" has no
    # entry in identity/issuer.py's AGENT_REGISTRY and never will — it's not a stable workload key
    # anything could have pre-seeded. A genuinely unregistered identity still pays this (smaller)
    # penalty on its first call, which is correct. A *registered* agent's own stable key (the
    # "agent" service, in this project) gets full per-agent seeding — see the two tests below.
    assert "DEST_NEVER_SEEN_BY_AGENT" in codes


def test_warm_up_seeds_per_agent_destination_for_the_registered_agent():
    """risk/baseline.jsonl carries "agent_id": "agent" on its research_agent lines — the one role
    with a real AGENT_REGISTRY entry — so RiskScorer.warm_up() must populate _SEEN_BY_AGENT["agent"]
    directly, not just _SEEN_BY_ORG."""
    RiskScorer.warm_up()
    assert "api.trusted-news.com" in risk_scorer._SEEN_BY_AGENT.get("agent", set())

    result = risk_scorer.score(
        agent_id="agent",
        role="research_agent",
        tool="http.get",
        destination_key="api.trusted-news.com",
        action="read",
        data_class="internal",
        session_taint="clean",
        threat_intel_hit=False,
    )
    codes = {f.code for f in result.factors}
    assert "DEST_UNKNOWN_TO_ORG" not in codes
    assert "DEST_NEVER_SEEN_BY_AGENT" not in codes


def test_warm_up_seeds_all_three_registered_multi_agent_workloads():
    """Pre-M3 multi-agent ruling: finance-agent and support-agent are now real registered
    services too (identity/issuer.py's AGENT_REGISTRY), so their baseline lines carry agent_id
    the same way research_agent's always have. admin_agent still has no deployed service."""
    RiskScorer.warm_up()
    assert "api.approved-erp.com" in risk_scorer._SEEN_BY_AGENT.get(
        "finance-agent", set()
    ) or "ledger" in risk_scorer._SEEN_BY_AGENT.get("finance-agent", set())
    assert risk_scorer._SEEN_BY_AGENT.get("support-agent")
    assert "admin-agent" not in risk_scorer._SEEN_BY_AGENT


def test_registered_agents_first_live_call_does_not_fire_dest_never_seen_by_agent():
    """End-to-end through the real pipeline (AGENTFW_CONTEXT.md pre-M3 ruling, gap #2): a token
    minted with the "agent" service claim — exactly what identity/issuer.py would mint for the one
    real registered agent — must not pay DEST_NEVER_SEEN_BY_AGENT on a baseline-seeded destination,
    even on its very first call after a fresh process start (simulated here by resetting all
    state, then warming up, then making exactly one call)."""
    RiskScorer.warm_up()

    private_key, public_key = generate_keypair()
    pipeline._ISSUER_PUBLIC_KEY = public_key
    token = mint_token(
        {
            "spiffe_id": "spiffe://agentfw.internal/ns/research_agent/agent/deadbeefcafe1",
            "role": "research_agent",
            "container_id": "deadbeefcafe1234567890abcdef",
            "image_digest": "sha256:deadbeef",
            "service": "agent",
            "attested_ip": "10.0.1.5",
        },
        private_key,
    )

    result = pipeline.run_pipeline(
        token=token,
        peer_ip="10.0.1.5",
        session_id="s1",
        tool="http.get",
        arguments={"url": "https://api.trusted-news.com/x"},
    )
    codes = {f["code"] for f in result.risk_factors}
    assert "DEST_NEVER_SEEN_BY_AGENT" not in codes
    assert "DEST_UNKNOWN_TO_ORG" not in codes
    pipeline._ISSUER_PUBLIC_KEY = None


def test_warm_up_suppresses_unseen_bigram_for_a_seeded_role_sequence(tmp_path):
    baseline = tmp_path / "mini_baseline.jsonl"
    baseline.write_text(
        "\n".join(
            json.dumps(e)
            for e in [
                {"role": "research_agent", "tool": "http.get", "destination_key": "a.example.com"},
                {"role": "research_agent", "tool": "http.get", "destination_key": "b.example.com"},
            ]
        ),
        encoding="utf-8",
    )
    count = RiskScorer.warm_up(str(baseline))
    assert count == 2

    result = risk_scorer.score(
        agent_id="brand-new-agent-id",
        role="research_agent",
        tool="http.get",
        destination_key="c.example.com",
        action="read",
        data_class="internal",
        session_taint="clean",
        threat_intel_hit=False,
    )
    assert "UNSEEN_BIGRAM" not in {f.code for f in result.factors}


def test_warm_up_does_not_populate_the_rate_window():
    """Replaying ~200 historical events must not look like 200 calls in the last 60 seconds —
    that would manufacture a false RATE_ANOMALY for every role immediately after startup, which
    is exactly the friction this seeding exists to avoid, not create."""
    RiskScorer.warm_up()
    assert risk_scorer._CALL_TIMES == {}


def test_baseline_file_has_no_denied_or_attack_shaped_entries():
    """Every baseline event must be plain ALLOW-shaped traffic for its own role, per
    policy/bundles/default.yaml — a baseline that quietly included attack traffic would corrupt
    exactly the signal it's supposed to protect."""
    from policy.engine import evaluate, load_bundle

    bundle = load_bundle("policy/bundles/default.yaml")
    with open("risk/baseline.jsonl", encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]

    assert len(events) == 200
    for event in events:
        fqdn = event["destination_key"] if event["tool"].startswith("http.") else None
        resource = event["destination_key"] if not event["tool"].startswith("http.") else None
        result = evaluate(
            bundle,
            role=event["role"],
            tool=event["tool"],
            fqdn=fqdn,
            resource=resource,
            session_taint="clean",
        )
        assert result.decision.name == "ALLOW", (event, result.reason)
