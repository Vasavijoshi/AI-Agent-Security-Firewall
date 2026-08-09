"""Tests for pep/quarantine.py and its wiring into pep/pipeline.py + pep/admin.py (pre-M3 ruling,
gap #3): entry triggers (risk CRITICAL, threat-intel hit, >=5 denials/60s), the absolute gate, and
manual-only release.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

import pep.admin as admin
import pep.pipeline as pipeline
import pep.quarantine as quarantine
import risk.scorer as risk_scorer
from identity.tokens import generate_keypair, mint_token
from policy.engine import Decision

CONTAINER_ID = "deadbeefcafe1234567890abcdef"
PEER_IP = "10.0.1.5"


def _reset_state():
    pipeline._SESSION_TAINT.clear()
    risk_scorer._SEEN_BY_AGENT.clear()
    risk_scorer._SEEN_BY_ORG.clear()
    risk_scorer._CALL_TIMES.clear()
    risk_scorer._LAST_TOOL.clear()
    risk_scorer._SEEN_BIGRAMS.clear()
    risk_scorer._DENIAL_STREAK.clear()
    quarantine._QUARANTINED.clear()
    quarantine._DENIAL_TIMES.clear()


def _token(keypair, role: str, service: str = "agent", ip: str = PEER_IP) -> str:
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
# pep/quarantine.py — unit-level
# =====================================================================================


def test_enter_and_release_round_trip():
    _reset_state()
    assert not quarantine.is_quarantined("agent")
    quarantine.enter("agent", "test reason")
    assert quarantine.is_quarantined("agent")
    assert quarantine.list_all() == {"agent": "test reason"}
    assert quarantine.release("agent") is True
    assert not quarantine.is_quarantined("agent")


def test_release_on_a_non_quarantined_agent_returns_false():
    _reset_state()
    assert quarantine.release("nobody") is False


def test_enter_is_idempotent_keeps_original_reason():
    _reset_state()
    quarantine.enter("agent", "first reason")
    quarantine.enter("agent", "second reason")
    assert quarantine.list_all() == {"agent": "first reason"}


def test_record_denial_crosses_threshold_at_five_within_the_window():
    _reset_state()
    for _ in range(4):
        assert quarantine.record_denial("agent") is False
    assert quarantine.record_denial("agent") is True


# =====================================================================================
# Wired into pep/pipeline.py
# =====================================================================================


def test_threat_intel_hit_triggers_quarantine_and_blocks_the_next_call():
    _reset_state()
    keypair = generate_keypair()
    pipeline._ISSUER_PUBLIC_KEY = keypair[1]
    token = _token(keypair, "research_agent")

    first = pipeline.run_pipeline(
        token=token,
        peer_ip=PEER_IP,
        session_id="s1",
        tool="http.get",
        arguments={"url": "https://evil.example.com/x"},
    )
    assert first.decision == Decision.DENY  # denied on its own merits (default-deny)
    assert quarantine.is_quarantined("agent")

    second = pipeline.run_pipeline(
        token=token,
        peer_ip=PEER_IP,
        session_id="s2",
        tool="http.get",
        arguments={"url": "https://api.trusted-news.com/x"},  # otherwise a fine request
    )
    assert second.decision == Decision.DENY
    assert second.reason == "AGENT_QUARANTINED"
    assert second.policy_id == "QUARANTINE_DENY"
    pipeline._ISSUER_PUBLIC_KEY = None


def test_risk_critical_band_triggers_quarantine(monkeypatch):
    """Isolated from the other two triggers deliberately: stacking real factors to 75+ without
    also incidentally causing a threat-intel hit is fragile to construct and fragile to keep
    passing as risk/scorer.py's factor weights evolve. Forcing the score directly tests exactly
    the trigger condition (risk_result.band == "CRITICAL") pep/pipeline.py checks."""
    _reset_state()
    keypair = generate_keypair()
    pipeline._ISSUER_PUBLIC_KEY = keypair[1]
    token = _token(keypair, "research_agent")

    def _fake_score(**_kwargs):
        return risk_scorer.ScoreResult(
            score=90,
            band="CRITICAL",
            factors=[risk_scorer.Factor("TEST_FORCED", 90, "forced for test")],
            decision_ceiling=Decision.QUARANTINE,
        )

    monkeypatch.setattr(pipeline.risk, "score", _fake_score)

    pipeline.run_pipeline(
        token=token,
        peer_ip=PEER_IP,
        session_id="s1",
        tool="http.get",
        arguments={"url": "https://api.trusted-news.com/x"},
    )
    assert quarantine.is_quarantined("agent")
    assert quarantine.list_all()["agent"] == "risk score reached CRITICAL band"
    pipeline._ISSUER_PUBLIC_KEY = None


def test_five_denials_in_60s_triggers_quarantine():
    _reset_state()
    keypair = generate_keypair()
    pipeline._ISSUER_PUBLIC_KEY = keypair[1]
    token = _token(keypair, "research_agent")

    # research_agent has no db.query charter at all (R-RESEARCH-002) — five clean policy denials,
    # none of them a threat-intel hit or a CRITICAL risk score on their own.
    for i in range(5):
        result = pipeline.run_pipeline(
            token=token,
            peer_ip=PEER_IP,
            session_id=f"s{i}",
            tool="db.query",
            arguments={"table": "customers"},
        )
        assert result.decision == Decision.DENY

    assert quarantine.is_quarantined("agent")

    blocked = pipeline.run_pipeline(
        token=token,
        peer_ip=PEER_IP,
        session_id="s-next",
        tool="http.get",
        arguments={"url": "https://api.trusted-news.com/x"},
    )
    assert blocked.reason == "AGENT_QUARANTINED"
    pipeline._ISSUER_PUBLIC_KEY = None


def test_quarantine_applies_regardless_of_policy():
    """ "Regardless of policy" is the whole point — even a request that would otherwise be a clean
    ALLOW must be denied once the agent is quarantined."""
    _reset_state()
    keypair = generate_keypair()
    pipeline._ISSUER_PUBLIC_KEY = keypair[1]
    token = _token(keypair, "research_agent")
    quarantine.enter("agent", "manually quarantined for this test")

    result = pipeline.run_pipeline(
        token=token,
        peer_ip=PEER_IP,
        session_id="s1",
        tool="http.get",
        arguments={"url": "https://api.trusted-news.com/x"},  # normally a clean ALLOW
    )
    assert result.decision == Decision.DENY
    assert result.reason == "AGENT_QUARANTINED"
    pipeline._ISSUER_PUBLIC_KEY = None


def test_release_restores_normal_service():
    _reset_state()
    keypair = generate_keypair()
    pipeline._ISSUER_PUBLIC_KEY = keypair[1]
    token = _token(keypair, "research_agent")
    quarantine.enter("agent", "test")

    denied = pipeline.run_pipeline(
        token=token,
        peer_ip=PEER_IP,
        session_id="s1",
        tool="http.get",
        arguments={"url": "https://api.trusted-news.com/x"},
    )
    assert denied.reason == "AGENT_QUARANTINED"

    assert quarantine.release("agent") is True

    allowed = pipeline.run_pipeline(
        token=token,
        peer_ip=PEER_IP,
        session_id="s2",
        tool="http.get",
        arguments={"url": "https://api.trusted-news.com/x"},
    )
    assert allowed.reason != "AGENT_QUARANTINED"
    pipeline._ISSUER_PUBLIC_KEY = None


# =====================================================================================
# pep/admin.py — the manual-only release surface
# =====================================================================================


def test_admin_app_lists_and_releases():
    _reset_state()
    quarantine.enter("agent", "test reason")

    client = TestClient(admin.admin_app)
    listed = client.get("/admin/quarantine").json()
    assert listed == {"agent": "test reason"}

    response = client.post("/admin/quarantine/agent/release")
    assert response.status_code == 200
    assert not quarantine.is_quarantined("agent")


def test_admin_release_on_unknown_agent_is_404():
    _reset_state()
    client = TestClient(admin.admin_app)
    response = client.post("/admin/quarantine/nobody/release")
    assert response.status_code == 404


def test_admin_routes_are_not_reachable_via_the_main_pep_app():
    """The security property this whole feature depends on: a quarantined (possibly compromised)
    agent can reach the main PEP app over agent-net, so the release endpoint must not exist there
    at all — only on the separate, loopback-bound admin_app (pep/proxy.py's lifespan)."""
    import pep.proxy as proxy

    main_app_paths = {route.path for route in proxy.app.routes}
    assert not any(path.startswith("/admin") for path in main_app_paths)
