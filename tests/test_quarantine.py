"""Tests for pep/quarantine.py (now eventstore-persisted — pre-M3 ruling, round 3) and its wiring
into pep/pipeline.py: entry triggers (risk CRITICAL, threat-intel hit, >=5 denials/60s), the
absolute gate, persistence across a simulated PEP restart, and fail-safe behavior when the
eventstore itself is unreachable.
"""

from __future__ import annotations

import httpx
import pytest

import events.store as event_store
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


class _FakeResponse:
    def __init__(self, status_code: int, json_data):
        self.status_code = status_code
        self._json = json_data

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=None, response=self)  # type: ignore[arg-type]


@pytest.fixture
def fake_eventstore(monkeypatch, tmp_path):
    """Substitutes only the network boundary — GET/POST/DELETE against pep/quarantine.py's own
    httpx calls dispatch straight to events/store.py's real SQLite functions on a scratch file.
    This exercises the real persistence layer (not a test double standing in for it) without
    needing a live eventstore process."""
    db_path = str(tmp_path / "events.db")

    def fake_get(url, timeout=None):
        assert url.endswith("/quarantine")
        return _FakeResponse(200, event_store.quarantine_list(db_path))

    def fake_post(url, json=None, timeout=None):
        agent_id = url.rsplit("/", 1)[-1]
        event_store.quarantine_enter(agent_id, json["reason"], "2026-01-01T00:00:00Z", db_path)
        return _FakeResponse(200, {"status": "entered"})

    def fake_delete(url, timeout=None):
        agent_id = url.rsplit("/", 1)[-1]
        released = event_store.quarantine_release(agent_id, db_path)
        return _FakeResponse(200 if released else 404, {})

    monkeypatch.setattr(quarantine.httpx, "get", fake_get)
    monkeypatch.setattr(quarantine.httpx, "post", fake_post)
    monkeypatch.setattr(quarantine.httpx, "delete", fake_delete)
    return db_path


# =====================================================================================
# pep/quarantine.py — unit-level, against the fake eventstore
# =====================================================================================


def test_enter_and_release_round_trip(fake_eventstore):
    _reset_state()
    assert not quarantine.is_quarantined("agent")
    quarantine.enter("agent", "test reason")
    assert quarantine.is_quarantined("agent")
    assert quarantine.list_all() == {"agent": "test reason"}
    assert quarantine.release("agent") is True
    assert not quarantine.is_quarantined("agent")


def test_release_on_a_non_quarantined_agent_returns_false(fake_eventstore):
    _reset_state()
    assert quarantine.release("nobody") is False


def test_enter_is_idempotent_keeps_original_reason(fake_eventstore):
    _reset_state()
    quarantine.enter("agent", "first reason")
    quarantine.enter("agent", "second reason")
    assert quarantine.list_all() == {"agent": "first reason"}


def test_record_denial_crosses_threshold_at_five_within_the_window():
    _reset_state()
    for _ in range(4):
        assert quarantine.record_denial("agent") is False
    assert quarantine.record_denial("agent") is True


def test_quarantine_survives_a_simulated_pep_restart(fake_eventstore):
    """The item-4 property, made concrete: quarantine membership lives in events/store.py's SQLite
    file, not in any PEP-process-local variable. "Restarting the PEP" is simulated here by
    clearing every other module-level cache this test suite knows about and re-checking — there is
    deliberately no `_QUARANTINED` dict left to clear, because there's nothing left that a restart
    could lose."""
    quarantine.enter("agent", "risk score reached CRITICAL band")
    assert quarantine.is_quarantined("agent")

    _reset_state()  # simulates process restart: clears every other piece of in-memory state
    assert quarantine.is_quarantined("agent"), "quarantine did not survive the simulated restart"


def test_is_quarantined_fails_safe_when_the_eventstore_is_unreachable(monkeypatch):
    def _boom(*_args, **_kwargs):
        raise httpx.HTTPError("simulated eventstore outage")

    monkeypatch.setattr(quarantine.httpx, "get", _boom)
    with pytest.raises(quarantine.QuarantineCheckUnavailable):
        quarantine.is_quarantined("agent")


# =====================================================================================
# Wired into pep/pipeline.py
# =====================================================================================


def test_threat_intel_hit_triggers_quarantine_and_blocks_the_next_call(fake_eventstore):
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


def test_risk_critical_band_triggers_quarantine(monkeypatch, fake_eventstore):
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


def test_five_denials_in_60s_triggers_quarantine(fake_eventstore):
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


def test_quarantine_applies_regardless_of_policy(fake_eventstore):
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


def test_release_restores_normal_service(fake_eventstore):
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


def test_pipeline_denies_with_a_distinct_reason_when_the_eventstore_is_unreachable(monkeypatch):
    """The quarantine gate's own fail-safe path must be distinguishable in the event log from a
    real AGENT_QUARANTINED verdict — see QuarantineCheckUnavailable's docstring."""
    _reset_state()
    keypair = generate_keypair()
    pipeline._ISSUER_PUBLIC_KEY = keypair[1]
    token = _token(keypair, "research_agent")

    def _boom(*_args, **_kwargs):
        raise httpx.HTTPError("simulated eventstore outage")

    monkeypatch.setattr(quarantine.httpx, "get", _boom)

    result = pipeline.run_pipeline(
        token=token,
        peer_ip=PEER_IP,
        session_id="s1",
        tool="http.get",
        arguments={"url": "https://api.trusted-news.com/x"},
    )
    assert result.decision == Decision.DENY
    assert result.reason == "quarantine_check_unavailable"
    assert result.reason != "AGENT_QUARANTINED"
    pipeline._ISSUER_PUBLIC_KEY = None
