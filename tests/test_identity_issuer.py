"""Tests for identity/issuer.py's attestation hardening: the Docker-reported image digest must
match, not just the compose service label (a label is attacker-settable via `docker run --label`;
forging a digest requires producing that image) — and, since the pre-M3 round-4 ruling,
trust-on-first-use pinning: unset EXPECTED_DIGEST_* is no longer an unpinned escape hatch, it just
means the first successful attestation pins whatever digest it observes instead of a pre-seeded one.
"""

from __future__ import annotations

import json
import logging

import pytest
from fastapi.testclient import TestClient

import identity.issuer as issuer
import identity.store as identity_store


def _fake_lookup(service: str, image_digest: str, container_id: str = "deadbeefcafe1234567890"):
    async def _lookup(_source_ip: str):
        return {"container_id": container_id, "image_digest": image_digest, "service": service}

    return _lookup


@pytest.fixture
def fake_pin_store(monkeypatch, tmp_path):
    """Points identity/issuer.py's IDENTITY_DB_PATH at a scratch SQLite file instead of the real
    volume-mounted path — identity/issuer.py's own _get_or_set_pin() is exercised unchanged, since
    (post pre-M3 round 5) it's a local, synchronous call into identity/store.py, not a network
    call to fake out."""
    db_path = str(tmp_path / "identity.db")
    monkeypatch.setattr(issuer, "IDENTITY_DB_PATH", db_path)
    return db_path


def _unseeded(role: str) -> issuer.RegisteredAgent:
    return issuer.RegisteredAgent(role=role, image_digest="")


# =====================================================================================
# Trust-on-first-use: no pre-seed
# =====================================================================================


def test_first_attestation_pins_whatever_digest_it_observes(monkeypatch, fake_pin_store):
    monkeypatch.setitem(issuer.AGENT_REGISTRY, "agent", _unseeded("research_agent"))
    monkeypatch.setattr(
        issuer, "_lookup_caller_container", _fake_lookup("agent", "sha256:first-boot")
    )

    client = TestClient(issuer.app)
    response = client.post("/attest")
    assert response.status_code == 200
    assert identity_store.list_all(fake_pin_store) == {"agent": "sha256:first-boot"}


def test_second_attestation_with_the_same_digest_succeeds(monkeypatch, fake_pin_store):
    monkeypatch.setitem(issuer.AGENT_REGISTRY, "agent", _unseeded("research_agent"))
    monkeypatch.setattr(
        issuer, "_lookup_caller_container", _fake_lookup("agent", "sha256:first-boot")
    )
    client = TestClient(issuer.app)
    assert client.post("/attest").status_code == 200
    assert client.post("/attest").status_code == 200


def test_second_attestation_with_a_different_digest_is_refused(monkeypatch, fake_pin_store, caplog):
    """The exact scenario asked for."""
    monkeypatch.setitem(issuer.AGENT_REGISTRY, "agent", _unseeded("research_agent"))
    client = TestClient(issuer.app)

    monkeypatch.setattr(
        issuer, "_lookup_caller_container", _fake_lookup("agent", "sha256:first-boot")
    )
    first = client.post("/attest")
    assert first.status_code == 200

    monkeypatch.setattr(
        issuer, "_lookup_caller_container", _fake_lookup("agent", "sha256:different-second-time")
    )
    with caplog.at_level(logging.INFO, logger="agentfw.identity"):
        second = client.post("/attest")

    assert second.status_code == 403
    assert "digest mismatch" in second.json()["detail"]
    event = json.loads(caplog.records[-1].message)
    assert event["decision"] == "DENY"
    assert "sha256:first-boot" in event["reason"]
    assert "sha256:different-second-time" in event["reason"]


def test_tofu_trade_off_an_attacker_winning_the_race_gets_pinned(monkeypatch, fake_pin_store):
    """Named trade-off, made concrete: whoever attests first for a service wins the pin, even if
    it's not the real container — TOFU's window is exactly one attestation, not "forever
    unverified" (the thing being removed), but it is not zero, and this test says so out loud."""
    monkeypatch.setitem(issuer.AGENT_REGISTRY, "agent", _unseeded("research_agent"))
    client = TestClient(issuer.app)

    monkeypatch.setattr(
        issuer, "_lookup_caller_container", _fake_lookup("agent", "sha256:attacker-won-the-race")
    )
    assert client.post("/attest").status_code == 200

    monkeypatch.setattr(
        issuer, "_lookup_caller_container", _fake_lookup("agent", "sha256:the-real-image")
    )
    real_container_attempt = client.post("/attest")
    assert real_container_attempt.status_code == 403


# =====================================================================================
# Trust-on-first-use: with a pre-seed (EXPECTED_DIGEST_*)
# =====================================================================================


def test_preseeded_digest_is_pinned_on_the_very_first_call(monkeypatch, fake_pin_store):
    monkeypatch.setitem(
        issuer.AGENT_REGISTRY,
        "agent",
        issuer.RegisteredAgent(role="research_agent", image_digest="sha256:known-good"),
    )
    monkeypatch.setattr(
        issuer, "_lookup_caller_container", _fake_lookup("agent", "sha256:known-good")
    )

    client = TestClient(issuer.app)
    assert client.post("/attest").status_code == 200
    assert identity_store.list_all(fake_pin_store) == {"agent": "sha256:known-good"}


def test_preseed_catches_a_mismatch_on_attestation_one_not_just_two(
    monkeypatch, fake_pin_store, caplog
):
    """The whole reason a pre-seed is worth configuring: without one, a wrong container passing
    itself off as "agent" on the very first boot gets pinned and trusted forever after. With one,
    that same first attempt is caught immediately."""
    monkeypatch.setitem(
        issuer.AGENT_REGISTRY,
        "agent",
        issuer.RegisteredAgent(role="research_agent", image_digest="sha256:known-good"),
    )
    monkeypatch.setattr(
        issuer, "_lookup_caller_container", _fake_lookup("agent", "sha256:not-what-was-expected")
    )

    client = TestClient(issuer.app)
    with caplog.at_level(logging.INFO, logger="agentfw.identity"):
        response = client.post("/attest")
    assert response.status_code == 403
    assert "digest mismatch" in response.json()["detail"]


# =====================================================================================
# Fail toward DENY when the pin store can't be reached
# =====================================================================================


def test_attestation_refused_when_the_pin_store_is_unreachable(monkeypatch, caplog):
    monkeypatch.setitem(issuer.AGENT_REGISTRY, "agent", _unseeded("research_agent"))
    monkeypatch.setattr(
        issuer, "_lookup_caller_container", _fake_lookup("agent", "sha256:whatever")
    )

    import sqlite3

    def _boom(_service, _seed_digest):
        raise sqlite3.OperationalError("simulated local disk outage")

    monkeypatch.setattr(issuer, "_get_or_set_pin", _boom)

    client = TestClient(issuer.app)
    with caplog.at_level(logging.INFO, logger="agentfw.identity"):
        response = client.post("/attest")
    assert response.status_code == 403
    assert "digest pin check unavailable" in response.json()["detail"]


# =====================================================================================
# Unchanged from before: registry/container-match checks
# =====================================================================================


def test_unknown_service_is_still_refused(monkeypatch):
    monkeypatch.setattr(
        issuer, "_lookup_caller_container", _fake_lookup("not-a-real-service", "sha256:x")
    )
    client = TestClient(issuer.app)
    response = client.post("/attest")
    assert response.status_code == 403


def test_no_container_match_is_refused_and_logged(monkeypatch, caplog):
    async def _lookup(_source_ip: str):
        return None

    monkeypatch.setattr(issuer, "_lookup_caller_container", _lookup)
    client = TestClient(issuer.app)
    with caplog.at_level(logging.INFO, logger="agentfw.identity"):
        response = client.post("/attest")
    assert response.status_code == 403
    assert len(caplog.records) == 1
