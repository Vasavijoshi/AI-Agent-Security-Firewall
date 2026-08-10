"""Tests for the pre-M3 attestation hardening: identity/issuer.py must verify the image digest
Docker reports, not just the compose service label — a label is attacker-settable via
`docker run --label`; forging a digest requires producing that image.
"""

from __future__ import annotations

import json
import logging

from fastapi.testclient import TestClient

import identity.issuer as issuer


def _fake_lookup(service: str, image_digest: str, container_id: str = "deadbeefcafe1234567890"):
    async def _lookup(_source_ip: str):
        return {"container_id": container_id, "image_digest": image_digest, "service": service}

    return _lookup


def test_correct_service_and_matching_digest_mints_a_token(monkeypatch):
    monkeypatch.setitem(
        issuer.AGENT_REGISTRY,
        "agent",
        issuer.RegisteredAgent(role="research_agent", image_digest="sha256:goodgoodgood"),
    )
    monkeypatch.setattr(
        issuer, "_lookup_caller_container", _fake_lookup("agent", "sha256:goodgoodgood")
    )

    client = TestClient(issuer.app)
    response = client.post("/attest")
    assert response.status_code == 200
    assert "token" in response.json()


def test_correct_service_wrong_digest_is_refused(monkeypatch, caplog):
    """The exact scenario asked for: right label, wrong image — refused."""
    monkeypatch.setitem(
        issuer.AGENT_REGISTRY,
        "agent",
        issuer.RegisteredAgent(role="research_agent", image_digest="sha256:goodgoodgood"),
    )
    monkeypatch.setattr(
        issuer, "_lookup_caller_container", _fake_lookup("agent", "sha256:forged-by-attacker")
    )

    client = TestClient(issuer.app)
    with caplog.at_level(logging.INFO, logger="agentfw.identity"):
        response = client.post("/attest")

    assert response.status_code == 403
    assert "digest mismatch" in response.json()["detail"]

    # WHY assert on the logged event, not just the HTTP response: the requirement is "log it as a
    # security event," not just "reject the HTTP call" — this is the same distinction M1 gap #3
    # already established for the bypass listener.
    assert len(caplog.records) == 1
    event = json.loads(caplog.records[0].message)
    assert event["decision"] == "DENY"
    assert event["policy_id"] == "ATTESTATION_DENY"
    assert "digest mismatch" in event["reason"]
    assert "sha256:goodgoodgood" in event["reason"]
    assert "sha256:forged-by-attacker" in event["reason"]


def test_forged_label_alone_does_not_help_without_the_real_digest(monkeypatch):
    """The attack this hardening actually closes: an attacker who can `docker run --label
    com.docker.compose.service=agent` still fails, because they can't also produce the pinned
    image's digest."""
    monkeypatch.setitem(
        issuer.AGENT_REGISTRY,
        "agent",
        issuer.RegisteredAgent(role="research_agent", image_digest="sha256:goodgoodgood"),
    )
    monkeypatch.setattr(
        issuer,
        "_lookup_caller_container",
        _fake_lookup("agent", "sha256:attacker-built-this-image"),
    )

    client = TestClient(issuer.app)
    response = client.post("/attest")
    assert response.status_code == 403


def test_unpinned_digest_still_succeeds_but_is_logged(monkeypatch, caplog):
    """WHY this must still succeed: AGENTFW_CONTEXT.md §1 requires `docker compose up` to work on
    a fresh clone with zero manual configuration, and a freshly built image's digest isn't
    knowable ahead of the build. Unset means "unpinned," logged loudly, not refused."""
    monkeypatch.setitem(
        issuer.AGENT_REGISTRY,
        "agent",
        issuer.RegisteredAgent(role="research_agent", image_digest=""),
    )
    monkeypatch.setattr(
        issuer, "_lookup_caller_container", _fake_lookup("agent", "sha256:whatever")
    )

    client = TestClient(issuer.app)
    with caplog.at_level(logging.WARNING, logger="agentfw.identity"):
        response = client.post("/attest")

    assert response.status_code == 200
    assert any("attestation_unpinned" in r.message for r in caplog.records)


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
