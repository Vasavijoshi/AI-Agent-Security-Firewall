"""Ed25519-signed short-lived workload tokens: identity proven by platform attestation, never by
a shared secret.

# WHY /attest is deliberately unauthenticated, and why that's not a hole: it doesn't need a
# credential because it's authenticated by network position + platform introspection instead —
# only something Docker itself can see running as a container, on agent-net, gets a truthful
# answer to "who is calling me." The agent never asserts its own identity; it can't forge what the
# Docker API reports about the socket that's actually connected (AGENTFW_CONTEXT.md §2).
#
# WHY /var/run/docker.sock, read-only, and why that's a real trade-off, not a free lunch: mounting
# the socket gives this container visibility into every container on the host's Docker daemon, not
# just this project's — a bigger blast radius than a "real" SPIFFE node attestor would have.
# Read-only limits it to inspect-only calls (this module never issues a write/control call against
# the socket). Accepted for this project's scope because the alternative — a Kubernetes
# ServiceAccount-style attestor — is exactly the infrastructure AGENTFW_CONTEXT.md §1 rules out.
#
# WHY the service label alone was never enough (pre-M3 hardening): `docker run --label
# com.docker.compose.service=agent` is something anyone who can start a container can set —
# forging it costs nothing. Forging the *image digest* that the Docker API reports for a running
# container requires producing an image that actually hashes to the expected value, which is a
# different, much harder problem. Verifying both is what turns "which label did you set" into
# "which image are you actually running."
#
# WHY trust-on-first-use, not an optional expected-digest check (pre-M3 ruling, round 4): an
# optional check is off by default, and "off by default" on a fresh clone — exactly
# AGENTFW_CONTEXT.md §1's acceptance-test configuration — means digest verification was never
# actually protecting anything unless someone remembered to turn it on. TOFU is unconditional:
# the first successful attestation for a service pins whatever digest it observed (see
# identity/store.py's get_or_set()), and every later attestation for that service must match or is
# refused. Named trade-off: the trust window is exactly one attestation, at first boot — an
# attacker who wins the race to attest first, before the real container does, gets pinned instead
# of the real image. EXPECTED_DIGEST_* (still optional, still just for pre-seeding) closes that
# window entirely for anyone willing to configure it: set, it becomes the value pinned on that
# first call instead of blindly trusting whatever shows up, so a mismatch is caught even on
# attestation #1.
#
# WHY the pin lives in identity's own local SQLite file, not the eventstore (pre-M3 ruling,
# round 5, correcting round 4): a digest pin is identity's own state, not a shared security event —
# routing it through the eventstore forced identity onto egress-net to reach it, making it a second
# dual-homed container and a second potential bridge from agent-net to the internet. Identity mints
# workload identity; a compromise of it is a high-value target, and giving it egress turns that
# compromise into an exfiltration path regardless of what identity's own code currently intends to
# do with the route. Local storage (identity/store.py, on its own named volume) removes the need
# for the route entirely — identity is agent-net-only again, and `pep` is once more the only
# dual-homed container (docker-compose.yml, AGENTFW_CONTEXT.md §5).
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request

import identity.store as pin_store
from identity.tokens import generate_keypair, mint_token, public_key_to_b64

DOCKER_SOCKET = os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock")
IDENTITY_DB_PATH = os.environ.get("IDENTITY_DB_PATH", "/data/identity.db")

# WHY stdout for attestation *denials*: see pep/bypass_proxy.py's M1-gap-#3 precedent —
# `docker compose logs identity` is the loud, attributable trail. Digest *pins* are different
# state entirely (identity/store.py, a local file, not an event), so they don't go through this
# logger — there's nothing to log on the happy path, only on refusal.
logging.basicConfig(level=logging.INFO, format="%(message)s")
event_logger = logging.getLogger("agentfw.identity")


@dataclass(frozen=True)
class RegisteredAgent:
    role: str
    # WHY still called "image_digest" and still optional: this is now a pre-seed for the TOFU pin
    # (see the module WHY), not the sole gate — "" means "no pre-seed, pin whatever the first
    # successful attestation observes" rather than "digest checking is off."
    image_digest: str


def _expected_digest(env_var: str) -> str:
    return os.environ.get(env_var, "")


# compose service name -> (role, optional digest pre-seed). WHY only "agent" has ever had a live
# container historically: docker-compose.yml originally defined a single agent service. Pre-M3
# multi-agent adds finance-agent and support-agent as real services (see docker-compose.yml)
# sharing this same image, distinguished only by which compose service name Docker reports them
# under — which is exactly the fact this registry keys off of.
AGENT_REGISTRY: dict[str, RegisteredAgent] = {
    "agent": RegisteredAgent(
        role="research_agent", image_digest=_expected_digest("EXPECTED_DIGEST_AGENT")
    ),
    "finance-agent": RegisteredAgent(
        role="finance_agent", image_digest=_expected_digest("EXPECTED_DIGEST_FINANCE_AGENT")
    ),
    "support-agent": RegisteredAgent(
        role="support_agent", image_digest=_expected_digest("EXPECTED_DIGEST_SUPPORT_AGENT")
    ),
}

_PRIVATE_KEY, _PUBLIC_KEY = generate_keypair()
# WHY generated fresh on every container start, not persisted: a restarted issuer invalidates
# every outstanding token, which is acceptable for 15-minute-TTL tokens in a single-instance demo
# and avoids building key storage/rotation infrastructure this project doesn't otherwise need.
# What I'd do differently at production scale: a persisted, rotated signing key so issuer restarts
# don't cascade into every agent re-attesting at once.

app = FastAPI(title="AgentFW Identity Issuer")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/public-key")
def public_key() -> dict[str, str]:
    return {"public_key": public_key_to_b64(_PUBLIC_KEY)}


@app.post("/attest")
async def attest(request: Request) -> dict[str, str]:
    source_ip = request.client.host if request.client else None
    if not source_ip:
        raise HTTPException(status_code=400, detail="no source address on this connection")

    info = await _lookup_caller_container(source_ip)
    if info is None:
        _log_attestation_denial("no_container_match", source_ip, None)
        raise HTTPException(status_code=403, detail="caller's container could not be identified")

    registered = AGENT_REGISTRY.get(info["service"])
    if registered is None:
        _log_attestation_denial(
            f"service {info['service']!r} not in AGENT_REGISTRY", source_ip, info
        )
        raise HTTPException(
            status_code=403, detail=f"service {info['service']!r} is not in the agent registry"
        )

    # --- image digest verification: trust-on-first-use, unconditional (see module WHY block) ---
    # WHY the pin lookup can itself deny: if the local pin store can't be read or written, this
    # module cannot tell whether it's checking a real container against a real pin — proceeding
    # anyway would be exactly the "unpinned escape hatch" this ruling removed, just relocated to a
    # different failure mode. Consistent with pep/quarantine.py's QuarantineCheckUnavailable: fail
    # toward DENY with a reason that says so, never toward silently trusting.
    try:
        seed_digest = registered.image_digest or info["image_digest"]
        pinned_digest = _get_or_set_pin(info["service"], seed_digest)
    except (sqlite3.Error, OSError) as exc:
        _log_attestation_denial(f"digest pin check unavailable: {exc}", source_ip, info)
        raise HTTPException(
            status_code=403, detail="attestation failed: digest pin check unavailable"
        ) from exc

    if info["image_digest"] != pinned_digest:
        _log_attestation_denial(
            f"image digest mismatch for service {info['service']!r}: pinned "
            f"{pinned_digest!r}, got {info['image_digest']!r}",
            source_ip,
            info,
        )
        raise HTTPException(status_code=403, detail="attestation failed: image digest mismatch")

    role = registered.role
    spiffe_id = f"spiffe://agentfw.internal/ns/{role}/agent/{info['container_id'][:12]}"
    token = mint_token(
        {
            "spiffe_id": spiffe_id,
            "role": role,
            "container_id": info["container_id"],
            "image_digest": info["image_digest"],
            # WHY "service" is a separate claim from container_id: container_id is this specific
            # process's identity — it changes on every restart, which is exactly right for the
            # container-binding check below (a stolen token must die with its container) but
            # exactly wrong for anything that needs to be known *before* attestation happens, like
            # baseline-seeding per-agent behavioral state or quarantine membership. "service" is
            # the compose service name (AGENT_REGISTRY's key) — stable across restarts, and
            # knowable ahead of time precisely because it's a registry lookup, not a runtime fact.
            "service": info["service"],
            # WHY this is here: the PEP's "container binding" check compares this against the IP
            # of the connection actually calling it, so a stolen token replayed from a different
            # container fails even though the signature is valid.
            "attested_ip": source_ip,
        },
        _PRIVATE_KEY,
    )
    return {"token": token}


def _log_attestation_denial(reason: str, source_ip: str, info: dict[str, str] | None) -> None:
    """Loud and attributable, matching pep/bypass_proxy.py's precedent — see the module WHY block
    for why this goes to stdout rather than the durable eventstore."""
    event = {
        "schema_version": "1.0",
        "timestamp": datetime.now(UTC).isoformat(),
        "trace_id": str(uuid.uuid4()),
        "session_id": "unknown",
        "agent_id": (info or {}).get("service") or "unknown",
        "role": "unknown",
        "tool": "identity.attest",
        "action": "attest",
        "destination": {"fqdn": None, "ip": source_ip, "port": None, "protocol": None},
        "resource": (info or {}).get("container_id"),
        "data_classification": "internal",
        "session_taint": "clean",
        "risk_score": 0,
        "risk_factors": [],
        "policy_id": "ATTESTATION_DENY",
        "policy_bundle_version": "n/a",
        "decision": "DENY",
        "reason": reason,
        "latency_ms": {},
    }
    event_logger.info(json.dumps(event))


def _get_or_set_pin(service: str, seed_digest: str) -> str:
    """Look up the pinned digest for `service` in identity's own local SQLite file, pinning
    `seed_digest` if this is the first attestation ever for it. Raises sqlite3.Error or OSError
    (caught by the caller) if the local store can't be read or written."""
    return pin_store.get_or_set(
        service, seed_digest, datetime.now(UTC).isoformat(), IDENTITY_DB_PATH
    )


async def _lookup_caller_container(source_ip: str) -> dict[str, str] | None:
    """Ask the Docker API which running container owns `source_ip`. Returns None if no container
    matches — never raises for "not found," since an unrecognized caller is an ordinary 403, not a
    fault."""
    transport = httpx.AsyncHTTPTransport(uds=DOCKER_SOCKET)
    async with httpx.AsyncClient(transport=transport, base_url="http://docker") as client:
        resp = await client.get("/containers/json")
        resp.raise_for_status()
        containers: list[dict[str, Any]] = resp.json()

    for container in containers:
        networks = container.get("NetworkSettings", {}).get("Networks", {})
        if any(net.get("IPAddress") == source_ip for net in networks.values()):
            labels = container.get("Labels", {}) or {}
            return {
                "container_id": container["Id"],
                "image_digest": container.get("ImageID", ""),
                "service": labels.get("com.docker.compose.service", ""),
            }
    return None
