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
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request

from identity.tokens import generate_keypair, mint_token, public_key_to_b64

DOCKER_SOCKET = os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock")

# WHY stdout, not a durable eventstore write: identity is on agent-net only (it never needs the
# internet, and giving it a route to eventstore on egress-net would mean touching the network
# topology the rest of this project's non-bypassability story rests on, for one log line). This
# mirrors pep/bypass_proxy.py's M1-gap-#3 precedent exactly: `docker compose logs identity` is the
# loud, attributable trail for attestation denials, at the cost of not showing up in the
# eventstore/dashboard's durable history. A known, deliberate scope line, not an oversight.
logging.basicConfig(level=logging.INFO, format="%(message)s")
event_logger = logging.getLogger("agentfw.identity")


@dataclass(frozen=True)
class RegisteredAgent:
    role: str
    image_digest: str  # expected `ImageID` from the Docker API; "" means unpinned (see below)


def _expected_digest(env_var: str) -> str:
    return os.environ.get(env_var, "")


# compose service name -> (role, expected image digest). WHY only "agent" has ever had a live
# container: docker-compose.yml originally defined a single agent service. Pre-M3 multi-agent adds
# finance-agent and support-agent as real services (see docker-compose.yml) sharing this same
# image, distinguished only by which compose service name Docker reports them under — which is
# exactly the fact this registry, and the digest check below, key off of.
#
# WHY image_digest defaults to "" (unpinned) rather than refusing when unset: AGENTFW_CONTEXT.md
# §1 is a hard constraint — a fresh `git clone && docker compose up` must work with zero manual
# configuration. A freshly built image's digest isn't knowable before the build finishes, so a
# fresh clone has nothing to pin against yet. Unset means "digest pinning not configured for this
# service" (logged loudly on every attest — see _attest_denied below), not "refuse everything until
# someone configures it," which would break the one acceptance test this whole project is
# optimized around. Set EXPECTED_DIGEST_AGENT / _FINANCE_AGENT / _SUPPORT_AGENT (e.g. from `docker
# inspect <image> -f '{{.Id}}'` after building) to get the real protection.
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

    # --- image digest verification: the actual hardening (see the module WHY block) ---
    if registered.image_digest and info["image_digest"] != registered.image_digest:
        _log_attestation_denial(
            f"image digest mismatch for service {info['service']!r}: expected "
            f"{registered.image_digest!r}, got {info['image_digest']!r}",
            source_ip,
            info,
        )
        raise HTTPException(status_code=403, detail="attestation failed: image digest mismatch")
    if not registered.image_digest:
        # WHY this is its own branch, logged but not refused: unpinned is the honest, expected
        # state for a fresh clone (see AGENT_REGISTRY's WHY) — surfaced loudly so it's never
        # mistaken for real digest protection being in effect, without breaking `docker compose up`.
        event_logger.warning(
            json.dumps(
                {
                    "event": "attestation_unpinned",
                    "service": info["service"],
                    "note": "no EXPECTED_DIGEST_* configured — running unverified",
                }
            )
        )

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
