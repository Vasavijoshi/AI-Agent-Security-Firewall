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
"""

from __future__ import annotations

import os
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request

from identity.tokens import generate_keypair, mint_token, public_key_to_b64

DOCKER_SOCKET = os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock")

# compose service name -> role. WHY only one entry has a live container: docker-compose.yml
# defines a single agent service ("agent"). The other three roles in policy/bundles/default.yaml
# are valid, policy-authored roles with no deployed agent yet — this registry maps what's actually
# reachable via the Docker API, not the full aspirational role set.
AGENT_REGISTRY: dict[str, str] = {
    "agent": "research_agent",
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
        raise HTTPException(status_code=403, detail="caller's container could not be identified")
    role = AGENT_REGISTRY.get(info["service"])
    if role is None:
        raise HTTPException(
            status_code=403, detail=f"service {info['service']!r} is not in the agent registry"
        )

    spiffe_id = f"spiffe://agentfw.internal/ns/{role}/agent/{info['container_id'][:12]}"
    token = mint_token(
        {
            "spiffe_id": spiffe_id,
            "role": role,
            "container_id": info["container_id"],
            "image_digest": info["image_digest"],
            # WHY this is here: the PEP's "container binding" check compares this against the IP
            # of the connection actually calling it, so a stolen token replayed from a different
            # container fails even though the signature is valid.
            "attested_ip": source_ip,
        },
        _PRIVATE_KEY,
    )
    return {"token": token}


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
