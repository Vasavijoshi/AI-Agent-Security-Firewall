"""Tool schemas and dispatch for http.get, http.post, db.query, file.read, email.send — all routed
through the PEP."""

from __future__ import annotations

import os
from typing import Any

import httpx

PEP_URL = os.environ.get("PEP_URL", "http://pep:8080")
IDENTITY_ISSUER_URL = os.environ.get("IDENTITY_ISSUER_URL", "http://identity:8082")

_token_cache: str | None = None

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "http.get",
        "description": "Fetch a URL.",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "http.post",
        "description": "POST a body to a URL.",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}, "body": {"type": "string"}},
            "required": ["url", "body"],
        },
    },
    {
        "name": "db.query",
        # WHY `table`, not a raw SQL string: policy (policy/bundles/default.yaml) matches
        # `resource` glob patterns like "customers.*" against this field. A free-text query string
        # isn't something a glob pattern — or anything short of a SQL parser — can reason about;
        # requiring a structured table name keeps the resource policy-governable, the same way
        # http.get/http.post take a structured `url` rather than a raw request line.
        "description": "Run a read query against a database table.",
        "input_schema": {
            "type": "object",
            "properties": {
                "table": {"type": "string"},
                "filter": {"type": "string"},
            },
            "required": ["table"],
        },
    },
    {
        "name": "file.read",
        "description": "Read a file by path.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "email.send",
        "description": "Send an email.",
        "input_schema": {
            "type": "object",
            "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
            "required": ["to", "body"],
        },
    },
]

TOOL_NAMES = frozenset(schema["name"] for schema in TOOL_SCHEMAS)


class ToolCallDenied(Exception):
    """Raised when the PEP's verdict was not ALLOW/ALLOW_REDACTED."""

    def __init__(self, decision: str, reason: str) -> None:
        self.decision = decision
        self.reason = reason
        super().__init__(f"{decision}: {reason}")


def _attest() -> str:
    """Fetch (and cache for the process lifetime) a workload token from the identity issuer.

    WHY the agent calls /attest instead of asserting its own identity: the token is minted from
    what the issuer's Docker API lookup finds, not from anything this process claims about itself
    (AGENTFW_CONTEXT.md §2) — there is nothing here for a prompt-injected agent to forge. Cached
    for the process's lifetime because a 15-minute TTL comfortably outlives one scripted session;
    a longer-running agent would need to re-attest on expiry, which this demo doesn't need.
    """
    global _token_cache
    if _token_cache is None:
        with httpx.Client(trust_env=False) as client:
            resp = client.post(f"{IDENTITY_ISSUER_URL}/attest", timeout=10.0)
        resp.raise_for_status()
        _token_cache = resp.json()["token"]
    return _token_cache


def dispatch(
    tool: str, arguments: dict[str, Any], *, session_id: str, trace_id: str
) -> tuple[str, dict[str, Any]]:
    """Every tool call crosses the PEP — this is the agent's only route out (AGENTFW_CONTEXT.md §2).

    WHY trust_env=False: this call's destination IS the PEP (http://pep:8080), reached directly
    over agent-net's internal container DNS — it is not a request being tunneled *through* the PEP
    as an HTTP forward proxy. docker-compose.yml still sets HTTP_PROXY/HTTPS_PROXY to pep:8081 (the
    bypass-catch listener) per AGENTFW_CONTEXT.md §5, but honoring that here would route this
    legitimate call into a listener designed to deny everything. Ignoring the agent's own proxy
    env vars for this one call is deliberate, not an oversight.
    """
    token = _attest()
    with httpx.Client(trust_env=False) as client:
        response = client.post(
            f"{PEP_URL}/v1/tool-call",
            json={
                "session_id": session_id,
                "trace_id": trace_id,
                "tool": tool,
                "arguments": arguments,
            },
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0,
        )
    body = response.json()
    if body["decision"] not in ("ALLOW", "ALLOW_REDACTED"):
        raise ToolCallDenied(body["decision"], body["reason"])
    return body["decision"], body["result"]
