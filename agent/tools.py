"""Tool schemas and dispatch for http.get, http.post, db.query, file.read, email.send — all routed
through the PEP."""

from __future__ import annotations

import os
from typing import Any

import httpx

PEP_URL = os.environ.get("PEP_URL", "http://pep:8080")

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
        "description": "Run a read query against the customer database.",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
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


def dispatch(
    tool: str, arguments: dict[str, Any], *, agent_id: str, session_id: str, trace_id: str
) -> tuple[str, dict[str, Any]]:
    """Every tool call crosses the PEP — this is the agent's only route out (AGENTFW_CONTEXT.md §2).

    WHY trust_env=False: this call's destination IS the PEP (http://pep:8080), reached directly
    over agent-net's internal container DNS — it is not a request being tunneled *through* the PEP
    as an HTTP forward proxy. docker-compose.yml still sets HTTP_PROXY/HTTPS_PROXY to pep:8080 per
    AGENTFW_CONTEXT.md §5, but honoring that here would mean asking pep to proxy a request whose
    destination is also pep, which is a needless and fragile self-loop. Ignoring the agent's own
    proxy env vars for this one call is deliberate, not an oversight.
    """
    with httpx.Client(trust_env=False) as client:
        response = client.post(
            f"{PEP_URL}/v1/tool-call",
            json={
                "agent_id": agent_id,
                "session_id": session_id,
                "trace_id": trace_id,
                "tool": tool,
                "arguments": arguments,
            },
            headers={"X-Agent-Id": agent_id},
            timeout=10.0,
        )
    body = response.json()
    if body["decision"] not in ("ALLOW", "ALLOW_REDACTED"):
        raise ToolCallDenied(body["decision"], body["reason"])
    return body["decision"], body["result"]
