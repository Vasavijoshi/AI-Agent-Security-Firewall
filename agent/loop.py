"""Hand-written multi-turn tool-calling loop that drives the agent against a Provider."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from agent.providers import Provider, get_provider
from agent.tools import TOOL_NAMES, TOOL_SCHEMAS, ToolCallDenied, dispatch

# WHY a hard cap, and why 10: a hijacked or simply confused agent must not be able to hammer the
# PEP forever — every call it makes is a real network round trip and a real event write. 10 is
# generous for every M1 scenario (which need 1-2 calls) and small enough that a runaway loop fails
# fast and visibly rather than as a slow resource leak.
MAX_ITERATIONS = 10


@dataclass
class TurnLog:
    tool: str
    arguments: dict
    decision: str
    reason: str
    detail: str


def run(
    agent_id: str, scenario: str | None = None, provider: Provider | None = None
) -> list[TurnLog]:
    """Drive one agent session to completion (or MAX_ITERATIONS) and return what happened.

    Every tool call the provider requests is dispatched through the PEP; there is no code path
    here that reaches a destination directly. A tool name the provider invents that doesn't exist
    in TOOL_SCHEMAS is never sent to the PEP at all — it's an agent-side error, logged locally,
    because the PEP has nothing to evaluate a call against a tool it's never heard of.
    """
    provider = provider or get_provider(scenario)
    session_id = str(uuid.uuid4())
    messages: list[dict] = []
    log: list[TurnLog] = []

    for _ in range(MAX_ITERATIONS):
        turn = provider.next_turn(messages, TOOL_SCHEMAS)
        if not turn.tool_calls:
            break

        for call in turn.tool_calls:
            if call.name not in TOOL_NAMES:
                log.append(TurnLog(call.name, call.arguments, "AGENT_ERROR", "unknown_tool", ""))
                continue

            trace_id = str(uuid.uuid4())
            try:
                decision, result = dispatch(
                    call.name,
                    call.arguments,
                    agent_id=agent_id,
                    session_id=session_id,
                    trace_id=trace_id,
                )
                log.append(
                    TurnLog(
                        call.name, call.arguments, decision, "matched_explicit_allow", str(result)
                    )
                )
            except ToolCallDenied as exc:
                log.append(TurnLog(call.name, call.arguments, exc.decision, exc.reason, ""))

    return log
