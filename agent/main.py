"""Container entrypoint: runs one agent session against AGENTFW_SCENARIO and prints the result log.

WHY the agent is a run-once batch job, not a long-running service: M1's agent doesn't listen for
anything — it drives a fixed scenario to completion and exits. `docker compose up -d` will show it
Exited(0); that's expected, not a crash. `docker compose logs agent` is how you read what happened.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict

from agent.loop import run

AGENT_ID = os.environ.get("AGENT_ID", "research-agent-01")


def main() -> int:
    log = run(AGENT_ID)
    for entry in log:
        print(json.dumps(asdict(entry)), flush=True)
    denied = [e for e in log if e.decision not in ("ALLOW", "ALLOW_REDACTED")]
    print(
        f"session complete: {len(log)} tool call(s), {len(log) - len(denied)} allowed, "
        f"{len(denied)} denied",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
