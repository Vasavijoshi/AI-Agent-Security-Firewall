# AgentFW — Zero Trust enforcement for LLM agents

> An LLM agent can be talked into anything. This is the layer that stops it from *doing* anything
> it shouldn't.

[CI badge — TBD once GitHub Actions has run at least once; workflow itself is real as of M1
(`ruff check` + `ruff format --check`), expands with tests in M2]

## The 30-second demo

[GIF — TBD in M4: agent gets prompt-injected, tries to exfiltrate, gets blocked twice]

## Why

LLM agents choose their own destinations at runtime, from content an attacker may control.
Classic egress firewalls key on IP and assume a static destination set. Both assumptions break.
AgentFW keys policy on workload identity and inspects the request before it's encrypted, mediating
every tool call through an 8-stage enforcement pipeline instead of trusting the agent to police
itself.

## Run it

```bash
git clone <repo> && cd agentfw
cp .env.example .env          # works with NO API key, using the mock LLM
docker compose up -d
python attacks/run_all.py     # 7 attacks, 7 blocks
python evals/score.py         # real measured numbers
```

If that sequence doesn't work on a clean machine with no API key and no cloud account, that's a bug
— [file an issue].

**As of M1**, the first three lines work: the stack builds and runs, and `docker compose logs
agent` shows one allowed and one denied tool call, both logged. `attacks/run_all.py` and
`evals/score.py` are still one-line placeholders — they're M3 work. This note goes away once they
are.

## Results

Every number below comes from an actual run on the author's machine, or it says `TBD`. None are
invented (AGENTFW_CONTEXT.md §8).

| Metric | Value |
|---|---|
| Attack scenarios blocked | TBD / 7 |
| Block rate (attack corpus, n=TBD) | TBD % |
| False-positive rate (benign corpus, n=TBD) | TBD % |
| PEP added latency, p50 | TBD ms |
| PEP added latency, p95 | TBD ms |
| PEP added latency, p99 | TBD ms |

## How it works

See [docs/architecture.md](docs/architecture.md) for the full pipeline diagram and network topology.

## Design decisions

Each of these gave something up on purpose — details in [docs/architecture.md](docs/architecture.md):

- TBD
- TBD
- TBD
- TBD
- TBD

## What I'd do next

Sidecar-per-agent deployment, Kubernetes NetworkPolicy as the L3 backstop, multicloud identity
federation — documented as design targets in `AgentFW_Architecture_v1.md`, deliberately out of
scope for this repo (AGENTFW_CONTEXT.md §1).

## Project status

Milestone: M1 — vertical slice. Agent loop (mock provider), PEP proxy with a hardcoded
allow/deny table, event logging, and the Docker two-network split are built. Identity, the real
policy engine, risk scoring, taint tracking, and DLP are all still M2. See
[docs/architecture.md](docs/architecture.md) for what's real vs. what's a documented stand-in.
