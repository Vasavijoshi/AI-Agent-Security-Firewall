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
python attacks/run_all.py     # 8 attacks, 8 blocks
python evals/score.py         # real measured numbers
```

If that sequence doesn't work on a clean machine with no API key and no cloud account, that's a bug
— [file an issue].

**As of the pre-M3 ruling**, the first three lines work: the stack builds and runs, the full
8-stage pipeline is live (identity, normalization, policy, threat intel, DLP, risk, decision,
log), and `docker compose logs pep` shows every decision — including bypass-listener denials —
without needing the eventstore reachable. `attacks/run_all.py` and `evals/score.py` still only
call `RiskScorer.warm_up()` at startup; the corpora and scoring loop are M3 work. This note goes
away once they are.

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

## Decision lattice — implementation status

`DENY < QUARANTINE < REQUIRE_APPROVAL < RATE_LIMIT < ALLOW_REDACTED < ALLOW` is the full lattice
(AGENTFW_CONTEXT.md §2). Not every point on it has real behavior behind it yet — this table is
the honest answer to "does X actually do anything," not just "does X get returned as a value":

| Decision | Status | What actually happens |
|---|---|---|
| `DENY` | Implemented | The action does not execute. |
| `ALLOW` | Implemented | The action executes. |
| `ALLOW_REDACTED` | Implemented | The action executes (DLP found something REDACT-severity). |
| `QUARANTINE` | Implemented | The action does not execute, **and** the agent's stable identity is added to a quarantine set persisted on the eventstore (`events/app.py`'s `/quarantine` routes) — every subsequent call from it is denied with `reason=AGENT_QUARANTINED`, regardless of policy, until a human releases it. Entry is automatic (risk CRITICAL band, a threat-intel hit, or 5+ denials in 60s); exit is manual only, on purpose — see `pep/quarantine.py`'s own WHY. Persisted (survives a PEP restart) and reachable only from egress-net — agent-net has no route there at all. |
| `RATE_LIMIT` | **Designed, not implemented** | The action currently executes, same as `ALLOW`. There is no actual throttling — no token bucket, no per-agent rate cap enforced against it. The lattice position and the lattice math (`min()` narrowing) are real; the "limit" part of the name is aspirational until a throttling mechanism is built. |
| `REQUIRE_APPROVAL` | **Designed, not implemented** | The action does **not** execute — but there is no approval queue, no notification, no human-in-the-loop workflow for it to wait on. It's currently indistinguishable from a dead end: the call is held forever in effect, because nothing ever approves it. This is the least-finished point on the lattice; a real implementation needs a queue, a timeout-to-deny, and something for a human to actually click. |

## What I'd do next

Sidecar-per-agent deployment, Kubernetes NetworkPolicy as the L3 backstop, multicloud identity
federation — documented as design targets in `AgentFW_Architecture_v1.md`, deliberately out of
scope for this repo (AGENTFW_CONTEXT.md §1).

## Project status

Milestone: pre-M3, M2 complete. Agent loop, PEP proxy, event logging (durable + `docker compose
logs pep` observable), the Docker two-network split, the real YAML policy engine + compiler,
Ed25519 identity with Docker-socket attestation, request normalization, DLP, the risk scorer
(with baseline seeding), taint tracking, and quarantine are all built — see the table above for
exactly which lattice states are real versus designed-only. Not yet built: the 8 attack scripts,
eval corpora, scorer, and dashboard (all M3). See [docs/architecture.md](docs/architecture.md)
for what's real vs. what's a documented stand-in.
