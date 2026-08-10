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
python attacks/run_all.py     # 9 attacks — see the honest caveat below
python evals/score.py         # real measured numbers
```

If that sequence doesn't work on a clean machine with no API key and no cloud account, that's a bug
— [file an issue].

**Honest caveat on `attacks/run_all.py` run this way:** two of the nine attacks (A4, multi-agent
lateral movement; A9, the raw `:8081` bypass listener) specifically require reaching the live
`identity`/`pep` containers over `agent-net` — a route that only exists from *inside* another
container on that network, not from the host (neither port is published in `docker-compose.yml`,
on purpose — publishing them would itself be a small non-bypassability leak). Run bare from the
host, or in this repo's own no-Docker dev sandbox, those two honestly report `UNVERIFIED` rather
than a faked pass, and the script's own summary says so. For the real 9/9, run it from where A4/A9
actually need to be:
```bash
docker compose exec agent python -m attacks.run_all
```
Every other attack (A1–A3, A5–A8) routes through the real pipeline code either way — live if the
PEP/identity containers answer, an in-process replay with a genuinely signed token
(`attacks/common.py`) if they don't — and each script's own output says explicitly which one
happened. See `docs/verification-log.md` for what has actually been confirmed against a live
Docker deployment versus what's still open.

## Results

Every number below comes from an actual run on the author's machine (`python attacks/run_all.py`
and `python evals/score.py`, in this repo's own no-Docker dev environment — see the caveat above),
or it says `TBD`. None are invented (AGENTFW_CONTEXT.md §8). Bad numbers are reported as measured,
not rounded away — see the explanations under the table.

| Metric | Value |
|---|---|
| Attack scenarios blocked | 7 / 9 in this environment (2 UNVERIFIED — need a live Docker run, see below) |
| Attack corpus size | 66 |
| Benign corpus size | 65 |
| Block rate (attack corpus) | 98.5% (65/66) |
| False-positive rate (benign corpus) | 3.1% (2/65) |
| Friction rate (benign corpus, RATE_LIMIT/REQUIRE_APPROVAL) | 96.9% (63/65) |
| Pipeline latency, p50 | 0.369 ms |
| Pipeline latency, p95 | 0.582 ms |
| Pipeline latency, p99 | 0.854 ms |

**What these numbers actually measure, and what they don't:** every replay above is an in-process
call into `pep.pipeline.run_pipeline()` with a genuinely signed token — real identity
verification, real normalization, real policy/threat-intel/DLP/risk code, real decision lattice —
timed with `time.perf_counter()` around the real call. It is **not** a live Docker deployment;
there's no network hop to a real PEP/identity/eventstore container in these numbers, so treat the
latency figures as a floor, not a ceiling — a real deployment adds real network time on top.

**7/9, not 9/9, and why that's the honest number here:** A4 (real multi-agent lateral movement)
and A9 (the raw `:8081` bypass listener) specifically require a live Docker deployment by this
milestone's own design — see the caveat above. In this no-Docker environment they correctly report
`UNVERIFIED`, and `attacks/run_all.py` does not count them as blocked just because a supplementary
local check happened to show a denial. Run `docker compose exec agent python -m attacks.run_all`
against a real `docker compose up -d` stack to get the true count.

**The friction rate is real, and it's high — 96.9%, not a typo.** Most of the benign corpus lands
on `RATE_LIMIT`, not a clean `ALLOW`. This is cold-start novelty scoring doing exactly what it's
designed to do (`risk/scorer.py`'s `DEST_UNKNOWN_TO_ORG`/`DEST_NEVER_SEEN_BY_AGENT` factors), run
against a corpus deliberately built to hit many different destinations/tables/tools for category
coverage — the opposite of the repeated-narrow traffic a real warmed-up deployment would see after
a few days. It is a genuine, unmassaged finding about the cost of novelty-based scoring on a
diverse workload, not a bug hidden by picking an easier corpus.

**The 3.1% false-positive rate (2 of 65 benign calls) is also real**, not tuned away: both are
`finance_agent` reading a confidential table (`ledger`/`invoices`) for the first time, immediately
after a burst of legitimate rapid calls earlier in the same corpus run — `RATE_ANOMALY` (a burst
of >5 calls/60s, a realistic batch-processing pattern) stacks with first-time novelty and the
`confidential` data-class factor to just cross the 75-point `CRITICAL`/`QUARANTINE` threshold. A
real deployment with `risk/baseline.jsonl`-style warmed-up history for these specific tables would
likely not see this; a brand-new one doing a legitimate batch job on day one plausibly would.

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

Milestone: M3 complete (not yet independently re-verified against a live Docker deployment in
every respect — see `docs/verification-log.md`). Agent loop, PEP proxy, event logging, the Docker
two-network split, the real YAML policy engine + compiler, Ed25519 identity with Docker-socket
attestation (now agent-net-only, with local SQLite digest pinning), request normalization, DLP,
the risk scorer (with baseline seeding), taint tracking, and quarantine were all built through M2
and pre-M3 hardening. M3 adds: nine attack demonstrations (`attacks/a1.py`–`a9.py`) covering
unauthorized-destination, DLP/exfiltration, taint containment, real multi-agent lateral movement,
credential access, indirect prompt injection (the headline scenario), a threat-intel hit,
normalization-bypass resistance, and the raw `:8081` proxy bypass; a 66-case attack corpus and
65-case adversarial-benign corpus (`evals/corpus_attack.jsonl`, `evals/corpus_benign.jsonl`); a
real evaluation harness (`evals/score.py`) that replays both through the actual pipeline code and
measures block rate, false-positive rate, friction rate, and latency percentiles; and a Streamlit
dashboard (`dashboard/app.py`, 177 lines) reading the live event store. Two of the nine attacks
(A4, A9) require a real Docker deployment to reach their own stated verification bar and are
honestly reported `UNVERIFIED` in this no-Docker development environment — see the Results section
above and `docs/verification-log.md` for the exact commands to close that gap. See
[docs/architecture.md](docs/architecture.md) for what's real vs. what's a documented stand-in.
