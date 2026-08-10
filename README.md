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
| False-positive rate (benign corpus) | 0.0% (0/65) |
| Approval rate (benign corpus, REQUIRE_APPROVAL — genuinely stopped) | 6.2% (4/65) |
| Throttle rate (benign corpus, RATE_LIMIT — **designed-not-implemented, executes normally**) | 52.3% (34/65) |
| `RATE_ANOMALY` firing rate, attack corpus | 69.7% (46/66) |
| `RATE_ANOMALY` firing rate, benign corpus | 4.6% (3/65) |
| Pipeline latency, p50 | 0.251 ms |
| Pipeline latency, p95 | 0.556 ms |
| Pipeline latency, p99 | 0.719 ms |

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

**A real bug was found and fixed while producing these numbers, and the first version of this
table was wrong because of it.** An earlier run reported false-positive 3.1% and friction 96.9% —
summing to exactly 100%, meaning *zero* benign records ever landed on a clean `ALLOW`. That's not
a real distribution; it was `evals/score.py` calling `RiskScorer.warm_up()` and then immediately
wiping the seed it had just built (`attacks.common.reset_process_state()` ran second, clearing the
same org/agent novelty state `warm_up()` had populated), so every corpus replay scored against
completely cold state regardless of `risk/baseline.jsonl`'s content. Fixed by reordering
(`evals/score.py`'s `run_evaluation()`) and by extending `risk/baseline.jsonl` to cover several
bundle-allowed destinations (three `*.arxiv.org` subdomains, one more `*@approved-helpdesk.com`
sender) that registered agents legitimately use but the baseline never listed — each new baseline
line independently verified against the real policy engine as genuinely `ALLOW`-shaped for its
role, not just appended and trusted.

**Fixing that dropped friction to 90.8%, still implausibly high — and that second number was also
an artifact, not a finding.** `replay_corpus()` iterates 65+ records in well under a second of real
wall-clock time; `risk/scorer.py`'s `RATE_ANOMALY` factor (`>5 calls/60s`) read the real clock, so
the harness itself was generating most of the signal it measured, regardless of how the underlying
traffic was actually spaced in time. Fixed by giving the rate-window logic an explicit, injectable
time source (`risk.scorer.set_clock()` — production still reads the real wall clock; nothing in the
scorer special-cases being replayed) and adding a real timestamp to the corpus schema
(`offset_seconds`, seconds since that corpus's own replay start) with realistic per-category
spacing: research browsing and ticket handling are minutes apart, not seconds; attack records burst
per *service* (a compromised workload's own continuous rapid-fire session — an early version bucketed
bursts by narrative category instead of by which agent was acting, which diluted every individual
agent's own call rate below the anomaly threshold and had to be fixed too).

**The result actually separates attack from benign traffic, which is the property that matters:**
`RATE_ANOMALY` fires on 69.7% of attack-corpus calls (rapid enumeration, exfiltration loops, and
denial-probing genuinely do look like bursts) and only 4.6% of benign-corpus calls — and that
residual 4.6% is a disclosed, deliberate edge case (`legit_repeated_calls`: a live-feed poll spaced
8–12 seconds apart, tight enough that a real deployment doing the same thing would plausibly trip
the same factor — an honest cost of that polling cadence, not a rig artifact). A factor firing at
similar rates on both corpora would have carried no information; this one doesn't.

**Final false-positive rate is 0.0%** (was 3.1%, entirely explained by the baseline-coverage bug
above — no threshold was touched to reach this).

**"Friction rate" as a single number is retired, not just improved — it was hiding two different
things behind one average.** The original 58.5% figure (96.9% → 90.8% → 58.5% across the two fixes
above) summed `RATE_LIMIT` and `REQUIRE_APPROVAL` together. Per the
[decision-lattice status table](#decision-lattice--implementation-status) below, those are not the
same event: `REQUIRE_APPROVAL` genuinely stops the call — no approval workflow exists yet, so it's
currently a dead end — while `RATE_LIMIT` is designed-not-implemented and **executes the call
exactly like `ALLOW`**, just narrowed and logged. A metric that averages "a human was stopped" with
"logged verbosely and proceeded anyway" can't inform any decision. Split into two
(`evals/score.py`'s `approval_rate()`/`throttle_rate()`):

- **Approval rate: 6.2%** (4/65) — the real friction number. This is what a human actually has to
  intervene on, and it's a reasonable rate, not the alarming 58.5%/90.8%/96.9% the aggregate showed.
- **Throttle rate: 52.3%** (34/65) — real, unmassaged, and labeled for what it is: cold-start
  destination novelty (`DEST_UNKNOWN_TO_ORG`/`DEST_NEVER_SEEN_BY_AGENT`) narrowing `ALLOW` to
  `RATE_LIMIT` on a corpus deliberately built to cover many different destinations/tables for
  category coverage — logged and visible, but the call still goes through. Not folded into approval
  rate, and not hidden.

No decision-lattice threshold or band boundary was changed anywhere in this process — every number
above came from fixing what the harness measured and how it was reported, not from changing what
the firewall does.

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
