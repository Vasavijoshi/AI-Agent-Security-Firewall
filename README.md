# AgentFW — Zero Trust enforcement for LLM agents

> An LLM agent can be talked into anything. This is the layer that stops it from *doing* anything
> it shouldn't.

**What it is:** a Policy Enforcement Point (PEP) that sits between an LLM agent and every tool it
calls — HTTP requests, database queries, file reads, emails, and calls to other agents — and
mediates each one through an 8-stage pipeline (identity, normalization, policy, threat intel, DLP,
risk scoring, decision, audit log) before anything executes.

**Who it protects:** whoever deploys the agent. Not the agent's user, not the agent itself — the
organization that would be liable if the agent got talked into leaking data or reaching somewhere
it shouldn't.

**What classic egress firewalls assume, and why it breaks for agents:** a conventional firewall
keys policy on IP and a static destination set — it works because identity is a proxy for network
location and "who's allowed to go where" doesn't change request to request. An LLM agent breaks
both assumptions: several roles can share one process/IP, and the agent picks its destination *at
runtime*, from content an attacker may control (a fetched web page, a tool result). A firewall that
only knows IPs and a fixed allowlist has nothing to say about that.

**What AgentFW changes:** policy is keyed on cryptographically-attested workload identity, not IP;
every request is normalized and inspected before being evaluated, not just port-and-address
matched; and the agent has no network path anywhere except through the PEP — enforced by Docker
network topology, not by the agent's own good behavior.

**Is this production-ready?** No, and this README says exactly where it isn't — see
[Limitations](#limitations). It's a portfolio project built to survive a real security review, not
a pitch deck.

---

## CI

[![CI](https://github.com/OWNER/agentfw/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)

**Honest status:** the workflow (`.github/workflows/ci.yml`) is real — three jobs (lint, policy
compile, test) that run on every push/PR with `LLM_PROVIDER=mock`, no API key required. It has
never actually run: this repository has no configured `git remote` and has never been pushed to
GitHub, so the badge above will 404 until it is. Swap `OWNER/agentfw` for the real path once it's
pushed, or the badge should be honestly removed rather than left pointing at nothing.

---

## 30-second demo

[GIF PLACEHOLDER — 30-second AgentFW demo]

*What you'll see once this is recorded: an agent gets an indirect prompt injection from a page it
fetched, complies with it (tries to read the customer DB and exfiltrate it), and AgentFW denies
both actions — the model got hijacked, the firewall didn't care.*

---

## Why this exists

An LLM agent's tool calls are chosen at runtime by a component that can be talked into anything —
a prompt injection riding inside a web page, a tool result, an uploaded document. Two assumptions
a classic egress firewall makes both break:

1. **Identity is a proxy for network location.** It isn't, for an agent: several differently-
   privileged roles can share one container/IP, and a firewall that only sees "traffic from
   10.0.1.5" has no way to ask "which *role* is this."
2. **The destination set is static, decided ahead of time by an operator.** It isn't, for an
   agent: the agent picks its own destination at runtime, often from content it just read — a
   fetched page telling it to POST somewhere is not a hypothetical, it's `A6` below.

AgentFW enforces deny-by-default egress on a workload whose destination set is chosen at runtime by
a component that may be adversarial. See [docs/architecture.md](docs/architecture.md) for the full
design.

---

## Run it

### Fast demo (no Docker, no API key, ~30 seconds)

```bash
git clone <repo> && cd agentfw
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
python -m attacks.run_all      # 9 attacks, in-process pipeline replay where Docker isn't reachable
python -m evals.score          # real measured numbers: block rate, false-positive rate, latency
```

### Full verification (Docker, ~5 minutes)

```bash
cp .env.example .env                    # works with NO API key, using the mock LLM
docker compose up -d
docker compose ps                       # all services should show healthy
curl http://localhost:8501              # dashboard reachable

# M3 attack suite — the real 9/9 needs to run from inside the agent container, not the host,
# because A4/A9 specifically require the agent-net route the host doesn't have (see below):
docker compose exec agent python -m attacks.run_all

# Evaluation (in-process pipeline replay — see Results table for exactly what this measures):
docker compose exec agent python -m evals.score

# Live PEP performance benchmark (the actual deployed /v1/tool-call endpoint, not a replay):
docker compose exec support-agent python -m evals.bench_pep --requests 1000

# Dashboard: http://localhost:8501
```

**Why `attacks/run_all.py` needs to run from inside the `agent` container for a true 9/9:** two of
the nine attacks (A4, multi-agent lateral movement; A9, the raw `:8081` bypass listener) require
reaching the live `identity`/`pep` containers over `agent-net` — a route that only exists from
*inside* another container on that network, not from the host (neither port is published in
`docker-compose.yml`, on purpose — publishing them would itself be a small non-bypassability
leak). Run bare from the host and those two honestly report `UNVERIFIED` rather than a faked pass.

If any of this doesn't work on a clean machine with no API key and no cloud account, that's a bug.

---

## Results

Every number below is either a real measurement with its methodology stated, or `NOT MEASURED`.
None are invented, estimated, or interpolated (`AGENTFW_CONTEXT.md` §8). Numbers that looked bad
are reported as measured, not rounded away — see the footnotes.

### Security evaluation — in-process pipeline replay

`evals/score.py`, replaying `evals/corpus_attack.jsonl` / `evals/corpus_benign.jsonl` through the
real `pep.pipeline.run_pipeline()` code with genuinely signed tokens (`attacks/common.py`) — **not**
a live Docker deployment; no network hop to a real PEP/identity/eventstore container is included in
these numbers. See footnote [^harness] on how this was corrected mid-milestone.

| Metric | Value |
|---|---|
| Attack corpus size | 66 |
| Benign corpus size | 65 |
| Total calls replayed | 131 |
| Block rate (attack corpus) | 98.5% (65/66) |
| False-positive rate (benign corpus) | 0.0% (0/65) |
| Approval rate (benign, `REQUIRE_APPROVAL` — genuinely stopped) [^lattice] | 6.2% (4/65) |
| Throttle rate (benign, `RATE_LIMIT` — **designed-not-implemented, executes normally**) [^lattice] | 52.3% (34/65) |
| `RATE_ANOMALY` firing rate, attack corpus | 69.7% (46/66) |
| `RATE_ANOMALY` firing rate, benign corpus | 4.6% (3/65) |
| In-process pipeline latency, p50 | 0.203 ms |
| In-process pipeline latency, p95 | 0.301 ms |
| In-process pipeline latency, p99 | 0.360 ms |
| In-process pipeline latency, mean | 0.260 ms |

### Docker attack verification — live deployment

`docker compose exec` against a running stack — see `docs/verification-log.md`'s Verification 5
for the full real command output and two important caveats this table's footnotes summarize.

| Metric | Value |
|---|---|
| Attacks tested | 9 (A1–A9) |
| Attacks denied, live Docker | 9 / 9 [^quarantine][^identity-mismatch] |
| A4 (real multi-agent lateral movement) | Reached live, genuinely denied [^quarantine] |
| A9 (raw `:8081` bypass listener) | Denied live, clean pass, no caveat |
| A9 `BYPASS_ATTEMPTED` attribution in PEP logs | Independently confirmed — 2 real log lines, real `trace_id`s, `docker compose logs pep` |

### Performance — live Docker PEP, `/v1/tool-call`

| Metric | Value |
|---|---|
| Request count | NOT MEASURED |
| Concurrency | NOT MEASURED |
| Warm-up requests | NOT MEASURED |
| End-to-end p50 / p95 / p99 | NOT MEASURED |
| DLP-exercised workload p50 / p95 / p99 | NOT MEASURED |
| DLP-not-triggered workload p50 / p95 / p99 | NOT MEASURED |
| Per-stage latency (identity/normalize/policy/threat_intel/dlp/risk/decision/log) | NOT MEASURED |

**Why this section is empty:** the tool to produce these numbers (`evals/bench_pep.py`) is built,
documented, and its HTTP-calling/stats mechanics were smoke-tested against a real running PEP
process — but I have no Docker in the environment I work in (the standing caveat repeated at every
milestone in this project), so the actual live numbers have not been collected. Run:

```bash
docker compose exec support-agent python -m evals.bench_pep --requests 1000 --concurrency 10 --warmup 50
```

and this table gets filled in with real numbers, not estimates. See
[Benchmark methodology](#benchmark-methodology) below for exactly what this measures and its own
limitations.

[^harness]: The first two versions of the benign-corpus numbers were wrong, and the mistakes were
    real bugs in the evaluation harness, not the firewall: an earlier run reported false-positive
    3.1% and friction 96.9% — summing to exactly 100%, meaning *zero* benign records ever landed
    on `ALLOW`, which a real distribution doesn't do. Root cause: `evals/score.py`'s
    `run_evaluation()` called `RiskScorer.warm_up()` then immediately wiped the seed it had just
    built (`reset_process_state()` ran second) — every replay scored against completely cold state
    regardless of `risk/baseline.jsonl`. Fixed by reordering, plus extending the baseline to cover
    destinations registered agents legitimately use but the baseline never listed. A second,
    smaller bug (`RATE_ANOMALY` reading the real wall clock during a sub-second replay loop,
    manufacturing its own signal) was fixed by giving the rate-window logic an injectable clock
    (`risk.scorer.set_clock()`) and adding a real per-record timestamp to the corpus schema. No
    decision-lattice threshold was ever changed to reach the final numbers.

[^lattice]: `REQUIRE_APPROVAL` and `RATE_LIMIT` were originally reported as one combined "friction
    rate" (58.5%). That conflated "a human is genuinely stopped" with "logged and executed exactly
    like `ALLOW`" — see the [decision lattice table](#decision-lattice--implementation-status).
    Split into two separate, correctly-labeled metrics; no threshold was touched to do it.

[^quarantine]: Six of the nine live results (A1, A2, A3, A4, A5, A7) show `AGENT_QUARANTINED` as
    their actual live `reason`, not the specific mechanism each attack is individually built to
    demonstrate (`DEFAULT_DENY`, `dlp_block`, `DEFAULT_DENY_EAST_WEST`, etc.) — because
    `run_all.py` ran all nine in one process against one persistent eventstore, and the calling
    workload was already quarantined (evidently from an earlier, untracked debugging run) before
    this run even started. The requests were still genuinely denied over live Docker — quarantine
    backstopping a gap is a real, arguably stronger result — but this run does not independently
    confirm each attack's *own* claimed mechanism the way a from-cold-state run would. Full detail
    in `docs/verification-log.md`'s Verification 5.

[^identity-mismatch]: A structural finding, not a one-off bug: `identity/issuer.py`'s `/attest` is
    deliberately unauthenticated and derives identity entirely from the caller's real network
    position, never from a claim the caller makes about itself (`AGENTFW_CONTEXT.md` §2 — this is
    correct, load-bearing design). That means an attack script's live path can only ever attest as
    whichever container it's actually invoked from — A2/A3/A5/A8 are written to simulate
    `finance_agent`/`admin_agent`/`support_agent`/`finance_agent`, but when `run_all.py` runs from
    a single container, their live component is actually evaluated under *that container's* real
    role. `admin_agent` has no registered workload at all, so A3's live `REAL_DOCKER_VERIFIED`
    status could only be real for whatever role actually answered. Full detail, including why this
    was caught by reading the output rather than trusting the summary line, in
    `docs/verification-log.md`'s Verification 5.

---

## Benchmark methodology

`evals/bench_pep.py` measures the **real deployed `/v1/tool-call` endpoint** over live Docker
networking — end-to-end HTTP latency, not the in-process replay `evals/score.py` measures. Run
from inside the `support-agent` container specifically (`docker compose exec support-agent
python -m evals.bench_pep`), because — see the identity finding above — `/attest` can only ever
attest as whichever container actually calls it.

- **Workloads:** two, both using `support_agent`'s own real charter so the comparison is
  apples-to-apples (same role, same baseline considerations):
  - **DLP-exercised** — `db.query` on `customers` (`R-SUPPORT-001` sets `inspect: true`; DLP runs
    on every request, unconditionally).
  - **DLP-not-triggered** — `email.send` to the approved helpdesk address (`R-SUPPORT-002` has no
    `inspect` flag, and `email.send` never produces an `fqdn`, so the stage-5 gate — `inspect` or
    external destination or `agent.invoke` — is never true).
- **Load:** 1000 requests per workload by default (`--requests`), concurrency 10 by default
  (`--concurrency`) — a controlled, realistic level for a demo-scale deployment, not a stress test;
  the objective is reproducibility, not a dramatic number.
- **Warm-up:** 50 requests by default (`--warmup`), discarded before measurement starts — first
  requests on a fresh connection pool pay TCP/TLS-setup costs a steady-state client doesn't.
- **Token reuse:** attested once per run, reused for every request in that run — matching how a
  real deployed agent behaves (`agent/tools.py`'s `_attest()` caches its token for the process
  lifetime); re-attesting per call would benchmark `identity/issuer.py`'s Docker-socket lookup
  instead of the PEP path this benchmark is about.
- **Denied requests are counted, not discarded.** A `DENY`/`QUARANTINE`/`REQUIRE_APPROVAL`
  response still executed the full pipeline server-side. Only genuine transport failures
  (connection refused, timeout) are classified as errors.
- **Per-stage timing** comes directly from the PEP's own `/v1/tool-call` response body
  (`latency_ms`, already returned for every call — no new instrumentation was needed) — real
  server-measured per-stage numbers, not derived or estimated client-side.
- **Docker/network overhead is kept in the number, not subtracted.** The reported latency is
  client-measured, wall-clock, end-to-end.
- **Known limitations of this methodology:** a single-machine Docker Desktop deployment is not
  representative of a production multi-host network; the FastAPI route handling `/v1/tool-call` is
  a synchronous `def`, so concurrent requests are served from Starlette's thread pool, not a
  fully async pipeline — worth knowing when interpreting concurrency scaling; no repeated-run
  variance has been collected (only one run's methodology is documented here, because no run has
  happened yet in an environment with Docker).

---

## Architecture

```
┌─────────────────── agent-net  (internal: true — NO route to the internet) ───────────────────┐
│                                                                                                │
│   ┌────────────┐          HTTP_PROXY /            ┌────────────────────────────┐              │
│   │   agent    │ ───────  HTTPS_PROXY=pep:8080 ──▶ │            pep             │              │
│   │ (loop.py,  │                                   │  (dual-homed — the ONLY    │              │
│   │  tools.py, │                                   │  container on both nets)   │              │
│   │  providers)│                                   └──────────────┬─────────────┘              │
│   └────────────┘                                                  │                             │
│   finance-agent, support-agent: same pattern, same network        │                             │
│   identity: agent-net only — local SQLite digest pins, no route   │                             │
│   out (see docs/architecture.md's round-5 note)                   │                             │
└────────────────────────────────────────────────────────────────────┼─────────────────────────────┘
                                                                     │  crosses into egress-net
                                                                     ▼
┌─────────────────────────── egress-net  (bridge — has internet route) ─────────────────────────┐
│                                                                                                 │
│      ┌────────────┐            ┌───────────────┐             allowlisted external              │
│      │ eventstore │◀───────────│  pep (2nd nic) │────────────▶ destinations                     │
│      │ (SQLite,   │            └───────────────┘                                                │
│      │  quarantine│                                                                              │
│      │  state)    │                                                                              │
│      └─────┬──────┘                                                                              │
│            │                                                                                     │
│      ┌─────▼──────┐                                                                              │
│      │ dashboard  │  (reads eventstore only, never touches agent-net)                            │
│      └────────────┘                                                                              │
│                                                                                                   │
└───────────────────────────────────────────────────────────────────────────────────────────────┘

Direct bypass path (pep/bypass_proxy.py, :8081): HTTP_PROXY/HTTPS_PROXY point here as a catch-all.
Any code path that tries a raw outbound call anyway hits this listener and gets DENY,
reason=BYPASS_ATTEMPTED — loud and attributable, not a silent connection failure.

East-west (agent.invoke, policy/engine.py's evaluate_east_west()): a different question from the
main rule table — "may workload A invoke workload B," not "may role R reach destination D." The
default bundle's east_west_rules list is empty: no role currently has a charter to invoke another,
so every cross-agent call hits default-deny.
```

`pep` is the only container on both networks — this is the actual current topology, matched to
`docker-compose.yml`, not aspirational. See [docs/architecture.md](docs/architecture.md) for the
full 8-stage pipeline diagram and the reasoning behind each element.

---

## Design decisions

Five decisions, each a real trade-off made in this codebase — not a manufactured list:

1. **Fail-closed enforcement over availability.** `pep/proxy.py`'s log-or-deny: if the durable
   event write fails, the action is denied, even if policy would have allowed it (invariant §3.4).
   *Given up:* availability during an eventstore outage — a legitimate agent's every call is
   blocked, not just malicious ones, until logging is restored. The alternative (allow-and-hope-
   the-log-catches-up) makes every denial claim in this README unauditable, which is worse.

2. **One central PEP over direct agent connectivity.** Every tool call is forced through
   `pep/proxy.py`'s `/v1/tool-call`; `agent-net` being `internal: true` means there is no other
   route out, even if the agent process is fully compromised. *Given up:* the PEP is a single
   enforcement point and a single point of failure/bottleneck — every agent action now costs a
   real network hop and pipeline execution it wouldn't otherwise pay, and the PEP not being
   horizontally scaled (see Limitations) caps how much traffic this topology can actually carry.

3. **Trust-on-first-use digest pinning over image-update convenience.** `identity/issuer.py`
   pins whichever image digest it observes on a service's first successful attestation and refuses
   every later attestation that doesn't match (`identity/store.py`, local SQLite, agent-net-only).
   *Given up:* rebuilding and redeploying an agent's image now requires deliberately clearing its
   pin first (`identity/admin_cli.py`, `docker compose exec identity python -m
   identity.admin_cli clear-pin <service>`) — an operational step a naive redeploy will forget,
   turning a routine image update into a self-inflicted attestation failure.

4. **Stateful risk/taint scoring over stateless horizontal scalability.** `risk/scorer.py`'s
   novelty, rate-window, and bigram tracking, and `pep/pipeline.py`'s session-taint state, are
   in-memory and per-process. *Given up:* the PEP cannot be run as more than one replica without
   either sharing this state externally (not built) or accepting that risk scoring/taint tracking
   silently degrades to per-replica partial visibility — a real scaling ceiling, not a hypothetical
   one, and the single biggest reason this isn't production-ready as-is.

5. **Strict, explicit-deny-first policy over developer flexibility.** `policy/engine.py`: explicit
   `DENY` beats explicit `ALLOW` beats implicit default-deny, always, with a structural taint
   ceiling (`session_taint == "tainted"` forbids writes/secret-class data) that no individual rule
   can override even by omission. *Given up:* a developer adding a new legitimate capability must
   write an explicit, reviewed policy rule for it — there is no "just let this through for now"
   escape hatch, which is the point, but it is real friction against fast iteration.

---

## Decision lattice — implementation status

`DENY < QUARANTINE < REQUIRE_APPROVAL < RATE_LIMIT < ALLOW_REDACTED < ALLOW` is the full lattice
(`AGENTFW_CONTEXT.md` §2). Not every point on it has real behavior behind it yet — this table is
the honest answer to "does X actually do anything," not just "does X get returned as a value":

| Decision | Status | What actually happens |
|---|---|---|
| `DENY` | Implemented | The action does not execute. |
| `ALLOW` | Implemented | The action executes. |
| `ALLOW_REDACTED` | Implemented | The action executes (DLP found something REDACT-severity). |
| `QUARANTINE` | Implemented | The action does not execute, **and** the agent's stable identity is added to a quarantine set persisted on the eventstore (`events/app.py`'s `/quarantine` routes) — every subsequent call from it is denied with `reason=AGENT_QUARANTINED`, regardless of policy, until a human releases it. Entry is automatic (risk CRITICAL band, a threat-intel hit, or 5+ denials in 60s); exit is manual only, on purpose. Persisted (survives a PEP restart) and reachable only from egress-net. |
| `RATE_LIMIT` | **Designed, not implemented** | The action currently executes, same as `ALLOW`. There is no actual throttling — no token bucket, no per-agent rate cap enforced against it. The lattice position and the lattice math (`min()` narrowing) are real; the "limit" part of the name is aspirational until a throttling mechanism is built. |
| `REQUIRE_APPROVAL` | **Designed, not implemented** | The action does **not** execute — but there is no approval queue, no notification, no human-in-the-loop workflow for it to wait on. It's currently indistinguishable from a dead end: the call is held forever in effect, because nothing ever approves it. |

---

## Limitations

Stated plainly, not buried:

- **`REQUIRE_APPROVAL` has no approval workflow.** It correctly stops execution, but there is no
  queue, timeout-to-deny, or UI for a human to actually approve or reject — a held call stays held
  forever in the current implementation.
- **`RATE_LIMIT` is not real throttling.** It executes the call exactly like `ALLOW`. The lattice
  position and narrowing logic are real; the enforcement is not.
- **The M3/M4 security evaluation is corpus replay, not production traffic.** 66 attack + 65
  benign hand-authored records, replayed through the real pipeline code — a controlled test, not a
  sample of real agent behavior in the wild. See the hostile-review section of the M4 report for
  the full skeptical treatment of what this does and doesn't prove.
- **The corpus was authored by the same process that built the firewall**, with full knowledge of
  `policy/bundles/default.yaml`'s exact rules. A benign/attack split constructed by someone with no
  visibility into AgentFW's internals would be a stronger, more independent test than this one.
- **`evals/score.py`'s evaluation clock is synthetic** (`offset_seconds`, `risk.scorer.set_clock()`)
  — necessary so a sub-second replay loop doesn't manufacture its own `RATE_ANOMALY` signal, but it
  means rate-anomaly timing in the evaluation reflects hand-chosen inter-arrival times, not
  observed real-world traffic patterns.
- **`risk/baseline.jsonl`'s seed data is hand-authored**, not sampled from real usage, and was
  specifically extended mid-M3 to cover destinations the eval corpus touches — see the hostile
  review for the skeptical read of that sequencing.
- **The threat-intel list is a tiny local file** (`threat_intel/lists/malicious_fqdns.txt`, two
  entries) — no external feed integration, no update mechanism.
- **No claim of complete prompt-injection detection or complete agent-compromise prevention.**
  AgentFW's entire design thesis is the opposite: it assumes the agent *will* be compromised and
  bounds the blast radius via identity, policy, taint, and DLP — see A6 and
  `docs/architecture.md`'s "Prompt injection containment (not detection)" section.
  `evals/corpus_attack.jsonl` demonstrates 66 specific attack shapes get blocked; it does not
  demonstrate coverage of attack shapes not represented in that corpus.
- **The live Docker performance benchmark has not been run in an environment with Docker
  available** — `evals/bench_pep.py` is built and its mechanics smoke-tested, but the Results
  table's performance section is honestly `NOT MEASURED` pending a run against the real deployment.
- **`docker compose exec agent python -m attacks.run_all`'s live "9/9 blocked" result has two
  documented methodology caveats** (quarantine cascade contaminating per-attack mechanism
  attribution; role-identity mismatch for attacks whose claimed role differs from the invoking
  container) — see the Results table footnotes and `docs/verification-log.md`'s Verification 5.
- **The PEP does not scale horizontally.** Risk/taint state is in-memory, per-process — see Design
  decision 4.
- **Identity's Docker-socket attestation gives the `identity` container visibility into every
  container on the host's Docker daemon**, not just this project's — a real, accepted trade-off
  for avoiding Kubernetes-style infrastructure this repo's scope excludes (`AGENTFW_CONTEXT.md` §2).

---

## What I'd do next

Prioritized by what the limitations above actually point at, not a wishlist:

1. **Approval workflow for `REQUIRE_APPROVAL`** — a queue, a timeout-to-deny, and something for a
   human to click. The single least-finished point on the lattice.
2. **Real rate limiting for `RATE_LIMIT`** — a token bucket or per-agent cap actually enforced, not
   just a lattice position.
3. **Stronger identity lifecycle** — key rotation for the issuer's signing key (currently
   regenerated fresh on every restart, invalidating every outstanding token), and a real
   alternative to Docker-socket attestation for anywhere but a single trusted host.
4. **A larger, independently-sourced evaluation corpus** — ideally authored or reviewed by someone
   without visibility into `policy/bundles/default.yaml`'s exact rules, to test generalization
   rather than fit.
5. **External threat-intelligence feed integration**, replacing the two-entry local list.
6. **Distributed state for risk/taint scoring**, removing the single-replica ceiling (Design
   decision 4) — likely a shared store (Redis or similar) once horizontal scaling is actually
   needed, not before.
7. **Observability**: metrics/tracing beyond the structured JSON event log and Streamlit dashboard
   — a real time-series backend for the latency/decision data already being captured.
8. **Production hardening**: signing-key rotation, secrets management beyond `.env`, and replacing
   the Docker-socket attestation trust model before running anywhere but a single trusted host.
9. **Performance scaling**: once the PEP can run more than one replica (item 6), re-run the
   benchmark methodology above under real concurrent multi-agent load, not the single-container
   controlled load this milestone's benchmark targets.

---

## Project status

Milestone: **M4 complete — this is the final milestone.** M1–M3 built the enforcement pipeline,
identity, policy engine, risk scoring, quarantine, nine attack demonstrations, the evaluation
harness, and the dashboard. M4 added: the live-Docker PEP benchmark tool (`evals/bench_pep.py`,
numbers pending a Docker-available run), this README, `docs/threat-model.md`, `docs/demo.md`, a
hostile self-review, and final resume bullets (`AgentFW_Build_Plan_v2.md` §9). See
`docs/verification-log.md` for the complete real-command/real-output verification history,
including two real findings inside a real "9/9 blocked" pass (Verification 5) that are reported
here rather than smoothed over.
