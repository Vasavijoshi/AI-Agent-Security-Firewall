# AgentFW — Zero Trust enforcement for LLM agents

> An LLM agent can be talked into anything. This is the layer that stops it from *doing* anything it shouldn't.

**What it is:** a Policy Enforcement Point (PEP) that sits between an LLM agent and every tool it calls — HTTP requests, database queries, file reads, emails, and calls to other agents — and mediates each one through an 8-stage enforcement pipeline (identity, normalization, policy, threat intel, DLP, risk scoring, decision, audit log) before anything executes.

**Who it protects:** whoever deploys the agent. Not the agent's user, not the agent itself — the organization that would be liable if the agent got talked into leaking data or reaching somewhere it shouldn't.

**What classic egress firewalls assume, and why it breaks for agents:** a conventional firewall keys policy on IP and a static destination set — it works because identity is a proxy for network location and "who's allowed to go where" doesn't change request to request. An LLM agent breaks both assumptions: several roles can share one process/IP, and the agent picks its destination *at runtime*, from content an attacker may control (a fetched web page, a tool result). A firewall that only knows IPs and a fixed allowlist has nothing to say about that.

**What AgentFW changes:** policy is keyed on cryptographically-attested workload identity, not IP; every request is normalized and inspected before being evaluated, not just port-and-address matched; and the agent has no network path anywhere except through the PEP — enforced by Docker network topology, not by the agent's own good behavior.

**Is this production-ready?** No, and this README says exactly where it isn't — see [Limitations](#limitations). It's a portfolio project built to survive a real security review, not a pitch deck.

---

## CI

**Honest status:** the workflow (`.github/workflows/ci.yml`) is real and currently passing. It runs three jobs on every push and pull request:

- **Lint** — `ruff check .` and `ruff format --check .`
- **Policy** — compiles `policy/bundles/default.yaml`
- **Test** — runs the full `pytest tests/ -v` suite after lint and policy checks pass

The workflow uses `LLM_PROVIDER=mock`, so the CI suite requires no external API key.
---


---

## Motivation and Problem Statement

An LLM agent's tool calls are chosen at runtime by a component that can be talked into anything —
a prompt injection riding inside a web page, a tool result, an uploaded document. Two assumptions
a classic egress firewall makes both break:

1. **Identity is a proxy for network location.** It isn't, for an agent: several differently-
   privileged roles can share one container/IP, and a firewall that only sees "traffic from
   10.0.1.5" has no way to ask "which *role* is this."
2. **The destination set is static, decided ahead of time by an operator.** It isn't, for an
   agent: the agent picks its own destination at runtime, often from content it just read — a
   fetched page telling it to POST somewhere is not a hypothetical, it's `A6` below.

AgentFW applies zero-trust egress enforcement to workloads whose tool destinations are chosen at
runtime by a component that may be adversarial. Every tool call is evaluated against the workload's
attested identity and the request's normalized destination, action, data classification, session
state, and other enforcement signals before execution.

See [docs/architecture.md](docs/architecture.md) for the full design.

---
## Run it

### Quick start (no Docker, no API key)

```bash
git clone https://github.com/Vasavijoshi/AI-Agent-Security-Firewall.git
cd AI-Agent-Security-Firewall

python -m venv .venv
source .venv/bin/activate                    # Windows: .venv\Scripts\activate

pip install -r requirements.txt

python -m attacks.run_all
python -m evals.score
```
### Full verification (Docker, ~5 minutes)

```
cp .env.example .env                    # works with NO API key, using the mock LLM
docker compose up -d
docker compose ps                       # identity, pep, eventstore, and dashboard should be up/healthy

# Dashboard:
# http://localhost:8501

# M3/M4 attack suite — run from the HOST.
# The orchestrator uses the Docker CLI to dispatch each attack to the
# Compose service that can genuinely attest as the role required by that attack.
python -m attacks.run_all

# Evaluation (in-process pipeline replay):
docker compose run --rm agent python -m evals.score

# Live PEP performance benchmark (the actual deployed /v1/tool-call endpoint, not a replay):
docker compose run --rm -T --no-deps -v "${PWD}:/app" -w /app --entrypoint python support-agent -m evals.bench_pep --requests 1000 --concurrency 10 --warmup 50 --workload both

# Dashboard:
# http://localhost:8501
```
### Host-Side Attack Orchestration:
The C1/C2 fix (see [Attack verification, corrected methodology](#attack-verification-corrected-methodology-c1c2-fix))
made it dispatch each attack to the *specific* Compose service that genuinely attests as the role
that attack needs (`docker compose run --rm <service> python -m attacks.aN`). This requires the
`docker` CLI and Compose project context to be available to the process running `run_all.py` itself;
no current service container provides that orchestration context.

Run it directly on the host, with `docker compose up -d` already running. It shells out to the
appropriate container for each attack and parses the resulting JSON, including A4 and A9, which
specifically exercise the `agent-net` route.

The orchestrator deliberately does not require the project's Python dependencies for its Docker
dispatch path — it only requires Python and the `docker` CLI — because it does not import the
project's `attacks`, `pep`, or `identity` implementation modules. It only launches the appropriate
Compose commands and parses their JSON results. This host-side execution model fixed a real bug
found during the first live attempt; the issue and its resolution are documented in
[`docs/verification-log.md`](docs/verification-log.md)'s Verification 7.

If `docker` or `docker compose` cannot be reached from where `run_all.py` is invoked, the runner
falls back to the in-process, no-Docker mode instead of silently treating the run as live Docker
verification. That fallback does require the project dependencies installed with
`pip install -r requirements.txt`.

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

The final corrected verification run is the authoritative result for A1–A9. Earlier live runs are
retained in `docs/verification-log.md` as methodology history because they exposed real execution
problems that were subsequently fixed.

| Metric | Value |
|---|---|
| Independent attacks tested | 9 (A1–A9) |
| Independently verified at the claimed mechanism | **8 / 9** |
| A1, A2, A4–A9 | `REAL_DOCKER_VERIFIED`, `mechanism_match: true` |
| A3 (`admin_agent`) | `UNVERIFIED` — no deployed Compose service can genuinely attest as `admin_agent` |
| A10 | Separate quarantine-cascade demonstration; **not counted** toward the A1–A9 total |

The earlier verification runs did deny all nine attacks over live Docker, but quarantine state and
role/identity mismatches prevented those runs from independently proving each attack's own claimed
mechanism. Those runs are documented as historical verification evidence rather than used to
inflate the final independent-verification count.

A9's raw `:8081` bypass attribution was independently observed in both earlier runs through real
PEP log entries and `trace_id`s; the final corrected methodology preserves A9 as an independently
verified attack.

### Run 3 (corrected methodology, per-role dispatch — genuinely verified, not just denied):

| Metric | Value |
|---|---|
| A1–A9 genuinely verified (correct role + own mechanism confirmed) | **8 / 9** [^c1c2-fix] |
| A3 (admin_agent — no deployed Compose service) | `UNVERIFIED`, structurally, by design — not a caveat, the correct answer |
| A10 (deliberate quarantine-cascade demonstration) | Attempted live, but **not confirmed** in the latest run [^a10] |

A10 is intentionally treated separately from the A1–A9 verification count. Its latest live run showed both calls being denied by `AGENT_QUARANTINED`; because the first call did not demonstrate its own intended threat-intelligence mechanism, the cascade could not be credited as independently confirmed. This is reported as a mechanism mismatch rather than converted into a successful cascade claim. [^a10]

[^a10]: The latest live A10 run returned `demonstrates_cascade: false`. Call 1 was denied with `AGENT_QUARANTINED` instead of its expected threat-intelligence mechanism, so `mechanism_match` was false. Call 2 was also denied with `AGENT_QUARANTINED`. The run therefore demonstrates quarantine state was present, but does not prove the intended cascade sequence.

See [Attack verification, corrected methodology](#attack-verification-corrected-methodology-c1c2-fix) below and `docs/verification-log.md`'s Verification 7 for the full real command
output, including the three real bugs found and fixed before this run succeeded.

### Performance — live Docker PEP, `/v1/tool-call`

Real measured numbers, collected this milestone via:
```bash
docker compose run --rm --no-deps -v "$PWD:/app" -w /app --entrypoint python support-agent \
  -m evals.bench_pep --requests 1000 --concurrency 10 --warmup 50 --workload both
```
Environment: `python=3.11.15`, Docker under WSL2
(`Linux-5.15.167.4-microsoft-standard-WSL2-x86_64-with-glibc2.41`). 1000 requests per workload,
concurrency 10, warm-up 50 per workload discarded — 2,000 measured requests total, **zero errors**.
Both workloads returned `success: 1000, deny: 0, error: 0` — this measures the *allowed* path.

| Metric | Value |
|---|---|
| Request count | 1000 per workload (2000 total) |
| Concurrency | 10 |
| Warm-up requests | 50 per workload (discarded) |
| Errors | 0 / 2000 |
| **End-to-end HTTP latency — `dlp_exercised`** | p50=138.415 ms · p95=351.680 ms · p99=809.256 ms · mean=174.119 ms |
| **End-to-end HTTP latency — `dlp_not_triggered`** | p50=130.423 ms · p95=413.625 ms · p99=839.947 ms · mean=169.307 ms |

**Per-stage latency, server-reported (`latency_ms` in the PEP's own response), p50/p95/p99 in ms:**

| Stage | `dlp_exercised` | `dlp_not_triggered` |
|---|---|---|
| identity | 0.3885 / 0.6066 / 1.4788 | 0.3680 / 0.5471 / 1.0091 |
| normalize | 0.0056 / 0.0097 / 0.0485 | 0.0054 / 0.0094 / 0.0133 |
| policy | 0.0564 / 0.1061 / 0.1670 | 0.0484 / 0.0881 / 0.1533 |
| threat_intel | 0.0021 / 0.0028 / 0.0031 | 0.0020 / 0.0027 / 0.0030 |
| dlp | 0.0274 / 0.0428 / 0.0918 | 0.0020 / 0.0031 / 0.0038 |
| risk | 0.1466 / 0.3262 / 0.8266 | 0.3002 / 0.5190 / 0.8346 |
| decision | 0.0048 / 0.0082 / 0.0138 | 0.0051 / 0.0083 / 0.0108 |
| log | 69.5336 / 234.1504 / 676.4877 | 62.5755 / 263.8114 / 595.2960 |
| **total** (server-reported, sum of stages) | **70.0759 / 234.6148 / 677.0141** | **63.4381 / 264.4298 / 596.0998** |

**Interpreting the Evaluation Results:**
- **End-to-end HTTP latency** is measured client-side (`time.perf_counter()` around the full
  request), and includes real network/Docker/HTTP-stack overhead. This is what a caller of the PEP
  actually experiences. It is **not** "PEP processing latency."
- **Server-reported `total`** is the sum of the eight pipeline stages, timed inside the PEP process
  itself — it does not include the network/transport time to reach the PEP or return the response.
  p50 end-to-end (~130–138 ms) is roughly double p50 server-reported `total` (~63–70 ms); that gap
  is real transport overhead the end-to-end number correctly includes and the stage breakdown
  correctly doesn't.
- **The `log` stage dominates server-reported pipeline latency** in both workloads — it accounts for
  nearly all of `total` at every percentile. This is a measured fact of *this* deployment (SQLite
  durable write plus an eventstore HTTP round trip in `pep/proxy.py`'s `_log_event()`); it is not
  extrapolated to any other environment or claimed as a general property of the architecture.
- **The DLP stage comparison is clean by construction:** `dlp_exercised` (DLP runs on every
  request) is roughly 10x `dlp_not_triggered` (DLP stage short-circuits) at every percentile —
  consistent with the two workloads' rules, not inferred from the timing alone.

Full real command output, environment details, and the second independent attack-verification run
collected in the same session: `docs/verification-log.md`'s Verification 6. See
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
    confirm each attack's *own* claimed mechanism the way a from-cold-state run would. **A second,
    independent run** (nine separate `docker exec` invocations, one per attack, rather than one
    shared `run_all.py` process) reconfirmed the same underlying finding from a different angle —
    a different subset of attacks (A3, A4, A5, A7 that time) showed `AGENT_QUARANTINED`, consistent
    with quarantine state being carried on the persistent eventstore across whatever ran before,
    not a fixed property of any one attack. Full detail in `docs/verification-log.md`'s
    Verifications 5 and 6.

[^identity-mismatch]: A structural finding, not a one-off bug: `identity/issuer.py`'s `/attest` is
    deliberately unauthenticated and derives identity entirely from the caller's real network
    position, never from a claim the caller makes about itself (`AGENTFW_CONTEXT.md` §2 — this is
    correct, load-bearing design). That means an attack script's live path can only ever attest as
    whichever container it's actually invoked from — A2/A3/A5/A8 are written to simulate
    `finance_agent`/`admin_agent`/`support_agent`/`finance_agent`, but when `run_all.py` runs from
    a single container, their live component is actually evaluated under *that container's* real
    role. `admin_agent` has no registered workload at all, so A3's live `REAL_DOCKER_VERIFIED`
    status could only be real for whatever role actually answered. **A second, independent run**
    (nine separate `docker exec` invocations against the same `m3-agent` container) reconfirmed
    this finding, this time backed by a direct grep of the deployed `identity` container's own
    `AGENT_REGISTRY` (three entries — `agent`, `finance-agent`, `support-agent` — no `admin_agent`),
    not just a read of the source tree. Full detail, including why this was caught by reading the
    output rather than trusting the summary line, in `docs/verification-log.md`'s Verifications 5
    and 6.

[^c1c2-fix]: 8 of 9 (A1, A2, A4–A9) genuinely `REAL_DOCKER_VERIFIED` with `mechanism_match: true` —
    correctly attested as the required role AND denied for the exact reason each scenario claims to
    demonstrate, not just "denied." A3 correctly and structurally reports `UNVERIFIED`: `admin_agent`
    has no deployed compose service, so no container can ever genuinely attest as it — this is the
    fix working as intended, not a residual gap. Getting to this result required fixing three real
    bugs surfaced only by an actual run attempt (a host-side dependency-import bug, a Docker-image
    packaging gap, and a wrong Compose command against a one-shot container) — see
    `docs/verification-log.md`'s Verification 7 for the full real output and all three fixes.

---

## Attack verification

The two footnotes above describe real problems with how A1–A9 were verified in Verifications 5 and 6
—not necessarily failures of the underlying enforcement. Those runs demonstrated live Docker denial,
but quarantine state and role/identity mismatches prevented them from independently confirming each
attack's own claimed mechanism. `attacks/run_all.py` and `attacks/common.py` were rewritten to fix
the execution model those runs exposed:

- **Each attack is dispatched to the Compose service that can genuinely attest as the role it
  requires** (`research_agent` → `agent`, `finance_agent` → `finance-agent`,
  `support_agent` → `support-agent`). The attacks use `docker compose run --rm <service>
  python -m attacks.aN` because these services are one-shot workloads rather than persistent
  containers. The attested role is cryptographically verified using the real identity service
  before a result can be reported as `REAL_DOCKER_VERIFIED`. A role mismatch is reported as
  `UNVERIFIED` rather than silently accepted. `admin_agent` (A3) has no deployed Compose service,
  so A3 remains structurally `UNVERIFIED` for its live path by design; no artificial service was
  created just to make the test pass.

- **Quarantine is cleared and verified empty immediately before each independent attack A1–A9**,
  using the existing public quarantine-management endpoints. This prevents an earlier attack's
  quarantine state from becoming an accidental prerequisite for a later attack.

- **Every attack checks its own expected decision and reason.** A correctly blocked request must be
  blocked by the mechanism that attack is intended to demonstrate. If a different mechanism such
  as `AGENT_QUARANTINED` takes over first, the result is reported as a mechanism mismatch rather
  than being counted as a successful verification.

- **A10 is a separate quarantine-persistence demonstration, not an independent attack.** It
  deliberately performs two calls on the same workload without clearing quarantine between them.
  Its purpose is to test whether an existing quarantine state persists into a subsequent request;
  it is never included in the A1–A9 independent-verification count.

**Current live verification status:** 8 of the 9 independent attacks (A1, A2, A4, A5, A6, A7, A8,
and A9) have been genuinely verified against the deployed Docker stack at their claimed mechanism,
with `mechanism_match: true`. A3 is intentionally `UNVERIFIED` because the required
`admin_agent` workload does not exist in the deployed Compose topology. This is a structural
limitation of the current deployment, not a fabricated pass.

A10 was also executed against the live Docker stack, but its latest run did **not** confirm the
intended quarantine cascade: both calls were denied with `AGENT_QUARANTINED`, while the first call
was expected to be denied by its own threat-intelligence mechanism. Therefore A10 is documented as
an attempted quarantine-cascade demonstration rather than claimed as independently confirmed
evidence. The result is intentionally reported as a mechanism mismatch instead of being counted
as a successful cascade verification.

This distinction is deliberate: the project reports what the deployed system actually demonstrated,
rather than converting every `DENY` response into a successful security-test result.

---

## Benchmark methodology

`evals/bench_pep.py` measures the **real deployed** **`/v1/tool-call`** **endpoint** over live Docker
networking — end-to-end HTTP latency, not the in-process replay measured by `evals/score.py`. The
benchmark is executed from a temporary `support-agent` Compose container so that the request
originates inside the deployed Docker network and can genuinely attest as `support_agent`.

- **Workloads:** two, both using `support_agent`'s own real charter so the comparison is
  apples-to-apples (same role, same baseline considerations):
  - **DLP-exercised** — `db.query` on `customers` (`R-SUPPORT-001` sets `inspect: true`; DLP runs
    on every request, unconditionally).
  - **DLP-not-triggered** — `email.send` to the approved helpdesk address (`R-SUPPORT-002` has no
    `inspect` flag, and `email.send` never produces an `fqdn`, so the stage-5 gate — `inspect` or
    external destination or `agent.invoke` — is never true).

- **Load:** 1000 requests per workload by default (`--requests`), concurrency 10 by default
  (`--concurrency`) — a controlled, demo-scale workload rather than a stress test. The objective
  is reproducibility and a meaningful comparison between the two request paths, not a maximum
  throughput claim.

- **Warm-up:** 50 requests per workload by default (`--warmup`), discarded before measurement
  starts. This allows the benchmark to separate initial request/setup effects from the measured
  workload.

- **Token reuse:** the agent is attested once per benchmark run and the resulting token is reused
  for requests in that run, matching the deployed agent behavior where `agent/tools.py`'s
  `_attest()` caches its token for the process lifetime. Re-attesting for every request would
  measure additional identity-service work rather than the PEP request path this benchmark is
  intended to measure.

- **Denied requests are counted, not discarded.** A `DENY`, `QUARANTINE`, or `REQUIRE_APPROVAL`
  response is still a completed PEP decision and is not classified as a transport error. Only
  genuine transport failures, such as connection errors or timeouts, are classified as errors.

- **Per-stage timing** comes directly from the PEP's own `/v1/tool-call` response body
  (`latency_ms`), which reports the server-measured duration of each pipeline stage. These values
  are not estimated from the client-side measurements.

- **Docker/network overhead is kept in the end-to-end number, not subtracted.** The reported
  end-to-end latency is measured client-side as wall-clock HTTP latency from the benchmark process
  to the deployed PEP endpoint and therefore includes the Docker/WSL2 networking overhead present
  in this environment.

- **The reported benchmark measures the allowed request paths.** The measured workloads returned
  `success: 1000, deny: 0, error: 0` for each workload in the recorded run. This benchmark therefore
  should not be interpreted as a stress test, a production capacity claim, or a measurement of
  denied-request latency.

- **Known limitations of this methodology:** a single-machine Docker-under-WSL2 deployment is not
  representative of a production multi-host network; the FastAPI route handling `/v1/tool-call`
  is a synchronous `def`, so concurrent requests are served through Starlette's thread pool
  rather than a fully asynchronous request handler; and no repeated-run variance has been
  collected. The latency numbers in [Results](#results) therefore represent one recorded run and
  have not been validated for run-to-run stability.

- **What was actually run, once, for real, this milestone:** 1000 requests × 2 workloads ×
  concurrency 10, with 50 warm-up requests discarded per workload, against a live Docker Compose
  deployment under WSL2, with zero transport errors. The recorded command was:

  ```bash
  docker compose run --rm -T --no-deps \
    -v "$PWD:/app" \
    -w /app \
    --entrypoint python \
    support-agent \
    -m evals.bench_pep \
    --requests 1000 \
    --concurrency 10 \
    --warmup 50 \
    --workload both

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

Five decisions, each representing a real trade-off in this codebase rather than a manufactured list:

1. **Fail-closed enforcement over availability.** `pep/proxy.py`'s log-or-deny behavior means that
   if the durable event write fails, the action is denied even when policy would otherwise have
   allowed it (invariant §3.4). *Given up:* availability during an eventstore outage — a legitimate
   agent's calls can be blocked until durable logging is restored. The alternative, allowing the
   action and hoping the event can be recorded later, weakens the auditability of enforcement
   decisions.

2. **One central PEP over direct agent connectivity.** Every tool call is forced through
   `pep/proxy.py`'s `/v1/tool-call`; `agent-net` is configured as `internal: true`, preventing
   workloads attached only to that network from using an alternative external route. *Given up:*
   the PEP becomes a central enforcement point and a potential bottleneck — every agent action
   incurs the network hop and pipeline processing that direct connectivity would avoid. The current
   topology is also not horizontally scaled.

3. **Digest pinning over frictionless image updates.** `identity/issuer.py` records and verifies the
   image digest associated with a service during attestation, and later attestations must satisfy
   the configured digest expectation. *Given up:* routine image replacement can require an
   intentional digest-pin update or reset rather than automatically accepting a new image. This
   adds an operational step, but prevents an unexpected image change from silently becoming a
   trusted workload.

4. **Stateful risk and taint tracking over stateless horizontal scalability.**
   `risk/scorer.py` tracks state such as novelty, rate-window, and bigram history, while
   `pep/pipeline.py` maintains session-taint state. These mechanisms are currently in-memory and
   process-local. *Given up:* running multiple PEP replicas without an external shared-state
   mechanism would give each replica only a partial view of this state. That creates a real
   scaling limitation for the current implementation and is one reason the topology is not
   production-ready as-is.

5. **Strict explicit-deny-first policy over developer flexibility.** `policy/engine.py` evaluates
   explicit `DENY` rules before explicit `ALLOW`, with unmatched requests falling through to
   default-deny. The policy also includes structural taint restrictions that prevent certain
   writes or secret-class data access when a session is tainted. *Given up:* adding a legitimate
   new capability requires an explicit, reviewed policy rule rather than providing an informal
   "just let this through" escape hatch. That creates friction during development, but keeps
   capability grants deliberate and auditable.

---

## Decision lattice — implementation status

`DENY < QUARANTINE < REQUIRE_APPROVAL < RATE_LIMIT < ALLOW_REDACTED < ALLOW` is the full decision
lattice (`AGENTFW_CONTEXT.md` §2). Not every point on the lattice has real enforcement behavior
behind it yet. This table is the honest implementation status — not simply which values the policy
engine can represent.

| Decision | Status | What actually happens |
| --- | --- | --- |
| `DENY` | Implemented | The action does not execute. The decision and reason are recorded in the eventstore. |
| `ALLOW` | Implemented | The action is permitted to proceed through the PEP. |
| `ALLOW_REDACTED` | Implemented | The action is permitted with the DLP redaction behavior associated with the result. |
| `QUARANTINE` | Implemented | The action does not execute, and the agent's stable identity is added to the quarantine state persisted by the eventstore (`events/app.py`'s `/quarantine` routes). Subsequent calls from a quarantined identity are denied with `reason=AGENT_QUARANTINED` until the quarantine is explicitly cleared. The quarantine state is persisted outside the PEP process and therefore survives a PEP restart. |
| `RATE_LIMIT` | **Designed, not implemented** | The decision exists in the lattice and can be produced by the risk/scoring path, but there is currently no independent throttling mechanism such as a token bucket or enforced per-agent request-rate cap. A request receiving `RATE_LIMIT` therefore does not currently provide production-style rate limiting. |
| `REQUIRE_APPROVAL` | **Designed, not implemented** | The decision exists as a lattice state, but there is currently no approval queue, notification mechanism, or human-in-the-loop workflow that can approve and resume the action. It should therefore be treated as an unimplemented workflow state rather than a functioning approval system. |

---

## Limitations

- **`REQUIRE_APPROVAL` has no approval workflow.** The decision state exists and can prevent the
  action from executing, but there is currently no approval queue, notification mechanism, timeout
  policy, or human-in-the-loop UI for approving or rejecting the request. It should therefore be
  treated as an unimplemented workflow state rather than a functioning approval system.

- **`RATE_LIMIT` is not real throttling.** There is currently no independent token bucket,
  per-agent request cap, or equivalent throttling mechanism enforced by the decision. The lattice
  position and narrowing logic are real; production-style rate limiting is not implemented.

- **The M3/M4 security evaluation is corpus replay, not production traffic.** The evaluation uses
  66 hand-authored attack records and 65 benign records, replayed through the real pipeline code.
  This is a controlled security test, not a sample of real agent behavior in the wild. See the
  hostile-review section of the M4 report for the full skeptical treatment of what this does and
  does not prove.

- **The corpus was authored by the same process that built the firewall**, with full knowledge of
  `policy/bundles/default.yaml`'s rules. A benign/attack split constructed independently by someone
  without visibility into AgentFW's internals would provide stronger evidence of generalization.

- **`evals/score.py`'s evaluation clock is synthetic** (`offset_seconds`,
  `risk.scorer.set_clock()`). This is necessary so a sub-second replay loop does not manufacture
  its own `RATE_ANOMALY` signal, but it means rate-anomaly timing in the evaluation reflects
  hand-chosen inter-arrival times rather than observed real-world traffic patterns.

- **`risk/baseline.jsonl`'s seed data is hand-authored**, not sampled from real usage, and was
  specifically extended during M3 to cover destinations exercised by the evaluation corpus. See
  the hostile review for the skeptical interpretation of that sequencing.

- **The threat-intelligence list is a tiny local file**
  (`threat_intel/lists/malicious_fqdns.txt`) with two entries. There is no external threat-intel
  feed integration or automatic update mechanism.

- **There is no claim of complete prompt-injection detection or complete agent-compromise
  prevention.** AgentFW's design assumes that an agent can be compromised and focuses on bounding
  the resulting blast radius through identity, policy, taint, and DLP. A6 demonstrates containment
  of one indirect-prompt-injection sequence; it does not establish coverage of prompt-injection
  techniques outside the tested scenarios.

- **The live Docker performance benchmark has been run once, not repeatedly.** Real measurements
  exist (see [Results](#results)), but no run-to-run variance has been collected. The benchmark
  also ran on a single-machine Docker-under-WSL2 deployment, which is not representative of a
  production multi-host network. See [Benchmark methodology](#benchmark-methodology).

- **The corrected live attack verification is not a 9/9 claim.** A1, A2, and A4–A9 were genuinely
  verified against the deployed Docker stack at their claimed mechanisms, giving **8 of 9**
  independently verified attacks. A3 remains `UNVERIFIED` by design because the required
  `admin_agent` workload has no deployed Compose service. A10 is a separate quarantine-cascade
  demonstration and its latest run did not confirm the intended cascade. See
  [Attack verification, corrected methodology](#attack-verification-corrected-methodology-c1c2-fix)
  and `docs/verification-log.md`.

- **The PEP does not currently scale horizontally.** Risk and session-taint state are in-memory
  and process-local. Running multiple PEP replicas without an external shared-state mechanism
  would give replicas only partial visibility of that state. See Design decision 4.

- **Identity's Docker-socket attestation gives the `identity` container visibility into every
  container on the host's Docker daemon**, not just containers belonging to this project. This is
  an intentional trade-off in the current architecture: it avoids requiring Kubernetes-style
  infrastructure while accepting broader Docker-daemon visibility
  (`AGENTFW_CONTEXT.md` §2).

- **The current deployment is a development/demo topology, not a production deployment.** There
  is no horizontal PEP scaling, no external shared state for risk/taint tracking, no external
  threat-intelligence feed, and no production-grade approval workflow. The project's security
  evidence should therefore be interpreted as reproducible prototype-level enforcement evidence,
  not as a claim of production readiness.

---

## Future Goals:

1. **Approval workflow for `REQUIRE_APPROVAL`** — build an approval queue, a timeout-to-deny
   policy, and a human-facing interface for approving or rejecting requests. This is currently
   the least-finished decision state in the lattice.

2. **Real rate limiting for `RATE_LIMIT`** — implement an enforced token bucket, per-agent quota,
   or equivalent throttling mechanism so `RATE_LIMIT` represents actual request control rather
   than only a lattice state.

3. **Stronger identity lifecycle** — add issuer signing-key rotation with a defined transition
   period and key-versioning strategy, and develop an attestation mechanism that does not depend
   on direct access to a host Docker socket when deploying beyond a single trusted host.

4. **A larger, independently sourced evaluation corpus** — add attack and benign records authored
   or reviewed independently of `policy/bundles/default.yaml` so the evaluation tests
   generalization rather than primarily testing scenarios designed with knowledge of the policy.

5. **External threat-intelligence integration** — replace the small local threat-intelligence list
   with an updateable external feed and define how feed freshness, failures, and trust are handled.

6. **Distributed state for risk and taint scoring** — introduce shared state once horizontal PEP
   scaling is required, so novelty, rate-window, bigram, and session-taint information remains
   consistent across replicas. A shared store such as Redis could be evaluated at that stage rather
   than introducing distributed infrastructure prematurely.

7. **Observability** — extend the existing structured event log and Streamlit dashboard with
   production-oriented metrics, tracing, and a time-series backend for latency, decisions,
   denials, quarantine events, and other operational signals.

8. **Production hardening** — strengthen secrets management beyond `.env`, formalize signing-key
   lifecycle management, harden administrative surfaces, and replace the current Docker-socket
   attestation trust model before deploying beyond a single trusted host.

9. **Performance scaling** — after the PEP can run with shared state across multiple replicas,
   repeat the benchmark under sustained concurrent multi-agent load and measure throughput,
   tail latency, and run-to-run variance rather than relying only on the current controlled
   single-container benchmark.

---
