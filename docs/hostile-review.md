# Hostile senior-engineer review (M4)

A self-review of the entire repository, written as if by a skeptical senior security engineer
evaluating this project for a hire. **Nothing here has been fixed as part of writing it** — per
this milestone's own rule, the point is to produce the list, not to immediately patch it. Every
finding below is real: verified against the actual current code, not assumed or extrapolated.

Severity: **CRITICAL** (undermines a core security or evaluation claim) / **HIGH** (real gap, real
exploit/failure scenario, bounded blast radius) / **MEDIUM** (real but narrower, or already
partially mitigated) / **LOW** (hygiene, polish, or a documented-and-accepted trade-off worth
restating for completeness).

---

## CRITICAL

### C1 — Attack scripts' "REAL_DOCKER_VERIFIED" status can be true for the wrong identity

**Finding:** `attacks/common.py`'s `try_live_pep_call()` posts to `/attest` with no parameters —
correct, since `identity/issuer.py`'s `/attest` is deliberately unauthenticated and derives
identity entirely from the caller's real source IP (`_lookup_caller_container()`). But this means
an attack script's live path can only ever attest as *whichever container actually invokes it*,
never as the `role`/`service` the script's own Python variables claim to simulate. When
`attacks/run_all.py` runs from one container, `A2`/`A3`/`A5`/`A8` (written as `finance_agent`,
`admin_agent`, `support_agent`, `finance_agent`) get evaluated under the real caller's real role,
not their claimed one — yet still print `verification_status: REAL_DOCKER_VERIFIED` and a
hardcoded `identity: role=..., ... (genuinely signed token)` string that was never checked against
what the live token actually contained.

**Why it matters:** this is the exact class of thing this whole project's own methodology exists
to catch and refuse to fabricate — and it shipped anyway, undetected until reading real Docker
output line-by-line during M4 (see `docs/verification-log.md` Verification 5). It directly weakens
any claim of the form "N attacks, each independently verified live, each with its own distinct
identity" — that claim is not true as stated for 4 of the 9 scripts when run from a shared
container.

**Evidence:** `admin_agent` has no `AGENT_REGISTRY` entry at all (`identity/issuer.py`); A3 (written
as `admin_agent`) still reported `REAL_DOCKER_VERIFIED` in the real run recorded in Verification 5
— which is only possible if the real caller attested as something else entirely.

**File/function:** `attacks/common.py` — `try_live_pep_call()`; every `run()` function in
`attacks/a2.py`, `a3.py`, `a5.py`, `a8.py` that hardcodes an `identity_desc` string.

**Exploit/failure scenario:** not an attacker-facing exploit — an *evaluation-integrity* failure.
A reviewer who trusts the printed `REAL_DOCKER_VERIFIED` label and identity string without
independently checking the underlying mechanism would believe more was proven live than actually
was.

**Impact:** undermines the credibility of the "9/9 blocked, live Docker" headline claim specifically
for role/identity diversity, not for the aggregate denial outcome (which remains true).

**Suggested future direction (not applied):** either (a) run each attack script from inside the
container matching its own claimed role, or (b) have `try_live_pep_call()` read back the token's
actual claims and compare them against the script's stated role, downgrading to a distinct status
(e.g. `REAL_DOCKER_VERIFIED_WRONG_IDENTITY`) rather than a plain pass when they don't match.

**Affects an interview claim:** yes, directly — "9/9 attacks independently verified live" needs the
caveat from Verification 5 attached every time it's said out loud.

---

### C2 — Quarantine cascade silently substitutes one mechanism for another across a shared run

**Finding:** `pep/pipeline.py`'s quarantine gate runs before stage 3 (policy) and is absolute —
once a workload is quarantined, every later call from it is denied `reason=AGENT_QUARANTINED`
regardless of what stage 3–7 would otherwise say. `attacks/run_all.py` runs all nine attacks in one
process against one persistent eventstore. In the recorded real run (Verification 5), six of nine
attacks (A1, A2, A3, A4, A5, A7) showed `AGENT_QUARANTINED` as their live reason, not the specific
mechanism each is individually built to demonstrate.

**Why it matters:** the security *outcome* (denied) is unaffected and arguably strengthened
(defense-in-depth), but the *evaluation claim* — "this attack demonstrates mechanism X" — is false
for those six specifically, in that specific run. A less careful write-up would have reported "9/9
blocked, each confirming its own claimed control" without noticing the printed reason didn't match
the printed "stopping stage."

**Evidence:** `docs/verification-log.md` Verification 5, full real output, `AGENT_QUARANTINED`
appearing starting on A1 — the very first call of that run, meaning the quarantine entry predated
this run entirely (persisted from an earlier, untracked session).

**File/function:** `pep/pipeline.py` — the quarantine gate block (`if quarantined: return
_deny_early("AGENT_QUARANTINED", "QUARANTINE_DENY", ...)`), which runs unconditionally before
`evaluate()`/`evaluate_east_west()`.

**Exploit/failure scenario:** none attacker-facing — this is an evaluation-methodology failure
mode, not a security one. (Arguably the *opposite* of a security weakness: quarantine backstopping
individual gaps is a stronger real-world property.)

**Impact:** the per-attack "which control stopped this" narrative is not independently
re-verifiable from a single `run_all.py` invocation once any workload has been quarantined by an
earlier attack in the same run or a prior session.

**Suggested future direction (not applied):** release all workloads from quarantine
(`docker compose exec pep curl -X DELETE http://eventstore:8090/quarantine/<workload>`) immediately
before a verification run intended to demonstrate individual mechanisms, and/or have `run_all.py`
release quarantine automatically at the start of its own run (though that itself would need
justifying — auto-releasing quarantine before every test run has its own security-hygiene
downside for a real deployment).

**Affects an interview claim:** yes — same as C1, attached to the "9/9 blocked" headline.

---

## HIGH

### H1 — PEP's cached issuer public key goes stale on an identity-only restart, breaking all authentication until the PEP is also restarted

**Finding:** `pep/pipeline.py`'s `_get_issuer_public_key()` fetches the issuer's public key once
and caches it in a module-level global (`_ISSUER_PUBLIC_KEY`) for the PEP process's entire
lifetime — never refreshed, never invalidated. `identity/issuer.py` generates a fresh Ed25519
keypair on every process start (`_PRIVATE_KEY, _PUBLIC_KEY = generate_keypair()` at module scope) —
an accepted, documented trade-off in isolation. But the combination means: if `identity` restarts
(container recreation, crash-restart, redeploy) without the `pep` container *also* restarting, the
PEP goes on verifying every token against the *old* public key, and every genuinely valid new token
fails signature verification — a full authentication outage for every workload, triggered by a
restart of a component that isn't the PEP itself, with no automatic recovery short of restarting
the PEP too.

**Why it matters:** this is a real availability cliff that isn't named anywhere in the existing
docs (which name "issuer restart invalidates outstanding tokens" but not "issuer restart while the
PEP keeps running silently poisons the PEP's cache for its entire remaining lifetime").

**Evidence:** confirmed by reading both sides directly — `pep/pipeline.py`'s
`_get_issuer_public_key()` (`if _ISSUER_PUBLIC_KEY is None:` — the only invalidation condition is
"never fetched yet") and `identity/issuer.py`'s module-level `generate_keypair()` call.

**File/function:** `pep/pipeline.py` — `_get_issuer_public_key()`; `identity/issuer.py` (module
scope, `_PRIVATE_KEY, _PUBLIC_KEY = generate_keypair()`).

**Exploit/failure scenario:** not attacker-triggered — an operational failure mode. A routine
`docker compose restart identity` (or `up -d --force-recreate identity`, exactly the command used
in Verification 3's own recorded testing) silently breaks every subsequent attestation-dependent
call until someone thinks to restart `pep` too. The failure is loud in the sense that every call
starts failing with `identity_verification_failed`, but the *root cause* (a stale cached key) is
not obvious from that message alone.

**Impact:** full-system unavailability for all workloads, recoverable only by restarting a
different container than the one that actually failed — a genuinely confusing on-call scenario.

**Suggested future direction (not applied):** either persist and version the issuer's signing key
(named as a "what I'd do next" item already) or have the PEP re-fetch on a verification failure
before giving up, with a bounded retry.

**Affects an interview claim:** yes, if asked about operational resilience or "what happens when a
component restarts" — this is a concrete, specific answer that should be given proactively if the
identity-restart trade-off comes up, not just the "tokens get invalidated" framing already in the
docs.

---

### H2 — Docker-socket failures during attestation are unhandled, producing a raw 500 instead of a clean, logged denial

**Finding:** `identity/issuer.py`'s `/attest` handler calls `info = await
_lookup_caller_container(source_ip)` with no surrounding `try`/`except`. If the underlying Docker
API call fails for any reason other than "no match found" (socket unreachable, malformed response,
timeout — `_lookup_caller_container()`'s own `resp.raise_for_status()` can raise), the exception
propagates unhandled out of the route handler. FastAPI's default behavior converts that into an
HTTP 500, not the clean 403 + `_log_attestation_denial()` every *other* failure path in this same
function produces.

**Why it matters:** every other denial path in `identity/issuer.py` is loudly, attributably logged
(`_log_attestation_denial`, matching `pep/bypass_proxy.py`'s M1-gap-#3 precedent this whole project
otherwise takes seriously). This one specific failure mode — arguably the most operationally likely
one, since it's triggered by infrastructure flakiness, not a malicious caller — bypasses that
pattern entirely.

**Evidence:** read directly, `identity/issuer.py` lines 126–144 — no exception handling around the
`_lookup_caller_container` call, in contrast to the deliberate `try`/`except (sqlite3.Error,
OSError)` a few lines later for the digest-pin lookup.

**File/function:** `identity/issuer.py` — `attest()`.

**Exploit/failure scenario:** Docker socket permission issues, daemon restarts, or any transient
Docker API hiccup during an attest call produces an unhandled 500; the calling agent's
`agent/tools.py`'s `_attest()` does `resp.raise_for_status()`, which raises and crashes the agent
process entirely (an unhandled exception, not a graceful denial the agent's own error handling
expects).

**Impact:** technically fails closed (nothing executes), but ungracefully — no security event is
logged for this failure mode, and the agent process crashes rather than reporting a clean denial.

**Suggested future direction (not applied):** wrap the `_lookup_caller_container` call in a
`try`/`except` that logs via `_log_attestation_denial` and returns a clean 403, consistent with
every other failure path in the same function.

**Affects an interview claim:** yes, if asked "does everything fail closed" — the honest answer is
"yes, but not always gracefully," and this is the concrete example.

---

### H3 — No horizontal scaling for the PEP; risk/taint state is single-process

**Finding:** `risk/scorer.py`'s novelty/rate/bigram tracking and `pep/pipeline.py`'s
`_SESSION_TAINT` are in-memory, per-process globals. Running more than one PEP replica would give
each replica a partial, inconsistent view of both risk history and session taint.

**Why it matters:** this is already disclosed in the README (Design decision 4, Limitations) — not
a hidden gap. Listed here for completeness and because it's the single most consequential scaling
limitation, worth being able to name precisely rather than gesture at.

**Evidence:** `risk/scorer.py`'s own module docstring ("behavioral factors... approximated from
in-memory, single-process state"); `pep/pipeline.py`'s `_SESSION_TAINT: dict[str, bool] = {}` at
module scope.

**File/function:** `risk/scorer.py` (module-level state dicts); `pep/pipeline.py` —
`_SESSION_TAINT`.

**Exploit/failure scenario:** not an exploit — a scaling ceiling. Two PEP replicas behind a load
balancer would each independently think every destination is novel and could see different taint
state for the same session depending on which replica handled which call.

**Impact:** real ceiling on production readiness — see README's "not production-ready" framing.

**Suggested future direction (not applied):** shared external state (Redis or similar) once
horizontal scaling is actually needed — already listed in "What I'd do next."

**Affects an interview claim:** yes, but already proactively disclosed — this finding exists mainly
to confirm the disclosure is accurate and complete, not to surface something new.

---

## MEDIUM

### M1 — `RATE_LIMIT` executes identically to `ALLOW`; the name overstates what happens

**Finding:** already disclosed in the README's decision-lattice table, restated here because a
hostile reviewer would flag it independently: `RATE_LIMIT` is a lattice position with no actual
throttling behind it. Any metric or interview claim that says "rate-limited" without immediately
qualifying it risks implying enforcement that doesn't exist.

**File/function:** `policy/engine.py` — `EXECUTABLE_DECISIONS` (includes `RATE_LIMIT`).

**Impact:** medium, not high, specifically because it's already disclosed prominently and
consistently (README table, this document, the M3/M4 metric naming — `throttle_rate`, explicitly
labeled "designed-not-implemented" everywhere it's printed).

**Suggested future direction (not applied):** a real token-bucket or per-agent rate cap — already
listed in "What I'd do next."

**Affects an interview claim:** yes, but the existing disclosure already handles it correctly.

### M2 — No dependency vulnerability scanning

**Finding:** `requirements.txt` pins exact versions (good hygiene) but nothing in CI runs
`pip-audit`, `safety`, or equivalent, and there's no Dependabot/Renovate configuration. A known CVE
in `fastapi`, `cryptography`, or any of the other 10 pinned packages would not be caught
automatically.

**File/function:** `.github/workflows/ci.yml` (no audit job); `requirements.txt`.

**Impact:** standard hygiene gap, low urgency for a portfolio-scale project, real for anything
closer to production.

**Suggested future direction (not applied):** add a `pip-audit` step to CI — doesn't cost a
dependency-budget slot (dev-only tooling, same category as `ruff`).

**Affects an interview claim:** minor — worth a proactive one-liner if asked about supply-chain
hygiene, not otherwise load-bearing.

### M3 — `threat_intel`'s list is two entries, no external feed

**Finding:** already disclosed in the README/threat-model — `threat_intel/lists/malicious_fqdns.txt`
has exactly two entries (`evil.example.com`, `known-c2.example`), both used by the M3 corpus and
attack scripts themselves. There's no update mechanism and no external feed integration.

**File/function:** `threat_intel/feed.py` — `is_known_bad()`; `threat_intel/lists/malicious_fqdns.txt`.

**Impact:** stage 4 provides zero real-world protection against any destination not already on this
tiny static list — it demonstrates the *mechanism*, not real threat coverage.

**Suggested future direction (not applied):** external feed integration — already listed in "What
I'd do next."

**Affects an interview claim:** yes, and already disclosed — worth being ready to say "this proves
the pipeline stage works, not that the list is useful" without prompting.

### M4 — CI has never actually run

**Finding:** `.github/workflows/ci.yml` is real, well-structured (lint/policy/test jobs, correct
`LLM_PROVIDER=mock` gating) — but this repository has no configured git remote and has never been
pushed to GitHub, so the workflow has literally never executed. A CI badge would 404.

**File/function:** `.github/workflows/ci.yml`; repo has no `git remote`.

**Impact:** "CI is green" is not a claim that can currently be made — only "a CI workflow exists and
passes when run locally in the same way CI would run it" (which was independently verified this
session via the local venv test loop).

**Suggested future direction (not applied):** push to GitHub, confirm the workflow actually runs
green on a real Actions runner (subtly different environment than the local venv testing done so
far — worth confirming, not assuming).

**Affects an interview claim:** yes — "CI passes" needs the caveat "locally verified the same way,
never run on an actual GitHub Actions runner" until it's pushed.

### M5 — `evals/bench_pep.py`'s numbers are entirely unmeasured

**Finding:** built and mechanically smoke-tested this milestone, but never run against a real
Docker deployment (no Docker available in this working environment). The entire Performance section
of the README's Results table reads `NOT MEASURED`.

**File/function:** `evals/bench_pep.py`.

**Impact:** the single most important technical measurement this milestone asked for is
structurally incomplete — not fabricated, not estimated, genuinely absent, and stated as such.

**Suggested future direction (not applied):** run it — the exact command is in the README.

**Affects an interview claim:** yes, directly — there is currently no defensible latency claim for
the live deployed PEP, only for the in-process replay, which is explicitly labeled as such
everywhere it's used.

---

## LOW

### L1 — `email.send`/`db.query`/`file.read` have no real backend

**Finding:** already disclosed (`pep/proxy.py`'s `_execute()` docstring) — three of six tools
return a labeled canned result rather than performing a real action. Only `http.get`/`http.post`
genuinely call out, because `pep` is the only dual-homed container and faking that would undercut
the one thing that has to be real.

**Impact:** low — deliberately scoped, clearly labeled, not misrepresented anywhere.

**Affects an interview claim:** minor — worth knowing precisely which tools are real vs. mocked if
asked to demo one of the mocked ones live.

### L2 — Event log has no cryptographic integrity (no hash chaining/signing)

**Finding:** events are append-only at the application layer (no UPDATE/DELETE route), but nothing
prevents direct filesystem/SQLite-level tampering with the durable log by a party with host access.

**File/function:** `events/store.py` — `write_event()`.

**Impact:** low for this project's stated scope (single trusted host, portfolio demo); would matter
more if this log were ever treated as a compliance-grade audit trail.

**Affects an interview claim:** minor — a reasonable "what would you add for a real audit trail"
answer if asked.

### L3 — Only one instrumented latency reading has ever been collected per number (no repeated-run variance)

**Finding:** every latency figure in this project (in-process and, once collected, live-Docker) so
far represents a single run, not a distribution across multiple runs — the M3/M4 methodology
sections don't yet report run-to-run variance.

**Impact:** low — the numbers are real measurements, just not yet characterized for stability.

**Affects an interview claim:** minor — "have you checked run-to-run variance" is a fair follow-up
with an honest "not yet" as the answer.

---

# 5A — Baseline seeding: the skeptical argument, in full

**Where it comes from:** `risk/baseline.jsonl`, 240 hand-authored lines (originally 200, extended
mid-M3 — see below), replayed by `RiskScorer.warm_up()` at process start into
`risk/scorer.py`'s `_SEEN_BY_ORG`/`_SEEN_BY_AGENT` state.

**How it's seeded:** every line is `{role, tool, destination_key, agent_id?}` — `agent_id` present
only for the three registered workloads (`agent`/`finance-agent`/`support-agent`); `admin_agent`
lines seed org-level novelty only, since it has no registered identity.

**Whether it covers allowed destinations:** yes, now — but only *because* it was specifically
extended mid-M3, after the evaluation corpus was already built, to cover destinations that corpus
touches (three more `*.arxiv.org` subdomains, one more `*@approved-helpdesk.com` sender) that the
original 200-line baseline didn't have.

**Whether it's agent-specific:** yes, for the three registered workloads; no, for `admin_agent`
(org-level only).

**The skeptical argument, stated explicitly:** *"A skeptical reviewer could argue that the baseline
was extended specifically to make the evaluation corpus look better, after the corpus was already
built and its gaps were already known — that's uncomfortably close to tuning the test to the
implementation rather than the other way around. Even if no decision *threshold* was changed, the
*input data* (the baseline) was changed in direct response to seeing bad evaluation numbers, by the
same person/process that built both the firewall and the corpus. A truly independent evaluation
would have a baseline that predates and is blind to the specific corpus it's later measured
against."*

**The strongest defense:** the baseline extension didn't invent seen-ness for destinations that
were never legitimately used — every added line represents a destination a *real, registered*
agent's *own charter* genuinely allows (`*.arxiv.org` for `research_agent`,
`*@approved-helpdesk.com` for `support_agent` — both real policy-bundle rules, not corpus-specific
carve-outs). The change is more accurately described as "the original 200-line baseline had an
incomplete sample of an agent's own already-allowed destinations" than "the baseline was expanded
to cover attack traffic" — attack-corpus destinations were deliberately left unbaselined and
still, correctly, score as novel. The bug this extension partly addressed (see `AGENTFW_CONTEXT.md`'s
M3-correction entries) was independently, mechanically diagnosable — `RiskScorer.warm_up()` state
being wiped immediately after being built — and would have needed the *same* baseline-coverage fix
regardless of which specific corpus was used to notice it.

**Residual uncertainty:** the defense above establishes that the extension was principled (real
charter-allowed destinations, not corpus-specific tuning) — it does not establish that a
*differently-authored* baseline, built by someone with no visibility into what the eval corpus
would eventually contain, would show the same numbers. That comparison has not been made and can't
be, retroactively, with this project's history. The honest position is: the baseline-coverage fix
is defensible on its own logic, and the false-positive-rate improvement it produced (3.1% → 0.0%)
is real given that logic — but the fact that the same person who builds the firewall, writes its
baseline, and authors its eval corpus is also the one deciding what counts as "legitimately
covered" is a structural conflict of interest this project cannot fully resolve internally, no
matter how principled any single decision within it was.

---

# 5B — Synthetic clock: the skeptical argument, in full

**Why it exists:** `evals/score.py`'s `replay_corpus()` iterates 65+ records in well under a second
of real wall-clock time. `risk/scorer.py`'s `RATE_ANOMALY` factor (`>5 calls/60s`) reading the real
clock would make the replay loop's own speed the dominant driver of the anomaly signal, independent
of the underlying traffic's actual shape — a real bug this milestone's own history found and fixed
(`AGENTFW_CONTEXT.md`'s M3-correction entries).

**Whether RATE_ANOMALY behavior depends on it:** entirely — `risk.scorer.set_clock()` is the only
thing standing between "the factor means something" and "the factor fires on almost everything,
uninformatively," as the pre-fix numbers directly demonstrated (96.9%→90.8% friction, later traced
to this exact mechanism among others).

**Whether it creates an unrealistic advantage:** potentially, yes — the clock values
(`offset_seconds`) are hand-chosen per corpus record, by the same process that built the firewall
being measured, using ranges explicitly picked to produce realistic-*sounding* behavior (e.g.
"research browsing: 180–420s apart," "attack bursts: 1.5–4s apart, per compromised service").
Nothing external validates that these specific ranges match real agent traffic timing.

**Whether attack and benign records receive equivalent treatment:** by construction, no — attack
records were deliberately given tight per-service burst spacing ("the burst IS the attack"); benign
records were deliberately given wide, human-work-pattern spacing. This is stated, intentional, and
disclosed (`evals/score.py`'s own module docstring, the corpus generator's comments) — it is not a
hidden asymmetry. But it means the resulting metric (`RATE_ANOMALY` firing 69.7% on attack vs. 4.6%
on benign) is, by design, measuring how well the corpus *author* modeled the difference between
attack and benign timing — not an emergent property discovered from neutral data.

**Whether the temporal distribution is realistic:** unverified against any real traffic sample —
there is no real deployment traffic to compare against. The ranges are plausible on their face
(research browsing genuinely isn't sub-second; a rapid-enumeration attack genuinely often is) but
"plausible on its face" is not the same claim as "validated against observed behavior."

**Whether the benchmark could be gamed by selecting favorable offsets:** yes, mechanically — nothing
prevents choosing offsets that make `RATE_ANOMALY` fire exactly where wanted. The defense against
this is not technical, it's that the offsets were chosen *before* seeing per-record results (the
generator script assigns them programmatically by category, not by hand-picking individual records
to hit a target number) — but that defense is procedural and trust-based, not independently
auditable after the fact.

**The strongest defense:** the clock's *existence* fixes a real, mechanical bug (a benchmark
measuring its own loop speed instead of the data) — that part is unambiguous and verifiable by
reading `evals/score.py`'s before/after code. The *specific offset values* are a modeling choice,
openly disclosed as such, consistent with how the corpus's own categories were already described
before offsets existed (e.g. "legit_repeated_calls" was already named and described as
adversarial-timing-relevant before this round of work). It is not hidden that the timing model is
authored, not observed.

**Residual uncertainty:** whether a differently-timed but equally "plausible" set of offsets would
produce a meaningfully different `RATE_ANOMALY` split has not been tested (no sensitivity analysis
across alternative timing models). The 69.7%/4.6% split is real for *this* timing model; its
robustness to a different, equally reasonable one is unknown.

---

# 5C — Corpus construction: what it proves and doesn't

**How records were generated:** programmatically, via a hand-written generator script (not
committed — `evals/corpus_attack.jsonl`/`corpus_benign.jsonl` are the committed, hand-reviewed
output), with per-category parameter lists (destinations, tools, roles, payloads) authored by the
same process that built `policy/bundles/default.yaml`.

**Diversity/category coverage:** 7 attack categories (unauthorized_destination, exfiltration,
privilege_escalation, injection_driven_action, credential_access, lateral_movement,
dlp_triggering_payloads), 10 benign categories — reasonable breadth for a hand-authored corpus of
this size, not large enough to claim statistical representativeness of "real agent behavior" in any
general sense.

**Agent/destination/policy distribution:** all four roles represented; destinations span both
registered-workload charters and deliberately out-of-charter targets; every attack record maps to
a specific, identifiable policy rule or default-deny path — which is itself worth flagging (see
below).

**Whether attack examples are too close to policy rules:** yes, largely by necessity and partly by
convenience. Every attack record was authored with `policy/bundles/default.yaml` open — destinations
and resources were chosen specifically *because* they're known to fall outside a role's charter,
not discovered to be so. This makes the corpus excellent at proving "the policy engine correctly
denies what it's supposed to deny" and weak at proving "the firewall generalizes to attack shapes
its author didn't specifically anticipate."

**Whether benign examples are genuinely adversarial:** partially. Several categories were
deliberately built to be hard (`legit_repeated_calls`, `legit_sensitive_looking_text`,
`legit_large_payload`, `legit_encoded_data`) and did surface real friction (the 52.3% throttle rate
is not a soft number) — that's a genuine, non-trivial adversarial property. But "adversarial" here
means "adversarial to this specific implementation's known soft spots" (cold-start novelty scoring,
regex/entropy DLP), authored by someone who knows exactly what those soft spots are — not
adversarial in the sense of an independent red-teamer trying to find *unknown* soft spots.

**Whether the same templates appear repeatedly:** no exact duplication, but structural
repetition is real — e.g. `dlp_triggering_payloads`' 12 records are 12 different secret *shapes*
posted to the *same* one or two endpoints; `legit_post_put`'s 6 records are the same tool/rule with
varied dollar amounts. This is reasonable for exercising a specific mechanism repeatedly, but it
means "66 attack records" is not "66 independently-conceived attack scenarios" — several are
structural variations on a smaller number of underlying ideas.

**Whether the corpus was authored with knowledge of AgentFW internals:** yes, fully — this is not
disputable and is stated plainly in the README's Limitations. Every record's expected outcome was
knowable in advance from reading the policy bundle and pipeline code.

**Whether labels are independent:** no — there is no held-out labeler; the same process authored
the record, predicted its outcome, and (in `evals/score.py`) computes whether that outcome actually
happened. There is no blinding of any kind.

**Whether any examples were tuned after seeing results:** the *baseline* was extended after seeing
results (see 5A) — the *corpus itself* was not altered after seeing block-rate/false-positive
numbers, as far as this project's own commit history shows; the fixes applied were to the
evaluation harness (reset-order bug, synthetic clock) and the baseline, not to corpus record
content or count.

**Whether the corpus is representative of real agent behavior:** no claim of this is made or
defensible — 131 total hand-authored records is a controlled test corpus, not a sample of observed
production traffic.

**What this corpus proves:** that the implemented mechanisms (default-deny, DLP regex/entropy
detection, east-west default-deny, taint ceiling, threat-intel lookup, normalization,
bypass-listener denial) function correctly against a diverse set of *known* attack shapes and
correctly avoid blocking a deliberately-hard set of *known* benign shapes, when replayed through
the real pipeline code.

**What this corpus does NOT prove:** that AgentFW generalizes to attack techniques its own author
didn't anticipate; that the false-positive rate would hold against real, organically-occurring
benign traffic; that the corpus is free of the specific bias that comes from one party authoring
firewall, baseline, and test simultaneously.

**Could a skeptical interviewer claim the benchmark favors AgentFW? Yes — write the strongest
version:** *"This isn't an evaluation, it's a demonstration. The same person who wrote the
detection rules wrote the test cases the detection rules are checked against, knew exactly which
rule each attack record would trip before writing it, and adjusted the historical baseline when
the benign numbers looked bad. A 98.5% block rate and 0.0% false-positive rate on a corpus built
this way is closer to a unit-test suite passing than to a security product's measured
effectiveness. The real question — does this generalize to attacks the author didn't think of, and
does it stay usable against real, messy, organic traffic — is not answered by this evaluation at
all."* That argument is largely correct and is not rebutted anywhere in this project; the honest
response is to agree with its scope-limiting claim explicitly (as this document and the README
both now do) rather than argue the corpus is more than it is.

---

# 5D — Metric interpretation review

- **Block rate / false-positive rate:** consistently defined as "landed on `DENY` or `QUARANTINE`"
  (`policy.engine.BLOCKED_DECISIONS`) — unambiguous, consistently applied in `evals/score.py` and
  every attack script's `AttackResult.blocked` property.
- **`DENY` vs `RATE_LIMIT` vs `REQUIRE_APPROVAL` — treated consistently?** Yes, and specifically
  *because* of the M4-preceding correction: `RATE_LIMIT` and `REQUIRE_APPROVAL` used to be summed
  into one "friction" number, which this project's own review (mid-M3) correctly identified as
  hiding the fact that `RATE_LIMIT` executes and `REQUIRE_APPROVAL` doesn't. Post-correction, the
  two are cleanly separated (`approval_rate`/`throttle_rate`) and neither is folded into
  `false_positive_rate`.
- **Does "blocked" mean actually prevented execution?** For `DENY`/`QUARANTINE`, yes — confirmed by
  `policy.engine.EXECUTABLE_DECISIONS` excluding both. For anything counted as "not blocked"
  (`ALLOW`/`ALLOW_REDACTED`/`RATE_LIMIT`), the action does execute — including `RATE_LIMIT`, which
  is correctly *not* counted as blocked, consistent with it not actually limiting anything.
- **Does `RATE_LIMIT` currently execute normally?** Yes, confirmed (`EXECUTABLE_DECISIONS`
  includes it) and consistently labeled everywhere it's reported (README table, `evals/score.py`'s
  own printed output, this document).
- **Does `REQUIRE_APPROVAL` currently execute or stop?** Stops — confirmed (`EXECUTABLE_DECISIONS`
  excludes it) — but with no workflow to ever let it through, which is itself worth restating: a
  benign call landing here is not "processed with delay," it is "held forever" in the current
  implementation, which is arguably *worse* than a clean deny for a legitimate user, even though it
  correctly counts as non-executed for metric purposes.
- **Could any evaluator label hide a dangerous behavior?** The one identified risk: nothing in
  `evals/score.py`'s aggregate numbers distinguishes "denied by the specific mechanism this record
  was meant to test" from "denied by an unrelated mechanism that happened to also fire" — the same
  class of issue as C2 above, but for the corpus-replay evaluation rather than the live Docker
  attack scripts specifically. `block_rate`/`false_positive_rate` are outcome-based (was it
  blocked, yes/no), not mechanism-based, so this specific ambiguity doesn't corrupt those two
  numbers — but it means neither number should be read as "the DLP detector caught N% of attacks"
  or similar mechanism-specific claims without checking which stage actually fired per record,
  which `evals/score.py` does not currently break out.

---

# 5E — M4 performance methodology review

Reviewed against the same skepticism, even though the numbers themselves are `NOT MEASURED`:

- **Is the workload representative?** Two fixed request shapes (one `db.query`, one `email.send`),
  both from `support_agent`'s own charter. Representative of *a* real request, not of a realistic
  traffic mix across roles/tools — a single-workload-pair benchmark, disclosed as such.
- **Is concurrency realistic?** Default 10, explicitly chosen as "controlled, not a stress test" —
  reasonable for a demo-scale deployment, unvalidated against what a real multi-agent deployment's
  actual concurrent load would look like (no such deployment exists to measure).
- **Is warm-up sufficient?** 50 requests by default — a reasonable, stated default; not derived
  from any measured warm-up curve (e.g., "latency stabilizes after N requests") — it's a round
  number with a stated rationale (connection pool + import caching), not an empirically-tuned one.
- **Is connection reuse affecting results?** Yes, deliberately — one `httpx.AsyncClient` per
  workload run, connection pooling on. This is the right choice for measuring steady-state latency,
  but means the benchmark does not characterize cold-connection cost (each new TCP/TLS setup),
  which a bursty, connection-churning real deployment might see more of.
- **Are denied requests included?** Yes, explicitly and by design (`RequestRecord.outcome` counts
  `deny` separately from `error`, and only `error` — genuine transport failure — is excluded from
  the "did the pipeline run" accounting).
- **Is DLP really exercised?** Yes, by construction rather than by chance — `dlp_exercised` uses a
  rule with `inspect: true` (DLP runs unconditionally, regardless of payload content);
  `dlp_not_triggered` uses a rule/tool combination where the stage-5 gate is structurally false.
  This is a methodologically sound way to guarantee the comparison, not an inference from observed
  timing.
- **Are stage timings instrumented correctly?** Yes — sourced directly from the PEP's own
  `/v1/tool-call` response body (`latency_ms`), which was already being computed and returned for
  every call before this benchmark existed; no new instrumentation was added, none was needed.
- **Are Docker/network costs included?** By design, yes — the benchmark measures client-side
  wall-clock end-to-end latency, deliberately not subtracting network/Docker overhead.
- **Is the sample size sufficient?** 1000 requests per workload by default satisfies this
  milestone's own stated minimum — but this has not actually been run yet (no Docker available),
  so "sufficient" is a statement about the script's default, not about a collected sample.
- **Are multiple runs necessary?** Not yet assessed — see L3 above; no repeated-run variance data
  exists for any latency number in this project yet, in-process or (once collected) live.
- **Could CPU/cache/container state distort the result?** Unaddressed by the current script — no
  CPU pinning, no isolation from other host load, no reported host resource utilization alongside
  the latency numbers. A real confound for any single-run benchmark on a shared development
  machine, not controlled for here.

**Bottom line on 5E:** the *methodology* is sound and the workload construction is methodologically
fair (DLP exercised by construction, not inference) — but it is a methodology that has not yet
produced a single real number, and several of the above (repeated-run variance, host resource
confounds, cold-connection cost) are gaps in the methodology itself, not just in whether it's been
run.
