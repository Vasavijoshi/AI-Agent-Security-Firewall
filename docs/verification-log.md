# Verification log

This is a record of what has actually been run against a live Docker deployment. Each entry is a
real command, its real output, and the security property that output does or doesn't establish.
Where a run found a real failure, the entry says so, how it was diagnosed, and what changed as a
result — this file is a record of what was tested, not a claim that everything works.

**Provenance matters, so it's noted per entry:** Verifications 1–6 were run by the project owner,
on their own machine, with the real output pasted back for me (Claude) to read and diagnose — every
earlier milestone in this project states plainly that I have no Docker in my own working
environment. Verification 7 is different: it was run directly by me, in-session, because Docker
Desktop happened to be reachable through this session's tooling — the first entry in this file
where that's true. That distinction is recorded on the entry itself, not glossed over, since the
absence of it was a standing, repeatedly-stated limitation of this project up to that point.

Seven runs have happened so far. Four found a real problem. That's the point of writing this down
either way: a passing result recorded here is worth more than an assumed one, and a failing result
gets fixed instead of argued about — including a fifth run that reported a clean "9/9 BLOCKED" on
its face but, read carefully, exposed two real problems inside a genuinely passing result, and a
sixth run that independently reconfirms both of those problems from a different angle while also
producing the project's first real live-Docker performance numbers and two new clean positive
confirmations (digest pins matching deployed images; quarantine release working end-to-end).

After the sixth run, a code fix for both of those reconfirmed problems (role-verified per-attack
dispatch; a real quarantine clear/verify step before each independent attack; A10 as a deliberate,
separately-labeled cascade demonstration) was implemented — see "C1/C2 remediation" below. That fix
needed three more real, independently-discovered bug fixes before it actually worked (a host-side
import bug, a Docker-image packaging gap, and a wrong Docker Compose command against a one-shot
container — none found by review, all found by an actual run attempt), and was then run for real: a
**seventh run** (Verification 7), the first to independently confirm the corrected execution model
against a live deployment — 8 of 9 attacks genuinely verified at their own claimed mechanism, A3
correctly and structurally `UNVERIFIED` by design, and A10's quarantine cascade confirmed live for
the first time.

---

## Verification 1 — bypass-catch listener (M1 gap #3)

**What was being checked:** `pep/bypass_proxy.py` (the `:8081` listener HTTP_PROXY/HTTPS_PROXY
point at) denies every request, and that denial is loud and attributable — not just "the
connection failed for some reason."

**Commands run, from inside the agent container:**

```
<an HTTPS request routed through http://pep:8081, via HTTP_PROXY>
```
Real output:
```
Tunnel connection failed: 403 Forbidden
```

```
docker compose logs pep | Select-String "BYPASS_ATTEMPTED"
```
Real output: *(nothing)*

```
docker compose logs pep | Select-String "CONNECT|BYPASS|DENY|evil.com"
```
Real output: *(nothing)*

**What this established:** the listener is reachable on agent-net and does deny the connection —
the first command proves that much.

**Failure found:** the denial was real but invisible in the PEP container's own log. Grepping for
any trace of it turned up nothing, on three different search terms.

**Diagnosis:** `pep/bypass_proxy.py`'s `_log_bypass()` only ever POSTed the event to the
`eventstore` container over HTTP. Nothing was ever written to the PEP process's own stdout — and
it turned out `pep/proxy.py`'s main `_log_event()` had exactly the same gap, for every decision,
not just bypass ones. `docker compose logs pep` was blind to the PEP's own reasoning, full stop.

**Fix:** a single `"agentfw.pep"` logger, configured once in `pep/proxy.py`, shared by
`pep/bypass_proxy.py`. Every event is echoed to stdout *before* the durable-write attempt to
eventstore, so container-log observability doesn't depend on eventstore being reachable either.

**Re-verified after the fix?** Not yet independently re-run via Docker as far as this log has
record of. Recommended re-test:

```
docker compose exec agent curl -m 3 -x http://pep:8081 https://evil.com
docker compose logs pep | Select-String "BYPASS_ATTEMPTED"
```
Expected: a JSON line with `"decision": "DENY", "reason": "BYPASS_ATTEMPTED"`.

---

## Verification 2 — quarantine admin-surface isolation

**What was being checked:** the quarantine release endpoint is unreachable from agent-net, so a
quarantined (possibly compromised) agent can't release itself even though it shares a Docker
network with the PEP. At the time of this test, that endpoint lived on the PEP process itself,
bound to `127.0.0.1`.

**Command run, from inside the agent container:**
```
<a request to the admin port, port 8079>
```
Real output: **HTTP 403 Forbidden**

**What was claimed beforehand:** loopback binding makes the admin port genuinely unreachable —
the expected failure mode for a real test would be connection-refused, not a same-protocol denial.

**Failure found:** HTTP 403 means something answered. Reachable, not refused — directly
contradicting the loopback-binding claim.

**Diagnosis:** the agent container has `HTTP_PROXY=http://pep:8081` set in its environment (per
AGENTFW_CONTEXT.md §5). A plain HTTP client (curl included) honors that variable by default for
*any* HTTP request, regardless of target port — so a request nominally aimed at `pep:8079` was
transparently redirected through the bypass-catch listener on `:8081` instead, which denies
*everything* with a 403 regardless of what was actually asked for. The test never reached — or
failed to reach — port 8079 at all; it tested the proxy-interception path by accident, and that
path's own 403 looked exactly like "the target was reachable and denied," which is a different
claim than the one being tested.

**Fix:** rather than argue about what a proxy-intercepted request does or doesn't prove, the admin
surface (quarantine list/release) moved off the PEP process entirely, onto `events/app.py`'s
`/quarantine` routes. `eventstore` sits on `egress-net` only — `agent-net` has *zero* route there,
no proxy involved, the same network split the project's core non-bypassability claim already
rests on. `pep/admin.py` was deleted.

**Re-verified after the fix?** Not yet. Recommended re-test — this one specifically avoids the
proxy-interception trap that invalidated the first attempt:

```
docker compose exec agent curl -m 3 http://eventstore:8090/quarantine
```
Expected: connection failure (no route — `agent-net` and `egress-net` don't overlap), not a 403.
Compare against a call that *should* work, from a container that has the route:
```
docker compose exec pep curl http://eventstore:8090/quarantine
```
Expected: `{}` (or the current quarantine list) — HTTP 200.

---

## Verification 3 — EXPECTED_DIGEST_AGENT wiring

**What was being checked:** whether `docker-compose.yml` actually passes a manually configured
`EXPECTED_DIGEST_AGENT` value through to the `identity` container.

**Setup:** obtained the real image digest —
```
docker inspect firewall-agent-1 --format "{{.Image}}"
```
— and set `EXPECTED_DIGEST_AGENT=sha256:bb40ec56e8c14f56962e8bb69b6be596efeaa54d1c4c76572ce6cd842b068942`
in the environment intended to configure the `identity` service.

**Commands run:**
```
docker compose up -d --force-recreate identity
docker compose exec identity python -c "import os; print('EXPECTED_DIGEST_AGENT=', os.getenv('EXPECTED_DIGEST_AGENT'))"
```
Real output:
```
EXPECTED_DIGEST_AGENT=
```
Identity's own logs, on the next attestation:
```json
{"event": "attestation_unpinned", "service": "agent", "note": "no EXPECTED_DIGEST_* configured — running unverified"}
```

**Failure found:** the configured value never reached the container — an empty string is what
`${EXPECTED_DIGEST_AGENT:-}` substitutes when Compose sees the variable as unset in its own
environment.

**Diagnosis:** `docker-compose.yml`'s wiring itself was re-read and confirmed correct —
`EXPECTED_DIGEST_AGENT: ${EXPECTED_DIGEST_AGENT:-}` is present and correctly placed under
`identity:`'s `environment:` block. The likely root cause was found by inspecting `.env.example`:
a line carrying the exact digest value above was sitting there, **still commented out**
(`#EXPECTED_DIGEST_AGENT=sha256:...`). Compose only ever reads a file literally named `.env` for
variable substitution — never `.env.example` — so if the edit landed in `.env.example` instead of
a real `.env` (a genuinely easy mixup: the repo's own instructions say "copy this file to `.env`
and edit *that*"), or if a leading `#` was left on the line in the real `.env`, Compose would see
the variable as unset either way, which is exactly the symptom observed. This could not be
independently confirmed against the user's actual `.env` — it's gitignored, and this project's own
rules forbid reading or touching it under any circumstance.

**Fix:**
1. `.env.example` cleaned up (the stray line removed) and its guidance rewritten to name this
   exact mistake explicitly — wrong file, and/or a leading `#` — rather than assuming a reader
   would infer it.
2. Structurally, independent of whatever caused this specific instance: digest verification
   stopped being gated on `EXPECTED_DIGEST_*` being configured at all. It's now unconditional
   trust-on-first-use (see AGENTFW_CONTEXT.md's pre-M3 round-4 entry) — the same class of
   configuration mistake, if it recurs, now degrades to "pin whatever is observed on first boot"
   instead of "no verification in effect," which is a real, if weaker, protection rather than none.

**Re-verified after the fix?** Not yet. Recommended re-test, using the *actual* `.env` file this
time and confirming the value is visible inside the container before drawing any conclusion about
the application logic:
```
docker compose exec identity env | Select-String "EXPECTED_DIGEST"
```
If that's still empty, the bug is upstream of anything in this repository (shell/`.env` handling
on the host) — the compose file itself has been re-verified correct as of this entry.

---

## Verification 4 — the original M1 non-bypassability proof

**What was being checked:** the single property the entire project's design argument rests on —
`agent-net` being `internal: true` means the agent container has no route to the internet at all,
not even to a host that a policy would otherwise allow. Two commands were run to make that
distinction concrete: one target with no allow rule, and one target that *would* be allowlisted if
the request ever reached the PEP's policy layer.

**Commands run, from inside the agent container:**
```
docker compose exec agent curl -sS --max-time 5 https://example.com
docker compose exec agent curl -sS --max-time 5 https://api.trusted-news.com
```

**Result:** both failed. (The exact curl stderr text wasn't captured in this run — only the pass/
fail outcome was reported back — so it isn't reproduced here rather than guessed at. A re-run per
Verification 1's template, with `-sS` output kept, would fill that in.)

**What this established:** `api.trusted-news.com` failing is the point, not a side note. If the
network layer only blocked *unlisted* hosts, that would prove nothing about `agent-net` itself —
it could just as easily mean some other component was doing the blocking. Both an allowlisted and
a non-allowlisted host failing identically, from the agent's own network namespace, shows the
block is indiscriminate: `agent-net` doesn't know or care what policy would eventually say about
either destination, because it has no route to either one. That's what makes allowlisting provably
the PEP's job and nobody else's — the network layer can't do it selectively even if it wanted to.

**Re-verified after any fix?** N/A — nothing failed here; this confirms a property that was already
believed true but had never been run and reported back until now.

---

---

## Verification 5 — M3 attack suite, live Docker, 9/9 denied — with two real findings inside a real pass

**What was being checked:** the two items the previous entry named as open — A4 (real multi-agent
lateral movement) and A9 (raw `:8081` bypass listener) — plus, incidentally, all nine attacks at
once via `attacks/run_all.py`.

**Commands run** (from the host, via `docker exec` against a running container named `m3-agent`,
and separately via `docker compose logs`):
```
docker exec -e PYTHONPATH=/app m3-agent python -m attacks.run_all
docker compose logs pep --since 10m | Select-String "BYPASS_ATTEMPTED"
docker exec -e PYTHONPATH=/app m3-agent python /app/evals/score.py
```
A separate attempt at `docker compose exec agent python -m attacks.a4` / `attacks.a9` (the
originally recommended re-test, run standalone rather than via `run_all.py`) failed with
`service "agent" is not running` — expected, not a bug: the `agent` service is a run-once batch job
with no restart policy (`AGENTFW_CONTEXT.md` §9 M1), so once its own entrypoint scenario finishes
and it exits, `docker compose exec` (which requires a running service) can no longer reach it. The
`m3-agent` container reached via plain `docker exec` was evidently still up.

**Headline result, real and worth stating plainly:** all nine attack requests were denied by the
live PEP, reached over real Docker networking with a real, genuinely-issued Ed25519 token
(`identity/issuer.py`'s real `/attest`, not a local replay) — `run_all.py` printed `9/9 BLOCKED`.
`docker compose logs pep` independently shows two real `BYPASS_ATTEMPTED` events with real
timestamps, `trace_id`s, and `"decision": "DENY"` — A9's attribution claim is now cleanly,
completely confirmed: a raw request to `:8081` is denied, and that denial is independently visible
in the PEP's own log, exactly as `pep/bypass_proxy.py`'s design claims.

**Two real problems, found by reading the output carefully rather than accepting the summary line:**

1. **Quarantine-cascade contamination of per-attack mechanism attribution.** `A1`'s live
   `policy_id / reason` printed as `DEFAULT_DENY / AGENT_QUARANTINED` — not the `no_matching_rule`
   default-deny A1 is built to demonstrate. `pep/pipeline.py`'s quarantine gate runs before stage 3
   (policy) and is absolute: once a workload is quarantined, every subsequent call from it is
   denied with `reason=AGENT_QUARANTINED` regardless of what stage 3–7 would have said. Because
   `run_all.py` runs all nine attacks *in one process, against one persistent eventstore*, and
   `agent`/`research_agent`'s workload was evidently already quarantined (from an earlier
   iteration of the user's own debugging — `AGENT_QUARANTINED` appears starting on A1, the very
   first call made in this run, which is itself circumstantial evidence that quarantine state
   correctly persisted across whatever earlier run put it there), six of the nine attacks
   (A1, A2, A3, A4, A5, A7) show `AGENT_QUARANTINED` as their live reason, not the specific
   mechanism (`DEFAULT_DENY`, `dlp_block`, `DEFAULT_DENY_EAST_WEST`, `matched_explicit_deny`,
   threat-intel) each one is individually built to demonstrate. The requests were still genuinely
   denied — quarantine backstopping a specific gap is arguably a *stronger* result, not a weaker
   one — but this run does not independently, cleanly confirm each attack's own claimed mechanism
   the way a from-cold-state run would. Only A9 (presents no identity, can't be quarantined) and,
   arguably, A6 (see below) are unaffected.
2. **Role-identity mismatch: `try_live_pep_call()` cannot actually test a role other than whichever
   container it's invoked from.** `identity/issuer.py`'s `/attest` is deliberately unauthenticated
   and derives identity entirely from the calling connection's source IP
   (`_lookup_caller_container()`) — by design, and correctly so (`AGENTFW_CONTEXT.md` §2: "the
   agent is never asked to assert its own identity"). But `attacks/common.py`'s
   `try_live_pep_call()` posts to `/attest` with no parameters at all, meaning the live token it
   gets back reflects *whichever real container made the call* — never the `role`/`service` each
   attack script's own Python variables claim to be testing. A3, A5, A2, and A8 are written as
   `admin_agent`, `support_agent`, `finance_agent`, and `finance_agent` respectively; `admin_agent`
   has no `AGENT_REGISTRY` entry at all (confirmed in `identity/issuer.py`), so A3's live branch
   could only have reported `REAL_DOCKER_VERIFIED` because the *real* caller (running inside a
   container actually registered as `research_agent`, going by A1/A4/A6/A7 succeeding under that
   same identity) attested successfully as itself, not as `admin_agent` — the request that then
   went to the PEP was genuinely denied, but it was evaluated under the real caller's real role,
   not the label the script prints (`identity: role=admin_agent, ...`, `role=support_agent, ...`,
   etc., a hardcoded description string that was never validated against what the live token
   actually contained). A1, A4, A6, A7 (all written as `research_agent`) are not affected by this
   specific issue, since that happens to be the real invoking container's real role.

**Net assessment:** "9/9 blocked, live Docker" is true and should be reported as such — every
request really was denied by the real deployed PEP. It should **not** be reported as "9 independent
attacks, each confirming its own distinct claimed mechanism and identity, live" — that overstates
what this run showed for six of the nine attacks (finding 1) and for four of the nine specifically
(finding 2, overlapping with finding 1's set). A9's result is a full, clean, independent pass with
no caveat. See the M4 hostile-review report for the severity assessment of both findings — neither
was fixed as part of recording this entry, per this milestone's own rule against fixing
hostile-review findings inside the milestone that found them.

**Re-verified after any fix?** N/A — nothing was changed as a result of this entry; both findings
are recorded as-is for a future milestone to address (e.g., release the quarantined workloads via
`docker compose exec pep curl -X DELETE http://eventstore:8090/quarantine/<workload>` before a
clean re-run, and/or run each attack script from inside the container matching its own claimed
role rather than from one shared container).

---

## Verification 6 — M4 live PEP benchmark, a second independent 9-attack re-run, digest-pin match, quarantine release

**What was being checked:** the M4 live performance benchmark (`evals/bench_pep.py`, previously
built but never run), plus a second, independently-invoked pass at all nine attacks to see whether
Verification 5's two findings reproduce under a different invocation pattern, plus two items
`docs/verification-log.md` had open (digest pins matching a real deployed image; quarantine release
via a real live call).

**Docker health**, `docker compose ps`: `eventstore`, `identity`, `pep` all `Up 4 minutes
(healthy)`; `dashboard` `Up 14 minutes` (no health check configured for that service, so no
`(healthy)` qualifier appears for it — not a health failure, just no probe defined). (`agent`/
`finance-agent`/`support-agent` not listed in this particular check — a separate long-lived
container named `m3-agent` was used for the attack re-run below instead, per the commands actually
run.)

### Live PEP benchmark — real numbers, first collected this milestone

**Command:**
```
docker compose run --rm --no-deps -v "C:\Firewall:/app" -w /app --entrypoint python support-agent \
  -m evals.bench_pep --requests 1000 --concurrency 10 --warmup 50 --workload both
```
**Environment:** `python=3.11.15`, `platform=Linux-5.15.167.4-microsoft-standard-WSL2-x86_64-with-glibc2.41`
(Docker under WSL2, not the Windows host directly). 1000 requests per workload, concurrency 10,
warm-up 50 per workload (discarded) — 2,000 measured requests total, **zero errors** in either
workload.

**Real output, `dlp_exercised` (`db.query` on `customers`, `R-SUPPORT-001`, `inspect: true`):**
```
requests: 1000  success: 1000  deny: 0  error: 0
end-to-end HTTP latency: p50=138.415 ms  p95=351.680 ms  p99=809.256 ms  mean=174.119 ms
per-stage (server-reported):
  identity 0.3885/0.6066/1.4788   normalize 0.0056/0.0097/0.0485   policy 0.0564/0.1061/0.1670
  threat_intel 0.0021/0.0028/0.0031   dlp 0.0274/0.0428/0.0918   risk 0.1466/0.3262/0.8266
  decision 0.0048/0.0082/0.0138   log 69.5336/234.1504/676.4877   total 70.0759/234.6148/677.0141
  (p50/p95/p99, ms)
```

**Real output, `dlp_not_triggered` (`email.send` to the approved helpdesk address, `R-SUPPORT-002`,
no `inspect` flag, no `fqdn`):**
```
requests: 1000  success: 1000  deny: 0  error: 0
end-to-end HTTP latency: p50=130.423 ms  p95=413.625 ms  p99=839.947 ms  mean=169.307 ms
per-stage (server-reported):
  identity 0.3680/0.5471/1.0091   normalize 0.0054/0.0094/0.0133   policy 0.0484/0.0881/0.1533
  threat_intel 0.0020/0.0027/0.0030   dlp 0.0020/0.0031/0.0038   risk 0.3002/0.5190/0.8346
  decision 0.0051/0.0083/0.0108   log 62.5755/263.8114/595.2960   total 63.4381/264.4298/596.0998
  (p50/p95/p99, ms)
```

**What this established, precisely:**
- **End-to-end HTTP latency and server-reported pipeline latency are two different numbers and
  must never be conflated.** p50 end-to-end is ~130–138 ms; p50 server-reported `total` is only
  ~63–70 ms — the difference is real network/Docker/HTTP-stack overhead the client-side
  measurement correctly includes and the server-side breakdown correctly doesn't.
- **The `log` stage dominates server-reported pipeline latency** in both workloads — p50 ~63–70 ms
  of the ~63–70 ms `total`, i.e. nearly all of it. This is a real, measured fact about *this*
  deployment (SQLite durable write + the eventstore HTTP round trip inside `pep/proxy.py`'s
  `_log_event()`) — not extrapolated to any other environment or claimed as a general property of
  the architecture.
- **The DLP stage comparison is real and methodologically clean, by construction:** `dlp_exercised`
  p50/p95/p99 = 0.0274/0.0428/0.0918 ms vs. `dlp_not_triggered` = 0.0020/0.0031/0.0038 ms — an
  order-of-magnitude difference, consistent with DLP genuinely running in one workload and not the
  other (confirmed by the rule construction, not inferred from the timing itself).
- All 1000 requests in both workloads returned `ALLOW`/executed (`success: 1000, deny: 0, error:
  0`) — this benchmark measured the *allowed* path's latency, not a denied path's.

### A second, independent 9-attack re-run — reconfirms both Verification 5 findings from a different angle

**Commands:** nine separate `docker exec -e PYTHONPATH=/app m3-agent python -m attacks.aN`
invocations (A1 through A9), each its own process — not one shared `run_all.py` invocation this
time. Real output for all nine recorded in full in the M4 session log this entry summarizes.

**Result:** all nine again denied. The specific live `reason` field varied by attack in a
*different* pattern than Verification 5's run (this run: A1 clean `no_matching_rule`; A2 clean
`matched_explicit_deny`; A3, A4, A5, A7 show `AGENT_QUARANTINED`; A6 clean `matched_explicit_deny`;
A8 clean `risk_band_high`; A9 clean `BYPASS_ATTEMPTED`, independently reconfirmed via
`docker compose logs pep --since 2m | Select-String "BYPASS_ATTEMPTED"`) — different specific
attacks were quarantined this time than last time, which is itself expected: quarantine state is
whatever accumulated across whatever ran before this particular sequence, not a fixed property of
any one attack.

**This reconfirms, independently, both of Verification 5's findings — it does not resolve either:**
1. **Quarantine cascade (still present, different attacks affected this run):** A3/A4/A5/A7 show
   `AGENT_QUARANTINED` rather than their own claimed mechanism this time. Same root cause as
   Verification 5 (`pep/pipeline.py`'s absolute pre-policy quarantine gate, persistent eventstore
   state carried across separate process invocations, not just within one shared process) — proven
   here to also apply across *independently invoked* processes, not only within one `run_all.py`
   run, which is if anything a slightly stronger version of the same finding.
2. **Role-identity mismatch (still present):** every one of these nine commands was run from the
   same `m3-agent` container. A3 (claims `admin_agent`) again reported `REAL_DOCKER_VERIFIED` even
   though `admin_agent` has no `AGENT_REGISTRY` entry — reconfirmed directly this run by grepping
   the deployed `identity/issuer.py` inside the running `identity` container itself (below), not
   just inferred from source as in Verification 5.

**Explicit disclosures carried over from this run's own output, worth recording verbatim rather
than summarizing away:**
- **A3:** its own printed output states admin_agent has no deployed compose service or registry
  entry — this run's downstream PEP decision was live, but the identity/attestation layer for
  `admin_agent` specifically was not a real deployed workload. Not represented as fully verified.
- **A5:** `risk/scorer.py`'s dedicated `CRED_ACCESS` action-class factor did not fire — confirmed
  again this run, same known gap as before (`pep/pipeline.py`'s `ACTION_MAP` has no tool wired to
  that action class).
- **A7:** the live pipeline genuinely called `quarantine.enter('agent', 'risk score reached
  CRITICAL band')` and `quarantine.enter('agent', 'threat-intelligence hit on destination')` —
  this is what produced the `AGENT_QUARANTINED` reason seen on A3/A4/A5 later in this same run.

**Registry confirmation, run directly against the deployed container (new this run — Verification 5
only checked this against source, not the running container):**
```
docker compose exec identity sh -c "grep -R -n 'AGENT_REGISTRY\|admin_agent\|finance-agent\|support-agent' /app/identity 2>/dev/null"
```
Confirms `AGENT_REGISTRY` (`identity/issuer.py`, as deployed) has exactly three entries — `agent`,
`finance-agent`, `support-agent` — no `admin_agent`. Directly supports the role-identity-mismatch
finding with evidence from the running container, not just the source tree.

### Digest pin verification — now confirmed matching real deployed images

**Commands:**
```
docker compose exec identity python -m identity.admin_cli list-pins
docker inspect firewall-agent-1 --format "agent={{.Image}}"
docker inspect firewall-finance-agent-1 --format "finance-agent={{.Image}}"
docker inspect firewall-support-agent-1 --format "support-agent={{.Image}}"
```
**Result:** the three pinned digests (`agent`, `finance-agent`, `support-agent`) exactly match the
three deployed images' real digests. This confirms trust-on-first-use pinning is genuinely pinning
the real, currently-deployed image for all three registered workloads — closing part of the
previously-open "identity's reverted network topology... digest pins... has not been confirmed"
item below. **What this does not confirm:** that a *changed* image is correctly *refused* — this
run only shows the pins match the current images, not a rebuild-and-reattempt-with-a-different-
digest scenario. That specific sub-claim (`tests/test_identity_issuer.py`'s TOFU-mismatch test,
never yet run against a real second image) remains open.

### Quarantine release — now confirmed working end-to-end via a real live call

**Commands:**
```
docker compose exec eventstore python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8090/quarantine').read().decode())"
# -> {"agent":"risk score reached CRITICAL band"}   (persisted, real, from A7 above)

docker compose exec eventstore python -c "import urllib.request; req=urllib.request.Request('http://localhost:8090/quarantine/agent', method='DELETE'); print(urllib.request.urlopen(req).read().decode())"
# -> {"status":"released","agent_id":"agent"}

docker compose exec eventstore python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8090/quarantine').read().decode())"
# -> {}
```
**Result:** a real, deliberate quarantine entry → persisted-and-observed → released via the real
`/quarantine/{agent_id}` DELETE route → confirmed empty afterward. This is the first time this
specific admin operation has been exercised live end-to-end, not just recommended as a re-test.

**Policy bundle deployed-state spot check:** `docker exec m3-agent sh -c "grep -n -i -E
'admin|research|finance|support|taint' /app/policy/bundles/default.yaml"` confirms all sixteen
rule IDs (`R-RESEARCH-*`, `R-FINANCE-*`, `R-SUPPORT-*`, `R-ADMIN-*`) and the `session_taint`
conditions referenced throughout this project's docs are genuinely present in the deployed bundle,
not just the source tree.

**Re-verified after any fix?** N/A — nothing was changed as a result of this entry either;
Verification 5's two findings are reconfirmed, not resolved, and the hostile-review document's C1
and C2 entries are updated to reference this second data point without softening either finding.

---

## C1/C2 remediation — execution-model fix, now live-verified (Verification 7 below)

Verifications 5 and 6 didn't just report "9/9 blocked" — read carefully, they exposed two real,
structural problems in *how the attacks were run*, not just isolated bad luck in one run:
quarantine state shared across a whole sequence (C2), and every attack's live identity being
whichever container actually invoked it rather than the role the script claims to simulate (C1).
This entry documents a **code fix** to the execution architecture that produced those two findings.
It went through three real, independently-discovered bugs before it actually worked — none of them
found by review, all of them found by an actual attempt to run it — recorded here rather than
smoothed into "and then it worked":

1. **`ModuleNotFoundError: No module named 'cryptography'`** — the first live-run attempt, from a
   bare Windows host with no project dependencies installed, failed before Docker dispatch mode
   ever got a chance to run: `run_all.py` imported `attacks.a1`..`a9` at module level, which
   transitively imports `pep.pipeline` → `identity.tokens` → `cryptography`. Fixed by moving every
   attack/risk/pep import to be local to `_run_in_process_fallback()` — the one code path that
   legitimately needs the full dependency set in the orchestrator's own process. Docker dispatch
   mode now needs only `docker` on PATH and the standard library on whatever host runs it.
2. **`ModuleNotFoundError: No module named 'pep'` — inside the container this time**, found the
   moment dispatch actually reached a real container: `agent/Dockerfile` (shared by `agent`,
   `finance-agent`, `support-agent`) had never copied `pep/`, `policy/`, `risk/`, `dlp/`,
   `threat_intel/`, or `identity/tokens.py` into the image — only `pep/Dockerfile` had. This gap
   predates this fix; nothing had ever actually run an attack script inside a freshly-built `agent`
   image before. Fixed by adding the same `COPY` lines `pep/Dockerfile` already has.
3. **`docker compose exec` → `"service \"agent\" is not running"`** — `agent`/`finance-agent`/
   `support-agent` are one-shot batch jobs (`docker-compose.yml`: "no restart policy... expected to
   show Exited(0)"), so once their default scenario finishes, there is no running container left
   for `exec` to target. Fixed by switching the dispatcher from `docker compose exec` to
   `docker compose run --rm -T --no-deps <service> python -m attacks.aN`, which creates a fresh,
   correctly-networked container from the service's own definition on demand instead of requiring
   it to already be up.

After all three fixes, the corrected suite was run for real — see **Verification 7** immediately
below, the first entry in this file to independently confirm the C1/C2 fix against a live
deployment rather than describe what it's supposed to do.

### What changed, structurally

**C1 fix — role-verified dispatch, not self-asserted identity:**
- `attacks/common.py` gained `attest_and_verify_role()`: a real `POST /attest` against the live
  issuer, followed by a real `GET /public-key` and a real Ed25519 signature verification
  (`identity.tokens.verify_token`) of the returned token — the exact same check
  `pep/pipeline.py`'s own stage 1 performs on every request. The role this returns is the issuer's
  own signed claim, not a string this script asserts about itself.
- `try_live_pep_call_verified()` calls that, compares the genuinely-attested role against the role
  the scenario declares it needs (each `attacks/aN.py`'s own `EXPECTED_ROLE`), and reports
  `REAL_DOCKER_VERIFIED` only when they match. A mismatch — the exact C1 failure mode — now
  produces `UNVERIFIED` with an explicit "attested as X, this scenario requires Y" error, never a
  silent pass.
- `attacks/run_all.py` no longer runs all nine attacks in one shared process/container. In Docker
  dispatch mode it shells out to `docker compose exec <service> python -m attacks.aN` once per
  attack, using `attacks/common.py`'s `ROLE_TO_SERVICE` table (`research_agent` → `agent`,
  `finance_agent` → `finance-agent`, `support_agent` → `support-agent`) so each attack is
  genuinely invoked from the container that can actually attest as the role it needs.
- `admin_agent` (A3) has no entry in that table on purpose — it has no deployed compose service
  (`identity/issuer.py`'s `AGENT_REGISTRY` never has, either) and this fix does **not** invent one
  to make A3 pass. A3 is dispatched from `agent` only to exercise the real live path; the role
  check then correctly and structurally reports it `UNVERIFIED` every time, honestly, rather than
  faking coverage for a role this topology doesn't deploy.

**C2 fix — real quarantine reset before each independent attack, using only the existing admin
API:**
- `attacks/run_all.py`'s Docker dispatch mode calls `docker compose exec eventstore python -c
  "..."` immediately before each of A1–A9 — the exact same real, public
  `GET /quarantine` / `DELETE /quarantine/{agent_id}` routes (`events/app.py`) Verification 6
  exercised by hand, nothing new, no eventstore internals touched, no in-memory state mutated
  directly. It lists what's quarantined, releases everything found, and re-checks that
  `GET /quarantine` genuinely returns `{}` before dispatching the next attack — the clear step is
  itself verified, not assumed to have worked.
- Every attack now declares its own `EXPECTED_DECISION`/`EXPECTED_REASON` and grades the live
  result against it (`attacks/common.py`'s `assess_mechanism()`). A denial is no longer treated as
  a pass on its own — `AGENT_QUARANTINED` (or any other decision/reason the scenario didn't ask
  for) is a loud, explicit **mismatch**, surfaced in `print_report()`'s output and in a nonzero
  exit code (`mechanism_exit_code()`), not silently absorbed into "9/9 blocked."
- `AttackResult` gained a `genuinely_verified` property: `True` only when `verification_status ==
  REAL_DOCKER_VERIFIED` **and** `mechanism_match is True`. This is now the single property that
  gates whether an attack counts toward the suite's total — replacing the looser
  `_counts_as_blocked()` check the previous version used.

**A10 — the cascade demonstrated on purpose, not stumbled into:** a new `attacks/a10.py` runs two
calls back-to-back on the same workload (`agent`/research_agent) with quarantine cleared once
*before* both calls and deliberately **not** cleared between them. Call 1 (an A7-style
threat-intel-hit request) is expected to show its own genuine mechanism and, as a real side effect,
trigger `quarantine.enter()`. Call 2 (an A1-style unrelated request) is expected to be denied
specifically by `AGENT_QUARANTINED` — proving persistence takes precedence, on purpose, clearly
separated from the A1–A9 independent-verification total (`CascadeDemoResult.demonstrates_cascade`,
never folded into `genuinely_verified`).

**Verifications 5 and 6 above are not retracted or reinterpreted.** They remain the accurate record
of what the *previous* execution model actually did, including the two real findings that motivated
this fix.

---

## Verification 7 — C1/C2 fix, live, real: 8/9 genuinely verified, A3 correctly UNVERIFIED, A10 cascade confirmed

**Provenance:** unlike Verifications 1–6, this run was executed directly by me (Claude), in-session
— Docker Desktop was reachable through this session's tooling, a first for this project. Not the
project owner's own machine; noted here so this entry's provenance is exactly as clear as every
other one's.

**Command:**
```powershell
docker compose up -d
docker compose ps
# after rebuilding the agent images (fix #2 above), TOFU pins from the old image had to be cleared:
docker compose exec identity python -m identity.admin_cli clear-pin agent
docker compose exec identity python -m identity.admin_cli clear-pin finance-agent
docker compose exec identity python -m identity.admin_cli clear-pin support-agent
python -m attacks.run_all
```
Run from a Python environment with **zero project dependencies installed** (only `docker` on PATH)
— deliberately, to prove fix #1 above actually holds, not just to run the suite.

**Environment:** `docker compose ps` before the run showed `dashboard`/`eventstore`/`identity`/`pep`
all `Up ... (healthy)`; `agent`/`finance-agent`/`support-agent` correctly absent (one-shot jobs,
per fix #3 above) — `docker compose run` created and removed a fresh container per attack.

**Real summary table, exactly as printed:**
```
=======================================================================================
Attack Category                Status              Mechanism   Reason
---------------------------------------------------------------------------------------
A1     unauthorized_destinationREAL_DOCKER_VERIFIEDMATCH       no_matching_rule
A2     dlp_exfiltration        REAL_DOCKER_VERIFIEDMATCH       dlp_block
A3     taint_containment       UNVERIFIED          n/a         real_docker_path_unrea
A4     lateral_movement        REAL_DOCKER_VERIFIEDMATCH       no_matching_east_west_
A5     credential_access       REAL_DOCKER_VERIFIEDMATCH       matched_explicit_deny
A6     indirect_prompt_injectionREAL_DOCKER_VERIFIEDMATCH       matched_explicit_deny
A7     threat_intel_hit        REAL_DOCKER_VERIFIEDMATCH       no_matching_rule
A8     normalization_bypass    REAL_DOCKER_VERIFIEDMATCH       matched_explicit_deny
A9     raw_egress_bypass       REAL_DOCKER_VERIFIEDMATCH       BYPASS_ATTEMPTED
---------------------------------------------------------------------------------------

8/9 A1-A9 GENUINELY VERIFIED (real Docker, correct role, own mechanism confirmed)
UNVERIFIED (real Docker path not reached or wrong role): A3
```
`$LASTEXITCODE` was `1` — correct, not a bug: `main()` only returns 0 when *every* one of A1–A9 is
`genuinely_verified`, and A3 structurally cannot be (see below), so a nonzero exit is the honest
result even though 8/9 succeeded and A9 is a genuine, independently-attributed pass.

**A1, A2, A4–A9 — each genuinely REAL_DOCKER_VERIFIED, correct role, own mechanism confirmed
(`mechanism_match: true`):**
- **A2** is the clearest before/after: dispatched correctly from `finance-agent`, it attested as
  `finance_agent`, and the live decision was genuinely `DENY / dlp_block` (policy_id
  `R-FINANCE-001`, an ALLOW rule — DLP is what narrowed it) — exactly the mechanism A2 claims,
  something the *previous* execution model could never show because the wrong container answered.
- **A9** reported `REAL_DOCKER_VERIFIED`/`BYPASS_ATTEMPTED`, and the durable event was
  independently re-confirmed via `docker compose logs pep --since 5m | grep BYPASS_ATTEMPTED`
  (real log line, real `trace_id`, matching Verification 1's original attribution).
- **A10** (run separately, immediately after A1–A9): call 1 (A7-style, threat-intel destination)
  was `REAL_DOCKER_VERIFIED`, `DENY / no_matching_rule`, `mechanism_match: true` — its own genuine
  mechanism, uncontaminated. Call 2 (A1-style, unrelated destination), run immediately after with
  quarantine deliberately **not** cleared, was `REAL_DOCKER_VERIFIED`, `DENY / AGENT_QUARANTINED`,
  `mechanism_match: true` against its *own* expectation of `AGENT_QUARANTINED` —
  `demonstrates_cascade: true`, live, for the first time. Quarantine was then cleared
  (`[final cleanup] quarantine verified empty`) and `GET /quarantine` confirmed `{}` afterward.

**A3 — correctly, structurally UNVERIFIED, exactly as designed, not a gap:**
```
note: REQUIRED real path not reached: this scenario requires role='admin_agent', but the calling
container genuinely attested as role='research_agent' — this container is not the one this
scenario needs (see ROLE_TO_SERVICE / run_all.py's dispatch table) Reported UNVERIFIED, not
blocked — a local replay is not accepted as proof of this scenario's own live mechanism.
```
This is the C1 fix working *for* A3, not against it: `admin_agent` has no compose service, so no
container can ever genuinely attest as it — the role check catches this every time, honestly,
rather than letting `agent`'s real attestation silently stand in for a role it isn't.

**Digest pins after the image rebuild** (`docker compose exec identity python -m
identity.admin_cli list-pins`): `agent`, `finance-agent`, `support-agent` all show fresh
`sha256:...` values matching the rebuilt images — TOFU re-pinned correctly on first attestation
after `clear-pin`, exactly as designed.

**Cleanup verified:** `docker ps -a --filter name=firewall-agent-run` (and the finance/support
equivalents) showed zero leftover containers after the run — `--rm` worked. Final
`GET /quarantine` returned `{}`.

**Re-verified after any fix?** N/A for the underlying enforcement (nothing in `pep/`, `policy/`,
`risk/`, `dlp/`, or `identity/` changed) — this entry verifies the *harness* fix (C1/C2), and
that fix is what changed. The full local test/lint/compiler suite was re-run after all three bug
fixes above and passed (165 tests, `ruff check`/`ruff format --check` clean, policy compiler OK).

---

## Not yet verified via Docker

Named explicitly, not left implicit — a missing entry here is not the same claim as a passing one:

- ~~**Identity's reverted network topology and digest-pin persistence** — whether
  `docker compose exec identity python -m identity.admin_cli list-pins` works against the mounted
  volume and matches deployed images.~~ **Confirmed (Verification 6):** `list-pins` was run
  against the real mounted volume and its three pinned digests exactly matched the three deployed
  images' real digests (`docker inspect`). The `docker compose up` topology itself was already
  running (`docker compose ps`, all relevant services healthy) when this check ran. `clear-pin`
  specifically was not exercised this round — not needed to confirm this item.
- **Trust-on-first-use pinning's *refusal* path, end to end** — still open. Verification 6
  confirmed pins *match* the current deployed images; it did not test "second attestation with a
  *different* digest is refused" against a real rebuilt image and a real second container. That
  specific claim is still verified only by `tests/test_identity_issuer.py` against a scratch SQLite
  file.
- ~~**A clean (non-quarantined, correct-container) re-run of A1–A9's own specific claimed
  mechanisms, live**~~ **Confirmed (Verification 7):** 8 of 9 genuinely verified at their own
  claimed mechanism (`mechanism_match: true`), from a clean quarantine state, dispatched to the
  correct per-role container. A3 remains structurally `UNVERIFIED` by design (no real `admin_agent`
  service exists) — not a residual instance of this gap, a different, intentional property.
- ~~**The corrected `run_all.py` dispatcher's own mechanics, live**~~ **Confirmed (Verification
  7):** `docker compose run --rm -T --no-deps <service> python -m attacks.aN` genuinely produced
  parseable `RESULT_JSON:` lines for all ten dispatches, and the quarantine list/clear/verify
  round-trip via `docker compose exec eventstore python -c "..."` behaved exactly as designed —
  `--rm` left zero containers behind afterward (checked with `docker ps -a`).
- ~~**A10's cascade demonstration, live**~~ **Confirmed (Verification 7):** call 1 showed its own
  genuine mechanism (`no_matching_rule`), call 2 — run immediately after with quarantine
  deliberately not cleared — was denied specifically by `AGENT_QUARANTINED`,
  `demonstrates_cascade: true`, both live.
- **The dashboard against a live eventstore with real attack/agent traffic in it** — verified
  locally in this session against a manually seeded local `events/app.py` instance (real event
  schema, real FastAPI routes) with a real browser render confirming charts/tables/detail view all
  populate correctly, but not yet against the actual `docker compose up -d` deployment.
- **Quarantine persistence across a real PEP restart** (pre-M3 round 3) — still not deliberately
  tested (`docker compose restart pep`, check membership survives). Verification 5 above is
  circumstantial, not a clean test of this specifically: `agent`/`research_agent` was observed
  already quarantined at the very start of that run, meaning the entry survived from an earlier,
  untracked session — consistent with persistence working, but no restart was deliberately
  triggered and observed as part of that same test.
- **Multi-agent lateral movement via `agent.invoke`, live, from a clean (non-quarantined) state**
  (pre-M3 round 3/4) — the east-west code path itself was reached live in Verification 5 (A4), but
  the workload was already quarantined by then, so the live result shown was the quarantine gate,
  not `DEFAULT_DENY_EAST_WEST` specifically. A local (non-Docker) integration test already confirms
  the east-west logic itself (`tests/test_east_west.py`); a clean live confirmation of this exact
  path is still open.
- **East-west DLP coverage and the compiler's unknown-workload check** (this session, item 2) —
  both are exercised locally (pytest, or `python -m policy.compiler`, neither requiring Docker);
  a Docker run isn't the missing piece for these two specifically, but they've never been part of
  a live multi-container demo either.
