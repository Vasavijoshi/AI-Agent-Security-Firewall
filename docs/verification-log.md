# Verification log

This is a record of what has actually been run against a live Docker deployment, by the project
owner (I have no Docker in the environment I work in — see AGENTFW_CONTEXT.md's standing caveat,
repeated at the end of every milestone report). Each entry is a real command, its real output, and
the security property that output does or doesn't establish. Where a run found a real failure,
the entry says so, how it was diagnosed, and what changed as a result — this file is a record of
what was tested, not a claim that everything works.

Five runs have happened so far. Four found a real problem. That's the point of writing this down
either way: a passing result recorded here is worth more than an assumed one, and a failing result
gets fixed instead of argued about — including a fifth run (below) that reported a clean "9/9
BLOCKED" on its face but, read carefully, exposed two real problems inside a genuinely passing
result.

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

## Not yet verified via Docker

Named explicitly, not left implicit — a missing entry here is not the same claim as a passing one:

- **Identity's reverted network topology** (pre-M3 round 5, correcting round 4) — `identity` moved
  back to `agent-net`-only, with digest pins now persisted to a local SQLite file
  (`identity/store.py`) on a named `identity-data` volume instead of the eventstore. Whether
  `docker compose up` builds and starts cleanly with this topology change, and whether
  `docker compose exec identity python -m identity.admin_cli list-pins` / `clear-pin <service>`
  actually work against the mounted volume, has not been confirmed.
- **Trust-on-first-use pinning itself, end to end** — "second attestation with a different digest
  is refused" is verified by `tests/test_identity_issuer.py` against a scratch SQLite file, not yet
  against a real rebuilt image and a real second container.
- **A clean (non-quarantined, correct-container) re-run of A1–A8's own specific claimed
  mechanisms, live** — see Verification 5's two findings. A9 does not need this; it already passed
  cleanly. The other eight would need either a fresh eventstore (or the specific workloads
  released from quarantine first) and, for A2/A3/A5/A8 specifically, actually running from inside
  the container matching their claimed role (`finance-agent`/`support-agent`) rather than from a
  single shared container, to independently confirm the claimed mechanism rather than the real
  caller's own role.
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
