# Verification log

This is a record of what has actually been run against a live Docker deployment, by the project
owner (I have no Docker in the environment I work in — see AGENTFW_CONTEXT.md's standing caveat,
repeated at the end of every milestone report). Each entry is a real command, its real output, and
the security property that output does or doesn't establish. Where a run found a real failure,
the entry says so, how it was diagnosed, and what changed as a result — this file is a record of
what was tested, not a claim that everything works.

Four runs have happened so far. Three found a real problem; the fourth confirmed the project's
central claim holds. That's the point of writing this down either way: a passing result recorded
here is worth more than an assumed one, and a failing result gets fixed instead of argued about.

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
- **Quarantine persistence across a real PEP restart** (pre-M3 round 3) — verified by
  `tests/test_quarantine.py` against a simulated restart (clearing in-memory state), not yet
  against an actual `docker compose restart pep`.
- **Multi-agent lateral movement** (pre-M3 round 3/4) — `agent.invoke` targeting `finance-agent`
  denied by east-west default-deny, live, via `docker compose logs agent` with
  `AGENTFW_SCENARIO=m2_lateral_movement_attempt`. Commands were given; no output has been reported
  back.
- **East-west DLP coverage and the compiler's unknown-workload check** (this session, item 2) —
  both are exercised locally (pytest, or `python -m policy.compiler`, neither requiring Docker);
  a Docker run isn't the missing piece for these two specifically, but they've never been part of
  a live multi-container demo either.
