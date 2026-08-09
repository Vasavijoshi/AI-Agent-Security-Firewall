# AgentFW — Architecture

This is the trimmed, buildable version of `AgentFW_Architecture_v1.md`. That document designs a
production system (SPIFFE/SPIRE, Kubernetes, Terraform, multicloud). This repo builds none of
that — see `AGENTFW_CONTEXT.md` §1 for the hard constraints. Where the two disagree, the context
file wins and this document follows it.

## The problem, in one sentence

A conventional workload's egress policy works because identity is a proxy for network location and
its destination set is static. An LLM agent breaks both: many roles can share one process/IP, and
the agent picks its destination at runtime from content an attacker may control (a fetched web
page, a tool result). AgentFW enforces deny-by-default egress on a workload whose destination set
is chosen at runtime by a component that may be adversarial.

## Why this is a firewall, not an API gateway

An API gateway asks *"may this caller reach my service?"* — it trusts the thing behind it. AgentFW
asks *"may this workload reach the world?"* and does not trust the agent it is attached to. The
agent is not AgentFW's client; it is AgentFW's subject of enforcement. That is the egress-firewall
relationship, not the ingress one.

## The 8-stage pipeline

Every tool call the agent makes is forced through the PEP (Policy Enforcement Point) and evaluated
in this fixed order. The order is chosen for cost and short-circuiting, not aesthetics — each stage
prunes work for the ones after it.

```
                    ┌─────────────────────────────────────────────────────────────┐
                    │                      pep (proxy.py)                         │
   agent tool call  │                                                             │
  ────────────────▶ │  1 ─▶ 2 ─▶ 3 ─▶ 4 ─▶ 5 ─▶ 6 ─▶ 7 ─▶ 8 ─▶ enforce / forward   │
                    │                                                             │
                    └─────────────────────────────────────────────────────────────┘

   1. Identity verification   Who is calling? Fail → DENY immediately. Cheapest, most decisive —
                               never evaluate policy for a caller you can't name.

   2. Request normalization   Canonicalize before evaluating: punycode/homoglyph domains,
                               URL-encoded traversal, http://evil.com@trusted.com/, case folding.
                               A security step, not plumbing — evaluate AND forward the canonical
                               form, never the original (idempotent: normalize(normalize(x)) == x).

   3. Policy evaluation       Deterministic. Default deny. No explicit ALLOW → stop here. Prunes
                               everything before any expensive work runs.

   4. Threat intelligence     Local set lookup against known-bad FQDN/IP. O(1), no network call —
                               cheap enough to run before inspection.

   5. DLP / data              Expensive (regex + entropy over the body). Only runs when the matched
      classification          rule sets inspect: true, or the destination is external. Never spent
                               on traffic that's already denied.

   6. Risk + behavior         Combines 1–5 plus per-agent historical state into an explainable,
      scoring                 capped, additive score with a factor vector.

   7. Decision                final = min(policy_verdict, risk_verdict) on the lattice below.

   8. Durable log → enforce   Append the event and flush BEFORE the action is released. If the write
                               fails, the action is denied (log-or-deny) — an unlogged allow is
                               unauditable.
```

## The decision lattice

```
DENY  <  QUARANTINE  <  REQUIRE_APPROVAL  <  RATE_LIMIT  <  ALLOW_REDACTED  <  ALLOW
```

Risk and any future ML scorer can only move a decision leftward — a deterministic DENY from stage 3
is final and nothing downstream can promote it. This is the monotonicity invariant, and it is
property-tested in `tests/test_invariants.py`.

## Docker networking — the non-bypassability proof

```
┌─────────────────── agent-net  (internal: true — NO route to the internet) ───────────────────┐
│                                                                                                │
│   ┌────────────┐          HTTP_PROXY /            ┌────────────────────────────┐              │
│   │   agent    │ ───────  HTTPS_PROXY=pep:8080 ──▶ │            pep             │              │
│   │ (loop.py,  │                                   │  (the only dual-homed      │              │
│   │  tools.py, │                                   │   container — see below)   │              │
│   │  providers)│                                   └──────────────┬─────────────┘              │
│   └────────────┘                                                  │                             │
│                                                                    │                             │
└────────────────────────────────────────────────────────────────────┼─────────────────────────────┘
                                                                     │
                                                                     │  crosses into egress-net
                                                                     ▼
┌─────────────────────────── egress-net  (bridge — has internet route) ─────────────────────────┐
│                                                                                                 │
│      ┌────────────┐            ┌───────────────┐             allowlisted external              │
│      │ eventstore │◀───────────│  pep (2nd nic) │────────────▶ destinations                     │
│      │ (SQLite,   │            └───────────────┘                                                │
│      │  §"eventstore                                                                             │
│      │  choice" below)                                                                          │
│      └─────┬──────┘                                                                              │
│            │                                                                                     │
│      ┌─────▼──────┐                                                                              │
│      │ dashboard  │  (reads eventstore only, never touches agent-net)                            │
│      └────────────┘                                                                              │
│                                                                                                   │
└───────────────────────────────────────────────────────────────────────────────────────────────┘
```

`pep` is the only container on both networks. `agent` has no other configured route out
(`HTTP_PROXY`/`HTTPS_PROXY` point at `pep:8080`), and `agent-net` being `internal: true` means that
even if the agent process is fully compromised and ignores the proxy variables, there is no network
path to anywhere but the other containers on `agent-net`. `docker compose exec agent curl
https://example.com` must fail at the network layer — that command is the whole non-bypassability
demo, and it costs one line in `docker-compose.yml`, not three weeks of Kubernetes NetworkPolicy.

## Identity (trimmed from the SPIFFE/SPIRE design)

The full architecture doc specifies SPIFFE URIs, mTLS, and a CA service — that's Kubernetes/cloud
infrastructure this repo explicitly excludes. What's kept: **the agent never holds a tool
credential.** `identity/issuer.py` issues short-lived Ed25519-signed tokens; the PEP verifies the
signature and injects the real credential only after a policy check passes. A prompt injection
still can't exfiltrate a credential the agent never had.

## Policy (trimmed from YAML→OPA/Rego)

Policy is authored in YAML (`policy/bundles/default.yaml`) because it's reviewed by humans far more
often than it's written. It compiles to a plain Python decision tree (`policy/engine.py`,
`policy/compiler.py`) instead of an OPA/Rego backend — no extra service to run, and every line is
one the author can explain without reference to an external DSL.

## Why SQLite for the event store

`AGENTFW_CONTEXT.md` leaves the choice open ("postgres or sqlite — pick one and say why"). This
repo uses SQLite:

- The durability invariant (log-or-deny) needs fsync-before-release from a single writer (the pep)
  — not concurrent multi-writer access, which is the case Postgres is actually built for.
- `sqlite3` is in the standard library, so it costs nothing against the 12-package dependency
  budget, versus a Postgres driver.
- One fewer service to configure correctly for the acceptance test in `AGENTFW_CONTEXT.md` §0 to
  stay a true "clone and run" experience.
- `eventstore` is still its own container (a thin FastAPI wrapper over a SQLite file on a volume),
  so the docker-compose service topology matches `AGENTFW_CONTEXT.md` §4 exactly and the choice is
  swappable later without changing any other service's contract.

## Prompt injection containment (not detection)

Text-layer prompt injection detection is not reliable enough to build security on. AgentFW doesn't
try — it assumes the agent becomes adversarial the moment it ingests untrusted content, and bounds
what an adversarial agent can do:

- Any tool result originating outside the trust boundary (web fetch, uploaded doc, third-party API
  body) sets `session.taint = tainted`, stamped by the PEP — the agent cannot set or clear this bit
  itself, and it is monotonic for the session (invariant §3.5).
- A tainted session is evaluated against a taint ceiling: no writes, no external POST/PUT, no
  secret-class data.

See `AGENTFW_CONTEXT.md` §10 for the full A6 scenario — the injection succeeds at the model layer
and is contained at the enforcement layer. That is the project's headline result.
