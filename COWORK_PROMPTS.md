# COWORK_PROMPTS.md — Session-by-session prompts

**How to use this file:** one milestone per Cowork session. Do not paste two at once. Start a fresh session for each, in the same Project so context carries.

Set the mode selector to **Manually approve (Manual)** for all of these. Auto mode consumes more of your usage limit, and you want to see the diffs anyway.

---

## M0 — Bootstrap (run this first, ~15 min)

```
Read AGENTFW_CONTEXT.md in this folder completely before doing anything. It is
the project contract. Also read AgentFW_Build_Plan_v2.md and
AgentFW_Architecture_v1.md for background — where they conflict with the
context file, the context file wins.

For this session, do ONLY the following. Do not write any application logic yet.

1. Scaffold the repo exactly as laid out in section 4 of the context file:
   every directory, with an empty __init__.py where it's a Python package, and
   a one-line placeholder docstring in each module stating what will live there.

2. Create these working files:
   - .gitignore (Python, .env, __pycache__, .venv, *.db, dashboard cache)
   - .env.example with LLM_PROVIDER=mock and a commented-out
     ANTHROPIC_API_KEY line. Never create or touch .env itself.
   - requirements.txt — pinned, with a one-line justification comment above
     each dependency. Stay under the 12-package budget.
   - pyproject.toml configuring ruff and black at line length 100.
   - docker-compose.yml with the two-network split from section 5 of the
     context file. Services: agent, pep, eventstore (postgres or sqlite —
     pick one and say why), dashboard. It doesn't need to run yet, but the
     network topology must be correct.
   - README.md skeleton with the pitch, the acceptance-test command block,
     and TBD placeholders for every number.

3. Write events/schema.json — the full security event schema. Include at
   minimum: timestamp, trace_id, session_id, agent_id, role, tool, action,
   destination{fqdn,ip,port,protocol}, resource, data_classification,
   session_taint, risk_score, risk_factors[], policy_id,
   policy_bundle_version, decision, reason, latency_ms{per stage}.

4. Write docs/architecture.md — a trimmed version of the architecture, with
   an ASCII diagram of the pipeline and the two Docker networks.

5. git init, and make one commit: "chore: scaffold repo structure".

Then stop and give me: the tree output, the dependency list with
justifications, and anything in the context file you think is wrong or
underspecified. Be blunt about the second part.
```

---

## M1 — Vertical slice

```
Read AGENTFW_CONTEXT.md. We are building Milestone M1 only — stop when its
definition of done is met.

Build, in this order, testing as you go:

1. agent/providers.py — the LLM provider interface, plus MockProvider and
   AnthropicProvider. MockProvider replays deterministic scripted tool-call
   sequences keyed by a scenario name passed in at construction. Start with
   two scripts: "benign_research" and "unauthorized_post".

2. agent/tools.py — five tool definitions with strict JSON schemas:
   http.get, http.post, db.query, file.read, email.send. Each tool executes by
   making an HTTP request THROUGH the PEP. The agent has no direct network
   path — that's enforced by Docker, but the code should also make it
   structurally obvious.

3. agent/loop.py — a hand-written tool-calling loop. Multi-turn, tool results
   fed back into the message list, a max-iteration guard, and a clear error
   path when the model requests an unknown tool. Comment the loop generously;
   I need to be able to explain every line of it in an interview.

4. pep/proxy.py + pep/pipeline.py — FastAPI service on :8080. Implement the
   8-stage pipeline structure with all eight stages present as real functions,
   but for M1 only stages 1, 2, 3 and 8 do real work (identity can accept a
   static token for now; policy is a hardcoded allowlist). Stages 4–7 are
   typed pass-throughs that return their neutral value — NOT "# TODO" stubs.

5. pep/normalize.py — the real thing, not a placeholder. Punycode/IDN
   handling, percent-decoding, path traversal collapse, userinfo stripping
   (http://evil.com@trusted.com/), lowercase host, default-port folding.
   Write the tests for this first — it's a security control.

6. events/store.py — append-only event writes conforming to schema.json, with
   the log-or-deny invariant enforced: if the write fails, the decision
   becomes DENY.

7. Make docker compose up actually work, and add a test that asserts the agent
   container CANNOT reach an external host directly.

Definition of done: one tool call allowed, one denied, both producing a valid
logged event, and the network isolation test passing.

Commit in logical increments with conventional-commit messages. When done,
show me the two events side by side and tell me what's weak.
```

---

## M2 — The engine

```
Read AGENTFW_CONTEXT.md. Milestone M2 only.

1. policy/bundles/default.yaml — a real bundle with at least 4 roles
   (research_agent, finance_agent, support_agent, admin_agent) and ~15 rules
   covering allow, deny, inspect:true, and taint conditions. Include bundle
   metadata: version, not_valid_after, fail_safe_after.

2. policy/engine.py — evaluation with the stated resolution order: explicit
   DENY > explicit ALLOW > implicit DENY; within an effect, highest priority
   wins; ties break lexicographically on rule id. No dependence on dict
   iteration order.

3. policy/compiler.py — validation that FAILS THE BUILD on: two same-priority
   overlapping rules with different effects; a rule referencing an unknown
   role; a role with no critical_path rule. Warn on shadowed rules.

4. identity/issuer.py — Ed25519-signed short-lived workload tokens (15 min
   TTL) issued after container attestation (container id + image digest).
   The PEP verifies signature, expiry, and binding. Use the cryptography
   package — that's a justified dependency.

5. risk/scorer.py — the additive explainable scorer. Every score returns a
   factor vector of (code, points, human_reason). Per-category caps. Bands:
   LOW/MODERATE/HIGH/CRITICAL. Use the factor table in the architecture doc.

6. Taint tracking — session state owned by the PEP, never settable by the
   agent. Any tool result from an untrusted source sets tainted, irreversibly.
   Tainted sessions hit the taint ceiling: no writes, no external POST/PUT,
   no confidential-or-above data.

7. dlp/detectors.py — regex detectors (AWS keys, JWT, PEM private key headers,
   card numbers with Luhn, Aadhaar, connection strings) plus Shannon entropy
   over tokens >= 20 chars. Log which detector fired, NEVER the matched value.

8. Wire stages 4-7 of the pipeline to the real implementations.

9. tests/policy/*.yaml — declarative policy cases, at least 20.
   tests/test_invariants.py — all six invariants from section 3 of the context
   file, property-based (use hypothesis) where it makes sense.

10. .github/workflows/ci.yml — ruff, black --check, pytest, policy tests,
    policy compiler validation. Must pass with LLM_PROVIDER=mock and no key.

Definition of done: CI green, and when I deliberately break a policy rule the
build fails with a clear message. Show me that failure output.
```

---

## M3 — The proof

```
Read AGENTFW_CONTEXT.md, with particular attention to section 10.
Milestone M3 only.

1. attacks/a1..a7 — seven scripts, each self-contained and each printing:
   the attack description, what the agent attempted, the pipeline stage that
   stopped it, the policy id or reason, the risk score with its factor vector,
   and the resulting event. Build A6 (indirect prompt injection) FIRST and with
   the most care — it's the headline. The mock provider must script the agent
   genuinely complying with the injection, so the demo shows containment, not
   detection.

2. attacks/run_all.py — runs all seven, prints a clean summary table, exits
   non-zero if any attack is NOT blocked. This is the script a recruiter runs.

3. evals/corpus_attack.jsonl — at least 60 malicious agent behaviours across
   the categories: exfiltration, unauthorized destination, privilege
   escalation, injection-driven action, credential access, lateral movement,
   DLP-triggering payloads. Vary them realistically; don't just permute one
   template.

4. evals/corpus_benign.jsonl — at least 60 legitimate behaviours that a naive
   firewall would plausibly false-positive on. This corpus is the honest half;
   make it genuinely adversarial toward my own system.

5. evals/score.py — reports block rate on the attack corpus, FALSE POSITIVE
   RATE on the benign corpus, and p50/p95/p99 pipeline latency. Print all
   three together. A high block rate with a bad false-positive rate is a
   broken firewall and the output should make that impossible to hide.

6. dashboard/app.py — Streamlit. Live event feed, decisions over time, risk
   score distribution, top denied destinations, per-agent taint status, and a
   detail view showing one event's full factor vector. Keep it under 250 lines.

Definition of done: run_all.py shows 7/7 blocked with reasons, score.py prints
real measured numbers. Put those numbers in the README — the actual ones, from
the actual run. If a number is bad, we keep it and I'll explain it.
```

---

## M4 — Packaging

```
Read AGENTFW_CONTEXT.md. Milestone M4 — the last one.

1. Measure PEP latency properly: p50/p95/p99 for the full pipeline and broken
   down per stage, with and without DLP inspection. Use a real load run, at
   least 1000 requests. Put the methodology in the README so the numbers are
   auditable.

2. README.md, final version. Structure: the pitch, CI badge, the 30-second
   demo (leave a placeholder for the GIF — I'll record it), why this exists
   (the two broken assumptions of classic egress firewalls), run instructions,
   a results table with the real numbers, architecture diagram, a "Design
   decisions" section with 5 entries each naming what was GIVEN UP to get it,
   limitations, and what I'd do next.

3. docs/threat-model.md — STRIDE table plus the agent-specific threats, each
   mapped to the specific control in this codebase that addresses it, by file
   and function name.

4. docs/demo.md — a timed 5-minute live walkthrough script. Exact commands in
   order, what to say at each step, what the screen should show, and the three
   questions an interviewer is most likely to interrupt with plus the answers.

5. Review the whole repo as a hostile senior engineer would. Give me a
   prioritized list of the weakest things in it. Do not fix them yet — I want
   to see the list first and decide.

6. Fill in the resume bullets in AgentFW_Build_Plan_v2.md section 9 with the
   real measured numbers. If a number didn't get measured, leave the bracket
   empty rather than estimating.
```

---

## Micro-prompts for common moments

**When it drifts or over-builds:**
```
Stop. Re-read section 1 and section 8 of AGENTFW_CONTEXT.md. Show me what you
added that isn't in the current milestone's definition of done, and remove it.
```

**When something breaks:**
```
Don't patch around it. Find the root cause, show me the minimal reproduction,
tell me which invariant or design assumption it violates, then fix it.
```

**Before every commit:**
```
Run ruff, black --check, and the full test suite. Show me the output. Then
tell me in one sentence what security property this commit upholds.
```

**Interview prep, once M4 is done:**
```
Act as a skeptical Aviatrix interviewer who has read this repo. Ask me the ten
hardest questions about it, one at a time. After each answer, tell me what a
strong answer would have included that mine didn't.
```
