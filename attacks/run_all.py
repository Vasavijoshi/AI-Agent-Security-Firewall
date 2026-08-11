"""Runs the M3/M4 attack suite: A1-A9 as independently isolated verifications, plus A10 as a
separate, clearly-labeled deliberate demonstration of quarantine cascade/persistence.

WHY this file changed shape (docs/hostile-review.md C1/C2 — the finding this rewrite fixes): the
previous version ran all nine attacks in one shared process/container, sharing one persistent
eventstore. Two consequences followed, both caught by reading real Docker output line-by-line
rather than trusting a "9/9 BLOCKED" summary (docs/verification-log.md Verifications 5-6):

  C1 - every attack's live identity was whichever container actually invoked it, never the role
       the attack claims to simulate (identity/issuer.py's /attest is deliberately IP-derived, not
       self-asserted - correct design, but it means a script's OWN role claim was never checked
       against what was ACTUALLY attested).
  C2 - an early attack could quarantine the shared workload, after which every later attack was
       denied by AGENT_QUARANTINED instead of its own claimed mechanism, silently.

This version fixes both structurally rather than papering over them:
  - Docker dispatch mode: each of A1-A9 is run via `docker compose run --rm <service> ...` in the
    compose container that genuinely attests as the role that attack requires (attacks/common.py's
    ROLE_TO_SERVICE) - `run`, not `exec`, since agent/finance-agent/support-agent are one-shot
    batch jobs with no long-running container for `exec` to target (see `_dispatch()` below). A
    role with no real deployed service (admin_agent) is never given a fake one; that attack is
    structurally UNVERIFIED, honestly, every time.
  - Quarantine is cleared and verified empty immediately BEFORE each of A1-A9, using only
    events/app.py's existing, real, public GET/DELETE /quarantine admin routes - the same routes a
    human operator already uses (docs/verification-log.md Verification 6). No eventstore internals
    are touched and no new backdoor route exists anywhere in this repo.
  - A10 is run separately, AFTER A1-A9, with quarantine cleared once before it and deliberately NOT
    cleared between its two calls - it demonstrates the cascade on purpose and is never counted
    toward the A1-A9 independent-verification total.
  - Every attack now asserts its own expected decision/reason (attacks/common.py's
    assess_mechanism()) - a denial for the wrong reason is a loud, explicit mismatch, not a quiet
    pass.

In-process fallback (no Docker reachable): every attack still runs, in one process, via direct
import + call - the "fast demo" path this project has always supported
(`python -m attacks.run_all`, no Docker, no API key). Each attack's own live-verification step
correctly, honestly reports UNVERIFIED in that mode, since there is no live stack to reach.

WHY this module imports NONE of attacks.a1..a10/attacks.common/risk.scorer at module level, only
inside `_run_in_process_fallback()`: the whole point of Docker dispatch mode is that the actual
enforcement code (pep.pipeline -> identity.tokens -> the `cryptography` package, fastapi, httpx,
...) runs INSIDE the containers this script dispatches to via `docker compose run` - never in
this script's own process. A host running this orchestrator needs only `docker` on PATH and the
Python standard library (subprocess, json, shutil) - never a project dependency install on the
host. An earlier version imported those attack modules unconditionally at the top of this file,
which meant `python -m attacks.run_all` on a bare host with no project dependencies installed
crashed with `ModuleNotFoundError: No module named 'cryptography'` before Docker dispatch mode
ever got a chance to run - a real bug, not a hypothetical, caught by an actual first live-run
attempt. Those imports are now deferred to exactly the one code path that legitimately needs them:
the no-Docker, in-process fallback, which was always going to need a real dependency install
anyway (the "Fast demo" section of the README's own venv + `pip install -r requirements.txt`
instructions), just never from Docker dispatch mode.

Exit code is 0 only when every one of A1-A9 is genuinely_verified (REAL_DOCKER_VERIFIED AND its own
claimed mechanism matched) AND A10 genuinely demonstrated the cascade; non-zero otherwise.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys

# WHY "UNVERIFIED" is a literal string here, not imported from attacks.common: importing
# attacks.common at module level pulls in pep.pipeline -> identity.tokens -> `cryptography`,
# exactly the import chain this module must not require on a bare host in Docker dispatch mode.
# The two must always agree; attacks.common.UNVERIFIED == "UNVERIFIED" is asserted by
# tests/test_run_all.py.
_UNVERIFIED = "UNVERIFIED"

# attack_id -> (dotted module path, compose service that genuinely attests as the role this
# scenario requires). Pure data, no imports - safe to build at module level in either mode.
#
# WHY A3 dispatches to "agent" rather than being skipped: admin_agent has no real compose service
# (docs/hostile-review.md C1 fix - not worked around by inventing one). Running it from `agent`
# still exercises the real live path end to end; try_live_pep_call_verified()'s role check
# correctly and structurally reports UNVERIFIED every time, which is the honest answer, not a
# special case bolted onto the dispatcher.
ATTACK_SPECS: list[tuple[str, str, str]] = [
    ("A1", "attacks.a1", "agent"),
    ("A2", "attacks.a2", "finance-agent"),
    ("A3", "attacks.a3", "agent"),
    ("A4", "attacks.a4", "agent"),
    ("A5", "attacks.a5", "support-agent"),
    ("A6", "attacks.a6", "agent"),
    ("A7", "attacks.a7", "agent"),
    ("A8", "attacks.a8", "finance-agent"),
    ("A9", "attacks.a9", "agent"),
]

_QUARANTINE_LIST_SCRIPT = (
    "import json,urllib.request;"
    "print(json.dumps(json.load(urllib.request.urlopen('http://localhost:8090/quarantine'))))"
)
_QUARANTINE_CLEAR_SCRIPT = (
    "import json,urllib.request;"
    "d=json.load(urllib.request.urlopen('http://localhost:8090/quarantine'));"
    "[urllib.request.urlopen(urllib.request.Request("
    "f'http://localhost:8090/quarantine/{a}',method='DELETE')) for a in d];"
    "print(json.dumps(d))"
)


def _docker_compose(args: list[str], timeout: float = 30.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", *args], capture_output=True, text=True, timeout=timeout
    )


def _stack_reachable() -> bool:
    """A real check, not a guess: `docker` must exist on PATH and `docker compose ps` must show
    eventstore/identity/pep genuinely running, since the dispatch model below depends on all
    three (eventstore for quarantine admin, identity+pep for every attack's live path)."""
    if shutil.which("docker") is None:
        return False
    try:
        proc = _docker_compose(["ps", "--format", "{{.Service}} {{.State}}"])
    except (OSError, subprocess.TimeoutExpired):
        return False
    if proc.returncode != 0:
        return False
    services: dict[str, str] = {}
    for line in proc.stdout.strip().splitlines():
        parts = line.rsplit(" ", 1)
        if len(parts) == 2:
            services[parts[0]] = parts[1]
    required = {"eventstore", "identity", "pep"}
    return required.issubset(services) and all("running" in services[s].lower() for s in required)


def _eventstore_exec(python_code: str) -> str:
    proc = _docker_compose(["exec", "-T", "eventstore", "python", "-c", python_code])
    if proc.returncode != 0:
        raise RuntimeError(
            f"docker compose exec eventstore python -c '...' failed (exit {proc.returncode}): "
            f"{proc.stderr.strip()}"
        )
    return proc.stdout.strip()


def clear_and_verify_quarantine(*, label: str) -> None:
    """The C2 fix's reset step: uses ONLY events/app.py's existing, real, public GET/DELETE
    /quarantine routes - the same admin surface docs/verification-log.md's Verification 6 already
    exercised by hand. No eventstore internals are touched, no in-memory state is mutated
    directly, and no new route or backdoor is added anywhere in this repo."""
    before_raw = _eventstore_exec(_QUARANTINE_LIST_SCRIPT)
    before = json.loads(before_raw) if before_raw else {}
    if before:
        cleared_raw = _eventstore_exec(_QUARANTINE_CLEAR_SCRIPT)
        print(
            f"  [{label}] quarantine was non-empty ({cleared_raw}) - released via "
            "DELETE /quarantine/{id}"
        )
    after_raw = _eventstore_exec(_QUARANTINE_LIST_SCRIPT)
    after = json.loads(after_raw) if after_raw else {}
    if after:
        raise RuntimeError(f"quarantine reset failed to reach empty state: still shows {after}")
    print(f"  [{label}] quarantine verified empty (GET /quarantine -> {{}})")


def _show_quarantine_state(*, label: str) -> None:
    raw = _eventstore_exec(_QUARANTINE_LIST_SCRIPT)
    print(f"  [{label}] GET /quarantine -> {raw}")


def _dispatch(module_path: str, service: str, *, timeout: float = 45.0) -> dict:
    """Run one attack inside the compose container that genuinely attests as the role it needs -
    the C1 fix. Parses the RESULT_JSON: line attacks/common.py's emit_result_json() prints.

    WHY `docker compose run --rm`, not `docker compose exec`: found by an actual first live
    dispatch attempt, not review. `agent`/`finance-agent`/`support-agent` are one-shot batch jobs
    (docker-compose.yml: "no restart policy... expected to show Exited(0)") - once their default
    scenario finishes, `docker compose exec <service>` fails with "service is not running", since
    exec targets an already-running container. `docker compose run` creates a fresh, correctly
    networked container from that service's own definition on demand instead - it doesn't need the
    service to already be up. `--rm` cleans the container up afterward so ten dispatches (A1-A9 +
    A10) don't leave ten stopped containers behind; `--no-deps` skips redundantly trying to
    (re)start identity/pep/eventstore, which are already up and healthy by the time this runs."""
    proc = _docker_compose(
        ["run", "--rm", "-T", "--no-deps", service, "python", "-m", module_path], timeout=timeout
    )
    print(proc.stdout)
    if proc.stderr.strip():
        print(proc.stderr, file=sys.stderr)
    for line in proc.stdout.splitlines():
        if line.startswith("RESULT_JSON:"):
            return json.loads(line[len("RESULT_JSON:") :])
    raise RuntimeError(
        f"{module_path} (service={service}) produced no RESULT_JSON line - cannot verify its "
        f"outcome. stdout tail: {proc.stdout[-500:]!r} stderr tail: {proc.stderr[-500:]!r}"
    )


def _run_docker_mode() -> tuple[list[dict], dict]:
    print("=== Docker dispatch mode: docker compose reachable, dispatching per-role ===\n")
    print("(this process itself imports no project dependencies - only `docker`, stdlib)\n")
    results: list[dict] = []
    for attack_id, module_path, service in ATTACK_SPECS:
        print(f"--- {attack_id}: clearing quarantine, dispatching to service={service!r} ---")
        clear_and_verify_quarantine(label=attack_id)
        result = _dispatch(module_path, service)
        results.append(result)

    print("\n=== A10: deliberate quarantine-cascade demonstration (NOT independent evidence) ===")
    print("--- clearing quarantine once before A10 (not cleared again between its two calls) ---")
    clear_and_verify_quarantine(label="A10-setup")
    cascade_result = _dispatch("attacks.a10", "agent", timeout=45.0)
    _show_quarantine_state(label="A10-after (workload remains quarantined on purpose)")
    clear_and_verify_quarantine(label="final cleanup")

    return results, cascade_result


def _run_in_process_fallback() -> tuple[list[dict], dict]:
    """WHY the attack/risk/common imports live here, not at module level: this is the one code
    path that legitimately needs the full project dependency set (fastapi, httpx, cryptography,
    ...) in THIS process, because there's no Docker to dispatch into - see the module docstring."""
    import importlib

    import attacks.a10 as a10
    from attacks.common import AttackResult, print_report
    from risk.scorer import RiskScorer

    print("=== In-process fallback: docker/docker compose not reachable ===")
    print("Every attack still runs, via direct import in this one process. Each attack's own live")
    print("path will correctly report UNVERIFIED in this mode - no Docker to genuinely attest")
    print("against, and this fallback is never treated as a substitute for that (see each")
    print("attack's own notes).\n")
    RiskScorer.warm_up()

    results: list[dict] = []
    for _attack_id, module_path, _service in ATTACK_SPECS:
        module = importlib.import_module(module_path)
        result: AttackResult = module.run()
        print_report(result)
        results.append(_attack_result_to_dict(result))

    print("\n=== A10: deliberate quarantine-cascade demonstration (NOT independent evidence) ===")
    print("Not meaningfully demonstrable without a live, shared eventstore across two real calls -")
    print("reported UNVERIFIED for both calls in this mode, honestly, rather than simulated.")
    cascade = a10.run()
    a10.print_cascade_report(cascade)
    cascade_result = {
        "demonstrates_cascade": cascade.demonstrates_cascade,
        "call_1": cascade.call_1.__dict__ if cascade.call_1 else None,
        "call_2": cascade.call_2.__dict__ if cascade.call_2 else None,
    }
    return results, cascade_result


def _attack_result_to_dict(r) -> dict:
    return {
        "attack_id": r.attack_id,
        "category": r.category,
        "verification_status": r.verification_status,
        "decision": r.decision,
        "reason": r.reason,
        "policy_id": r.policy_id,
        "stage": r.stage,
        "expected_decision": r.expected_decision,
        "expected_reason": r.expected_reason,
        "mechanism_match": r.mechanism_match,
        "blocked": r.blocked,
        "genuinely_verified": r.genuinely_verified,
        "risk_score": r.risk_score,
    }


def _print_summary(results: list[dict], cascade_result: dict) -> None:
    header = f"{'Attack':<7}{'Category':<24}{'Status':<20}{'Mechanism':<12}{'Reason':<24}"
    print("\n" + "=" * len(header))
    print(header)
    print("-" * len(header))
    for r in results:
        mech = (
            "MATCH"
            if r["mechanism_match"] is True
            else ("MISMATCH" if r["mechanism_match"] is False else "n/a")
        )
        print(
            f"{r['attack_id']:<7}{r['category']:<24}{r['verification_status']:<20}{mech:<12}"
            f"{str(r['reason'])[:22]:<24}"
        )
    print("-" * len(header))

    verified_count = sum(1 for r in results if r["genuinely_verified"])
    total = len(results)
    print(
        f"\n{verified_count}/{total} A1-A9 GENUINELY VERIFIED "
        "(real Docker, correct role, own mechanism confirmed)"
    )

    unverified = [r["attack_id"] for r in results if r["verification_status"] == _UNVERIFIED]
    if unverified:
        print(f"UNVERIFIED (real Docker path not reached or wrong role): {', '.join(unverified)}")
    mismatched = [
        r["attack_id"]
        for r in results
        if r["verification_status"] != _UNVERIFIED and r["mechanism_match"] is False
    ]
    if mismatched:
        print(
            "*** MECHANISM MISMATCH (reached live, but wrong reason - a real failure): "
            f"{', '.join(mismatched)} ***"
        )

    print(
        "\nA10 (deliberate cascade demo, NOT counted above): "
        f"demonstrates_cascade={cascade_result['demonstrates_cascade']}"
    )


def main() -> int:
    docker_mode = _stack_reachable()
    if docker_mode:
        results, cascade_result = _run_docker_mode()
    else:
        results, cascade_result = _run_in_process_fallback()

    _print_summary(results, cascade_result)

    all_verified = all(r["genuinely_verified"] for r in results)
    cascade_ok = cascade_result["demonstrates_cascade"] or not docker_mode
    return 0 if (all_verified and cascade_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
