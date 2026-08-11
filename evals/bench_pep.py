"""M4 live PEP performance benchmark: measures the REAL deployed /v1/tool-call endpoint over a
live Docker network — end-to-end HTTP latency, not the in-process pipeline replay evals/score.py
measures. Run this from inside a container that's actually attested as `support-agent`
(`docker compose exec support-agent python -m evals.bench_pep`), since /attest derives identity
from the caller's real network position (identity/issuer.py) and cannot be told to impersonate a
different workload — the same structural fact documented in docs/verification-log.md's
Verification 5, finding 2.

WHY support_agent, and why these two specific tool calls, for the DLP-exercised vs DLP-not-triggered
comparison (see pep/pipeline.py's stage-5 gate: DLP runs iff
`policy_result.decision == ALLOW and (policy_result.inspect or _is_external(fqdn) or tool ==
"agent.invoke")`):

  DLP-exercised:     db.query table=customers   (R-SUPPORT-001, inspect: true -> DLP always runs)
  DLP-not-triggered: email.send to the approved helpdesk address
                      (R-SUPPORT-002, no inspect flag, and email.send's extract_target() never
                      produces an fqdn, so _is_external() is False too -> DLP never runs)

Both come from support_agent's own real charter, so this is a fair, apples-to-apples comparison —
same role, same baseline novelty state considerations, only the DLP gate differs. No new
dependency: httpx is already in requirements.txt; everything else is stdlib.

WHY the token is attested once and reused, not re-attested per request: this mirrors how a real
deployed agent actually behaves (agent/tools.py's _attest() caches its token for the process
lifetime) — re-attesting per call would benchmark identity/issuer.py's Docker-socket lookup, not
the PEP's own /v1/tool-call path this benchmark is about.

WHY denied/held requests are counted, not discarded: a DENY, QUARANTINE, or REQUIRE_APPROVAL
response still executed the full 8-stage pipeline server-side — dropping it from the sample would
undercount real pipeline work. Only genuine transport failures (connection refused, timeout) are
classified as errors.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import statistics
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

DEFAULT_PEP_URL = os.environ.get("PEP_URL", "http://pep:8080")
DEFAULT_IDENTITY_URL = os.environ.get("IDENTITY_ISSUER_URL", "http://identity:8082")

STAGE_NAMES = (
    "identity",
    "normalize",
    "policy",
    "threat_intel",
    "dlp",
    "risk",
    "decision",
    "log",
    "total",
)

WORKLOADS: dict[str, dict[str, Any]] = {
    "dlp_exercised": {
        "tool": "db.query",
        "arguments": {"table": "customers", "filter": "bench=1"},
        "why": "R-SUPPORT-001 sets inspect:true - DLP runs on every request, unconditionally.",
    },
    "dlp_not_triggered": {
        "tool": "email.send",
        "arguments": {"to": "reply@approved-helpdesk.com", "body": "bench probe, no payload"},
        "why": "R-SUPPORT-002 has no inspect flag and email.send has no fqdn, so the stage-5 "
        "gate (inspect or external-destination or agent.invoke) is never true.",
    },
}


@dataclass
class RequestRecord:
    start_ts: float
    end_ts: float
    latency_ms: float
    http_status: int | None
    decision: str | None
    reason: str | None
    outcome: str  # "success" (2xx, ALLOW/ALLOW_REDACTED/RATE_LIMIT) | "deny" (2xx, DENY/QUARANTINE/
    # REQUIRE_APPROVAL) | "error" (transport/HTTP failure - no pipeline execution happened)
    stage_latency_ms: dict[str, float] | None = None


@dataclass
class WorkloadResult:
    name: str
    records: list[RequestRecord] = field(default_factory=list)


async def _attest(identity_url: str) -> str:
    async with httpx.AsyncClient(trust_env=False, timeout=10.0) as client:
        resp = await client.post(f"{identity_url}/attest")
        resp.raise_for_status()
        return resp.json()["token"]


async def _one_request(
    client: httpx.AsyncClient,
    pep_url: str,
    token: str,
    tool: str,
    arguments: dict[str, Any],
    i: int,
) -> RequestRecord:
    t0 = time.perf_counter()
    start_ts = time.time()
    try:
        resp = await client.post(
            f"{pep_url}/v1/tool-call",
            json={
                "session_id": f"bench-{tool}",
                "trace_id": f"bench-{tool}-{i}",
                "tool": tool,
                "arguments": arguments,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        latency_ms = (time.perf_counter() - t0) * 1000
        body = resp.json()
        decision = body.get("decision")
        outcome = "success" if decision in ("ALLOW", "ALLOW_REDACTED", "RATE_LIMIT") else "deny"
        return RequestRecord(
            start_ts=start_ts,
            end_ts=time.time(),
            latency_ms=latency_ms,
            http_status=resp.status_code,
            decision=decision,
            reason=body.get("reason"),
            outcome=outcome,
            stage_latency_ms=body.get("latency_ms"),
        )
    except httpx.HTTPError as exc:
        latency_ms = (time.perf_counter() - t0) * 1000
        return RequestRecord(
            start_ts=start_ts,
            end_ts=time.time(),
            latency_ms=latency_ms,
            http_status=None,
            decision=None,
            reason=str(exc),
            outcome="error",
        )


async def run_workload(
    *,
    name: str,
    pep_url: str,
    token: str,
    tool: str,
    arguments: dict[str, Any],
    count: int,
    concurrency: int,
    warmup: int,
) -> WorkloadResult:
    async with httpx.AsyncClient(trust_env=False, timeout=30.0) as client:
        # Warm-up: discarded, not measured. WHY: first requests on a fresh connection pool pay
        # TCP/TLS-setup and Python import-caching costs a steady-state client never sees again.
        sem = asyncio.Semaphore(concurrency)

        async def _bounded(i: int) -> RequestRecord:
            async with sem:
                return await _one_request(client, pep_url, token, tool, arguments, i)

        if warmup:
            await asyncio.gather(*(_bounded(-i) for i in range(1, warmup + 1)))

        records = await asyncio.gather(*(_bounded(i) for i in range(count)))
    return WorkloadResult(name=name, records=list(records))


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, int(round(pct / 100 * (len(ordered) - 1)))))
    return ordered[k]


def summarize(result: WorkloadResult) -> dict[str, Any]:
    latencies = [r.latency_ms for r in result.records]
    by_outcome = {"success": 0, "deny": 0, "error": 0}
    for r in result.records:
        by_outcome[r.outcome] += 1

    stage_summary: dict[str, dict[str, float]] = {}
    for stage in STAGE_NAMES:
        values = [r.stage_latency_ms[stage] for r in result.records if r.stage_latency_ms]
        if values:
            stage_summary[stage] = {
                "p50": percentile(values, 50),
                "p95": percentile(values, 95),
                "p99": percentile(values, 99),
                "mean": statistics.fmean(values),
            }

    return {
        "workload": result.name,
        "request_count": len(result.records),
        "success_count": by_outcome["success"],
        "deny_count": by_outcome["deny"],
        "error_count": by_outcome["error"],
        "p50_ms": percentile(latencies, 50),
        "p95_ms": percentile(latencies, 95),
        "p99_ms": percentile(latencies, 99),
        "mean_ms": statistics.fmean(latencies) if latencies else 0.0,
        "stage_latency_ms": stage_summary,
    }


def _print_summary(summary: dict[str, Any]) -> None:
    print(f"\n=== workload: {summary['workload']} ===")
    print(
        f"requests: {summary['request_count']}  "
        f"success: {summary['success_count']}  deny: {summary['deny_count']}  "
        f"error: {summary['error_count']}"
    )
    print("end-to-end HTTP latency (client-measured, includes network + full pipeline):")
    print(
        f"  p50={summary['p50_ms']:.3f} ms  p95={summary['p95_ms']:.3f} ms  "
        f"p99={summary['p99_ms']:.3f} ms  mean={summary['mean_ms']:.3f} ms"
    )
    if summary["stage_latency_ms"]:
        print("per-stage latency (server-reported, from the PEP's own response body):")
        for stage in STAGE_NAMES:
            s = summary["stage_latency_ms"].get(stage)
            if s:
                print(
                    f"  {stage:<13} p50={s['p50']:.4f}  p95={s['p95']:.4f}  "
                    f"p99={s['p99']:.4f}  mean={s['mean']:.4f}  (ms)"
                )
    else:
        print("per-stage latency: unavailable (no successful responses with a latency_ms body)")


async def main_async(args: argparse.Namespace) -> dict[str, Any]:
    token = await _attest(args.identity_url)
    results = {}
    which = WORKLOADS.keys() if args.workload == "both" else [args.workload]
    for name in which:
        wl = WORKLOADS[name]
        result = await run_workload(
            name=name,
            pep_url=args.pep_url,
            token=token,
            tool=wl["tool"],
            arguments=wl["arguments"],
            count=args.requests,
            concurrency=args.concurrency,
            warmup=args.warmup,
        )
        summary = summarize(result)
        _print_summary(summary)
        results[name] = summary
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pep-url", dest="pep_url", default=DEFAULT_PEP_URL)
    parser.add_argument("--identity-url", dest="identity_url", default=DEFAULT_IDENTITY_URL)
    parser.add_argument("--requests", type=int, default=1000, help="requests per workload")
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--warmup", type=int, default=50, help="warm-up requests, discarded")
    parser.add_argument("--workload", choices=[*WORKLOADS.keys(), "both"], default="both")
    parser.add_argument("--json-out", dest="json_out", default=None, help="write full results here")
    args = parser.parse_args()

    print("=== AgentFW M4 live PEP benchmark ===")
    print(f"pep_url={args.pep_url} identity_url={args.identity_url}")
    print(
        f"requests_per_workload={args.requests} concurrency={args.concurrency} warmup={args.warmup}"
    )
    print(f"python={platform.python_version()} platform={platform.platform()}")
    for name, wl in WORKLOADS.items():
        if args.workload in (name, "both"):
            print(f"workload '{name}': tool={wl['tool']!r} - {wl['why']}")

    results = asyncio.run(main_async(args))

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"\nfull results written to {args.json_out}")

    error_counts = [r["error_count"] for r in results.values()]
    return 0 if all(e == 0 for e in error_counts) else 1


if __name__ == "__main__":
    raise SystemExit(main())
