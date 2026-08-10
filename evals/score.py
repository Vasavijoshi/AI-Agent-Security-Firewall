"""Scores evals/corpus_attack.jsonl and evals/corpus_benign.jsonl against the real pipeline: block
rate, false-positive rate, approval/throttle rates, and measured latency percentiles.

Verdict taxonomy (pre-M3 ruling):

    Blocked   = DENY or QUARANTINE           (policy.engine.BLOCKED_DECISIONS)
    Permitted = ALLOW, ALLOW_REDACTED,
                RATE_LIMIT, REQUIRE_APPROVAL  (policy.engine.PERMITTED_DECISIONS)

    Block rate            = blocked / attack corpus
    False-positive rate   = blocked / benign corpus

WHY there is no single "friction rate" here (M3 correction, after review): policy.engine's own
FRICTION_DECISIONS groups RATE_LIMIT and REQUIRE_APPROVAL together, but they are not the same kind
of event and reporting them as one number hides that. Per README.md's own "Decision lattice —
implementation status" table, REQUIRE_APPROVAL genuinely stops the call (no approval workflow
exists yet, so it's currently a dead end — the call never executes) while RATE_LIMIT is
designed-not-implemented and executes the call exactly like ALLOW, just narrowing the decision
value and logging it. A metric that averages "a human must intervene" with "logged verbosely and
proceeded anyway" cannot inform any decision — separating them is what makes the number actionable:

    Approval rate  = benign calls landing on REQUIRE_APPROVAL, over the benign corpus. The real
                      friction number: something a human is actually stopped by.
    Throttle rate  = benign calls landing on RATE_LIMIT, over the benign corpus. Reported
                      separately and labeled designed-not-implemented — visible, never conflated
                      with work that was actually stopped.

Corpus record schema (evals/corpus_attack.jsonl, evals/corpus_benign.jsonl) — designed for M3,
nothing pre-existing to match, since no evaluation input schema existed in this repo before this
milestone:

    {"id": str, "category": str, "role": str, "service": str, "tool": str,
     "arguments": {...}, "description": str, "offset_seconds": number}

One record = one tool call, replayed through pep.pipeline.run_pipeline() with a genuinely signed
token for `role`/`service` (attacks.common.run_locally — the same real-pipeline mechanism the nine
attack demonstrations use, not a fabricated decision). This is an in-process replay, not a live
Docker run: see AGENTFW_CONTEXT.md's standing no-Docker-in-this-environment caveat and each
attack's own REAL_DOCKER_VERIFIED/TEST_ONLY reporting for what that distinction means here.

WHY behavioral state (risk/scorer.py's novelty/rate/bigram tracking) is NOT reset between records
within one corpus: resetting per-record would make every single call look like a brand-new agent's
first-ever call, which is not what evaluating a corpus against a running deployment means — the
whole point of risk/baseline.jsonl's warm_up() is that a real deployment already has history behind
it. State IS reset once between the attack corpus and the benign corpus (attacks.common.
reset_process_state(), re-seeded from the baseline each time) so neither corpus's traffic
contaminates the other's scoring.

WHY offset_seconds exists and what it drives: replaying 65+ records in a tight Python loop takes
well under a second of real wall-clock time — if risk/scorer.py's rate-window logic read the real
clock, replay_corpus() would itself manufacture RATE_ANOMALY on almost every record purely from how
fast this process iterates a list, which is a property of the harness, not the traffic. Each
record's offset_seconds instead records its own realistic inter-arrival time (seconds since that
corpus's own replay started), and replay_corpus() drives risk/scorer.py's injectable clock
(risk.scorer.set_clock()) from those offsets — the scorer's own rate-window code is unmodified and
unaware it's being replayed (risk/scorer.py's own WHY on _clock explains the seam). Attack records
are bursty within a category on purpose (the burst often IS the attack); benign records use
per-category realistic spacing — see the generator's own comments for the reasoning per category.
"""

from __future__ import annotations

import json
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from policy.engine import BLOCKED_DECISIONS, Decision
from risk.scorer import RiskScorer

DEFAULT_ATTACK_CORPUS = "evals/corpus_attack.jsonl"
DEFAULT_BENIGN_CORPUS = "evals/corpus_benign.jsonl"

REQUIRED_FIELDS = (
    "id",
    "category",
    "role",
    "service",
    "tool",
    "arguments",
    "description",
    "offset_seconds",
)


class CorpusValidationError(Exception):
    """Raised by load_corpus() when a record is missing a required field or arguments isn't a
    dict — a malformed corpus is a build-time failure, not something to silently skip a line for."""


@dataclass(frozen=True)
class CorpusRecord:
    id: str
    category: str
    role: str
    service: str
    tool: str
    arguments: dict[str, Any]
    description: str
    offset_seconds: float


def load_corpus(path: str) -> list[CorpusRecord]:
    """Parse and validate every line of a corpus JSONL file. Raises CorpusValidationError on the
    first structurally invalid record, naming its id/line number — the whole point of validating
    before claiming completion (this milestone's own instruction) is that a bad record fails loudly
    here, not silently mis-scores three stages downstream."""
    records: list[CorpusRecord] = []
    for lineno, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        raw = json.loads(line)
        missing = [f for f in REQUIRED_FIELDS if f not in raw]
        if missing:
            raise CorpusValidationError(f"{path}:{lineno} missing required field(s): {missing}")
        if not isinstance(raw["arguments"], dict):
            raise CorpusValidationError(f"{path}:{lineno} 'arguments' must be an object")
        if not isinstance(raw["offset_seconds"], int | float) or isinstance(
            raw["offset_seconds"], bool
        ):
            raise CorpusValidationError(f"{path}:{lineno} 'offset_seconds' must be a number")
        records.append(CorpusRecord(**{k: raw[k] for k in REQUIRED_FIELDS}))
    return records


def _blocked_fraction(decisions: list[Decision]) -> float:
    if not decisions:
        return 0.0
    return sum(1 for d in decisions if d in BLOCKED_DECISIONS) / len(decisions)


def block_rate(attack_corpus_decisions: list[Decision]) -> float:
    """Block rate = blocked / attack corpus."""
    return _blocked_fraction(attack_corpus_decisions)


def false_positive_rate(benign_corpus_decisions: list[Decision]) -> float:
    """False-positive rate = blocked / benign corpus.

    WHY this isn't just block_rate() called on a different list: the formula is identical, but
    naming it separately is the point — conflating "block rate measured on attacks" with "block
    rate measured on benign traffic" behind one ambiguous function is exactly the kind of mixup
    this taxonomy exists to rule out before M3's scorer gets written.
    """
    return _blocked_fraction(benign_corpus_decisions)


def approval_rate(benign_corpus_decisions: list[Decision]) -> float:
    """Approval rate = benign calls landing on REQUIRE_APPROVAL, over the benign corpus. The real
    friction number: REQUIRE_APPROVAL is not executed (no approval workflow exists yet — see
    README.md's decision-lattice status table), so a benign call landing here is genuinely stopped,
    not logged-and-allowed. Never added into false_positive_rate()'s numerator — REQUIRE_APPROVAL
    is a distinct lattice point from DENY/QUARANTINE, not a misclassification as an attack."""
    if not benign_corpus_decisions:
        return 0.0
    stopped = sum(1 for d in benign_corpus_decisions if d == Decision.REQUIRE_APPROVAL)
    return stopped / len(benign_corpus_decisions)


def throttle_rate(benign_corpus_decisions: list[Decision]) -> float:
    """Throttle rate = benign calls landing on RATE_LIMIT, over the benign corpus. RATE_LIMIT is
    designed-not-implemented (policy/engine.py's own EXECUTABLE_DECISIONS includes it): the call
    executes exactly like ALLOW, just narrowed and logged. Reported on its own, deliberately not
    folded into approval_rate() or false_positive_rate() — conflating "executed normally" with
    "a human was stopped" is exactly the aggregate this split replaces."""
    if not benign_corpus_decisions:
        return 0.0
    throttled = sum(1 for d in benign_corpus_decisions if d == Decision.RATE_LIMIT)
    return throttled / len(benign_corpus_decisions)


def percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile — no interpolation, so the reported number is always a value that
    was actually measured, never an average of two measurements."""
    if not values:
        return 0.0
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, int(round(pct / 100 * (len(ordered) - 1)))))
    return ordered[k]


@dataclass
class ReplayOutcome:
    decisions: list[Decision]
    latencies_ms: list[float]
    rate_anomaly_hits: int  # how many records had RATE_ANOMALY in their factor vector


def replay_corpus(records: list[CorpusRecord]) -> ReplayOutcome:
    """Replay every record through the real pipeline, in order (state accumulates across records —
    see module WHY), with risk/scorer.py's rate-window clock driven by each record's own
    offset_seconds rather than the real wall clock — see module WHY on offset_seconds. Latency is
    measured around the actual run_pipeline() call, never invented; the clock swap doesn't touch
    that measurement, only what risk/scorer.py's rate-window logic sees when it asks the time."""
    import attacks.common as common
    import risk.scorer as risk_scorer

    decisions: list[Decision] = []
    latencies: list[float] = []
    rate_anomaly_hits = 0
    corpus_start = time.time()
    offset_holder = {"value": 0.0}
    risk_scorer.set_clock(lambda: corpus_start + offset_holder["value"])
    try:
        for i, rec in enumerate(records):
            offset_holder["value"] = rec.offset_seconds
            t0 = time.perf_counter()
            result, _event = common.run_locally(
                role=rec.role,
                service=rec.service,
                tool=rec.tool,
                arguments=rec.arguments,
                session_id=f"eval-{rec.id}-{i}",
            )
            latencies.append((time.perf_counter() - t0) * 1000)
            decisions.append(result.decision)
            if any(f["code"] == "RATE_ANOMALY" for f in result.risk_factors):
                rate_anomaly_hits += 1
    finally:
        risk_scorer.set_clock(time.time)
    return ReplayOutcome(
        decisions=decisions, latencies_ms=latencies, rate_anomaly_hits=rate_anomaly_hits
    )


def run_evaluation(
    attack_path: str = DEFAULT_ATTACK_CORPUS, benign_path: str = DEFAULT_BENIGN_CORPUS
) -> dict[str, Any]:
    import attacks.common as common

    attack_records = load_corpus(attack_path)
    benign_records = load_corpus(benign_path)

    # WHY reset_process_state() runs BEFORE warm_up(), not after: reset_process_state() clears
    # risk/scorer.py's _SEEN_BY_ORG/_SEEN_BY_AGENT along with the session/quarantine state it's
    # actually meant to isolate between the two corpora — calling it after warm_up() silently
    # discards the baseline seed it just replayed, so every corpus run scores against completely
    # cold state regardless of risk/baseline.jsonl's content. Caught via a real bug report: a
    # benign corpus with zero clean ALLOWs (friction + false-positive summing to exactly 100%) is
    # not a calibration finding, it's this ordering mistake.
    common.reset_process_state()
    RiskScorer.warm_up()
    attack_outcome = replay_corpus(attack_records)

    common.reset_process_state()
    RiskScorer.warm_up()
    benign_outcome = replay_corpus(benign_records)

    all_latencies = attack_outcome.latencies_ms + benign_outcome.latencies_ms
    return {
        "attack_corpus_size": len(attack_records),
        "benign_corpus_size": len(benign_records),
        "block_rate": block_rate(attack_outcome.decisions),
        "false_positive_rate": false_positive_rate(benign_outcome.decisions),
        "approval_rate": approval_rate(benign_outcome.decisions),
        "throttle_rate": throttle_rate(benign_outcome.decisions),
        "p50_latency_ms": percentile(all_latencies, 50),
        "p95_latency_ms": percentile(all_latencies, 95),
        "p99_latency_ms": percentile(all_latencies, 99),
        "mean_latency_ms": statistics.fmean(all_latencies) if all_latencies else 0.0,
        "total_calls_replayed": len(all_latencies),
        "attack_rate_anomaly_rate": attack_outcome.rate_anomaly_hits / len(attack_records)
        if attack_records
        else 0.0,
        "benign_rate_anomaly_rate": benign_outcome.rate_anomaly_hits / len(benign_records)
        if benign_records
        else 0.0,
    }


if __name__ == "__main__":
    report = run_evaluation()
    print(f"attack corpus size:    {report['attack_corpus_size']}")
    print(f"benign corpus size:    {report['benign_corpus_size']}")
    print(f"block rate:            {report['block_rate']:.1%}")
    print(f"false positive rate:   {report['false_positive_rate']:.1%}")
    print(f"approval rate:         {report['approval_rate']:.1%}")
    print("  (REQUIRE_APPROVAL - genuinely stopped, no approval workflow exists yet)")
    print(f"throttle rate:         {report['throttle_rate']:.1%}")
    print("  (RATE_LIMIT - designed-not-implemented, executes the call normally)")
    print(f"p50 latency:           {report['p50_latency_ms']:.3f} ms")
    print(f"p95 latency:           {report['p95_latency_ms']:.3f} ms")
    print(f"p99 latency:           {report['p99_latency_ms']:.3f} ms")
    print(f"mean latency:          {report['mean_latency_ms']:.3f} ms")
    print(f"total calls replayed:  {report['total_calls_replayed']}")
    print(f"RATE_ANOMALY on attack corpus:  {report['attack_rate_anomaly_rate']:.1%}")
    print(f"RATE_ANOMALY on benign corpus:  {report['benign_rate_anomaly_rate']:.1%}")
    print(
        "\nNOTE: this is an in-process replay of the real pipeline code (no Docker deployment in "
        "this environment) — see AGENTFW_CONTEXT.md's standing caveat. Latency here excludes the "
        "real network hop to a live PEP/identity/eventstore a Docker deployment would add. "
        "Rate-window timing is driven by each corpus record's own offset_seconds, not the real "
        "wall clock — see this module's WHY on offset_seconds."
    )
