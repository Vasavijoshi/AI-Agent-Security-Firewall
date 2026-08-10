"""Scores evals/corpus_attack.jsonl and evals/corpus_benign.jsonl against the real pipeline: block
rate, false-positive rate, friction rate, and measured latency percentiles.

Verdict taxonomy (pre-M3 ruling):

    Blocked   = DENY or QUARANTINE           (policy.engine.BLOCKED_DECISIONS)
    Permitted = ALLOW, ALLOW_REDACTED,
                RATE_LIMIT, REQUIRE_APPROVAL  (policy.engine.PERMITTED_DECISIONS)

    Block rate            = blocked / attack corpus
    False-positive rate   = blocked / benign corpus
    Friction rate          = benign calls landing on RATE_LIMIT or REQUIRE_APPROVAL, over the
                              benign corpus — NOT a false positive (the call wasn't blocked), but
                              not free either. Reported on its own, never folded into either the
                              false-positive or the "clean permit" bucket.

Corpus record schema (evals/corpus_attack.jsonl, evals/corpus_benign.jsonl) — designed for M3,
nothing pre-existing to match, since no evaluation input schema existed in this repo before this
milestone:

    {"id": str, "category": str, "role": str, "service": str, "tool": str,
     "arguments": {...}, "description": str}

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
"""

from __future__ import annotations

import json
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from policy.engine import BLOCKED_DECISIONS, FRICTION_DECISIONS, Decision
from risk.scorer import RiskScorer

DEFAULT_ATTACK_CORPUS = "evals/corpus_attack.jsonl"
DEFAULT_BENIGN_CORPUS = "evals/corpus_benign.jsonl"

REQUIRED_FIELDS = ("id", "category", "role", "service", "tool", "arguments", "description")


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


def friction_rate(benign_corpus_decisions: list[Decision]) -> float:
    """Friction rate = benign calls landing on RATE_LIMIT or REQUIRE_APPROVAL, over the benign
    corpus. Never added into false_positive_rate()'s numerator — a held-for-approval benign call
    is friction the firewall imposes, not a misclassification of it as an attack."""
    if not benign_corpus_decisions:
        return 0.0
    friction = sum(1 for d in benign_corpus_decisions if d in FRICTION_DECISIONS)
    return friction / len(benign_corpus_decisions)


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


def replay_corpus(records: list[CorpusRecord]) -> ReplayOutcome:
    """Replay every record through the real pipeline, in order (state accumulates across records —
    see module WHY). Latency is measured around the actual run_pipeline() call, never invented."""
    import attacks.common as common

    decisions: list[Decision] = []
    latencies: list[float] = []
    for i, rec in enumerate(records):
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
    return ReplayOutcome(decisions=decisions, latencies_ms=latencies)


def run_evaluation(
    attack_path: str = DEFAULT_ATTACK_CORPUS, benign_path: str = DEFAULT_BENIGN_CORPUS
) -> dict[str, Any]:
    import attacks.common as common

    attack_records = load_corpus(attack_path)
    benign_records = load_corpus(benign_path)

    RiskScorer.warm_up()
    common.reset_process_state()
    attack_outcome = replay_corpus(attack_records)

    RiskScorer.warm_up()
    common.reset_process_state()
    benign_outcome = replay_corpus(benign_records)

    all_latencies = attack_outcome.latencies_ms + benign_outcome.latencies_ms
    return {
        "attack_corpus_size": len(attack_records),
        "benign_corpus_size": len(benign_records),
        "block_rate": block_rate(attack_outcome.decisions),
        "false_positive_rate": false_positive_rate(benign_outcome.decisions),
        "friction_rate": friction_rate(benign_outcome.decisions),
        "p50_latency_ms": percentile(all_latencies, 50),
        "p95_latency_ms": percentile(all_latencies, 95),
        "p99_latency_ms": percentile(all_latencies, 99),
        "mean_latency_ms": statistics.fmean(all_latencies) if all_latencies else 0.0,
        "total_calls_replayed": len(all_latencies),
    }


if __name__ == "__main__":
    report = run_evaluation()
    print(f"attack corpus size:    {report['attack_corpus_size']}")
    print(f"benign corpus size:    {report['benign_corpus_size']}")
    print(f"block rate:            {report['block_rate']:.1%}")
    print(f"false positive rate:   {report['false_positive_rate']:.1%}")
    print(f"friction rate:         {report['friction_rate']:.1%}")
    print(f"p50 latency:           {report['p50_latency_ms']:.3f} ms")
    print(f"p95 latency:           {report['p95_latency_ms']:.3f} ms")
    print(f"p99 latency:           {report['p99_latency_ms']:.3f} ms")
    print(f"mean latency:          {report['mean_latency_ms']:.3f} ms")
    print(f"total calls replayed:  {report['total_calls_replayed']}")
    print(
        "\nNOTE: this is an in-process replay of the real pipeline code (no Docker deployment in "
        "this environment) — see AGENTFW_CONTEXT.md's standing caveat. Latency here excludes the "
        "real network hop to a live PEP/identity/eventstore a Docker deployment would add."
    )
