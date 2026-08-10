"""Tests for evals/score.py's M3 additions: corpus loading/validation, the percentile helper, and
that the real committed corpora (evals/corpus_attack.jsonl, evals/corpus_benign.jsonl) are
themselves valid and meet the milestone's size requirement — a regression guard against a future
edit silently breaking the schema or shrinking below 60 records.
"""

from __future__ import annotations

import json

import pytest

from evals.score import (
    CorpusValidationError,
    load_corpus,
    percentile,
    replay_corpus,
    run_evaluation,
)


def test_real_attack_corpus_loads_and_meets_the_size_requirement():
    records = load_corpus("evals/corpus_attack.jsonl")
    assert len(records) >= 60
    assert len({r.category for r in records}) >= 5


def test_real_benign_corpus_loads_and_meets_the_size_requirement():
    records = load_corpus("evals/corpus_benign.jsonl")
    assert len(records) >= 60
    assert len({r.category for r in records}) >= 5


def test_missing_required_field_raises(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text(
        json.dumps({"id": "X-1", "category": "c", "role": "research_agent", "tool": "http.get"})
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(CorpusValidationError):
        load_corpus(str(path))


def test_non_dict_arguments_raises(tmp_path):
    path = tmp_path / "bad.jsonl"
    record = {
        "id": "X-1",
        "category": "c",
        "role": "research_agent",
        "service": "agent",
        "tool": "http.get",
        "arguments": "not-a-dict",
        "description": "x",
        "offset_seconds": 0.0,
    }
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(CorpusValidationError):
        load_corpus(str(path))


def test_non_numeric_offset_seconds_raises(tmp_path):
    path = tmp_path / "bad.jsonl"
    record = {
        "id": "X-1",
        "category": "c",
        "role": "research_agent",
        "service": "agent",
        "tool": "http.get",
        "arguments": {"url": "https://api.trusted-news.com/x"},
        "description": "x",
        "offset_seconds": "soon",
    }
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(CorpusValidationError):
        load_corpus(str(path))


def test_blank_lines_are_skipped(tmp_path):
    path = tmp_path / "ok.jsonl"
    record = {
        "id": "X-1",
        "category": "c",
        "role": "research_agent",
        "service": "agent",
        "tool": "http.get",
        "arguments": {"url": "https://api.trusted-news.com/x"},
        "description": "x",
        "offset_seconds": 0.0,
    }
    path.write_text("\n" + json.dumps(record) + "\n\n", encoding="utf-8")
    records = load_corpus(str(path))
    assert len(records) == 1


def test_percentile_on_a_known_set():
    values = [float(x) for x in range(1, 101)]  # 1..100
    assert percentile(values, 50) == pytest.approx(51, abs=2)
    assert percentile(values, 0) == 1
    assert percentile(values, 100) == 100


def test_percentile_on_empty_list_is_zero():
    assert percentile([], 50) == 0.0


def test_run_evaluation_actually_uses_the_warmed_up_baseline():
    """Regression test for a real bug: run_evaluation() used to call
    common.reset_process_state() *after* RiskScorer.warm_up(), which wiped the org/agent novelty
    state warm_up() had just seeded, so every corpus run scored against completely cold state
    regardless of risk/baseline.jsonl's content — a benign corpus with zero clean ALLOWs (block +
    friction summing to exactly 100%) was the symptom that caught it. A destination baselined for
    a registered agent (research_agent's "api.trusted-news.com") must not still look brand-new by
    the time the corpus replay reaches it."""
    import attacks.common as common
    import risk.scorer as risk_scorer

    common.reset_process_state()
    from risk.scorer import RiskScorer

    RiskScorer.warm_up()
    assert "api.trusted-news.com" in risk_scorer._SEEN_BY_ORG  # would fail if wiped right after

    report = run_evaluation()
    assert report["false_positive_rate"] < 1.0  # not every benign call blocked
    assert report["friction_rate"] < 1.0  # not literally 100% friction either


def test_replay_corpus_returns_one_decision_and_latency_per_record(tmp_path):
    path = tmp_path / "tiny.jsonl"
    records = [
        {
            "id": f"X-{i}",
            "category": "c",
            "role": "research_agent",
            "service": "agent",
            "tool": "http.get",
            "arguments": {"url": "https://api.trusted-news.com/x"},
            "description": "x",
            "offset_seconds": i * 200.0,  # well-spaced: no RATE_ANOMALY interference
        }
        for i in range(3)
    ]
    path.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
    loaded = load_corpus(str(path))
    outcome = replay_corpus(loaded)
    assert len(outcome.decisions) == 3
    assert len(outcome.latencies_ms) == 3
    assert all(ms >= 0 for ms in outcome.latencies_ms)
    assert outcome.rate_anomaly_hits == 0
