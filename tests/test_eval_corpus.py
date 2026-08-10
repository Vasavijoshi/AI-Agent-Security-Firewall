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
        }
        for i in range(3)
    ]
    path.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
    loaded = load_corpus(str(path))
    outcome = replay_corpus(loaded)
    assert len(outcome.decisions) == 3
    assert len(outcome.latencies_ms) == 3
    assert all(ms >= 0 for ms in outcome.latencies_ms)
