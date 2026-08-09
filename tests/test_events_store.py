"""Tests for events/store.py — durability and log-or-deny validation.

WHY these moved out of the old tests/test_m1_pipeline.py: that file also had M1-hardcoded-table
tests, deleted now that policy/engine.py has a real evaluator (see tests/test_policy_cases.py and
tests/test_pipeline_m2.py instead). The event-store tests below never depended on M1's stand-in
and stay valid unchanged.
"""

from __future__ import annotations

import pytest

from events.store import EventWriteError, read_all_events, write_event

_STAGES = (
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


def test_write_and_read_event_roundtrip(tmp_path):
    db_path = str(tmp_path / "events.db")
    event = _sample_event()
    write_event(event, db_path)
    stored = read_all_events(db_path)
    assert stored == [event]


def test_write_event_rejects_missing_required_field(tmp_path):
    db_path = str(tmp_path / "events.db")
    event = _sample_event()
    del event["risk_factors"]
    with pytest.raises(EventWriteError):
        write_event(event, db_path)
    # WHY re-read after the failed write: log-or-deny only means something if a rejected event
    # genuinely left nothing behind for an auditor to mistake for a real record.
    assert read_all_events(db_path) == []


def test_read_all_events_on_empty_store_returns_empty_list(tmp_path):
    db_path = str(tmp_path / "events.db")
    assert read_all_events(db_path) == []


def test_events_survive_across_separate_connections(tmp_path):
    """WHY this matters beyond the basic roundtrip: the eventstore container is a long-running
    process that reopens the SQLite file per request (events/app.py) — a bug that only surfaces
    across separate connections would be invisible to a single-connection test."""
    db_path = str(tmp_path / "events.db")
    write_event(_sample_event(trace_id="t1"), db_path)
    write_event(_sample_event(trace_id="t2"), db_path)
    stored = read_all_events(db_path)
    assert [e["trace_id"] for e in stored] == ["t1", "t2"]


def _sample_event(trace_id: str = "t1") -> dict:
    return {
        "schema_version": "1.0",
        "timestamp": "2026-08-09T00:00:00+00:00",
        "trace_id": trace_id,
        "session_id": "s1",
        "agent_id": "deadbeefcafe1",
        "role": "research_agent",
        "tool": "http.get",
        "action": "read",
        "destination": {"fqdn": "example.com", "ip": None, "port": 443, "protocol": "https"},
        "resource": "/",
        "data_classification": "internal",
        "session_taint": "clean",
        "risk_score": 0,
        "risk_factors": [],
        "policy_id": "R-RESEARCH-001",
        "policy_bundle_version": "2026.08.10-1",
        "decision": "ALLOW",
        "reason": "matched_explicit_allow",
        "latency_ms": {s: 0.0 for s in _STAGES},
    }
