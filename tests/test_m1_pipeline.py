"""Tests for M1's pipeline stand-in (pep/pipeline.py) and event durability (events/store.py).

WHY these live outside test_invariants.py: that file is reserved for the 6 formal,
property-tested invariants in AGENTFW_CONTEXT.md §3, built with Hypothesis in M2 once the real
policy engine exists. These are example-based tests against M1's hardcoded stand-in and will be
deleted, not extended, once policy/engine.py grows a real evaluator.
"""

from __future__ import annotations

import pytest

from events.store import EventWriteError, read_all_events, write_event
from pep.pipeline import PIPELINE_STAGES, run_pipeline
from policy.engine import Decision


def test_allowed_call_matches_explicit_rule():
    result = run_pipeline("research-agent-01", "http.get", header_agent_id="research-agent-01")
    assert result.decision == Decision.ALLOW
    assert result.reason == "matched_explicit_allow"
    assert result.policy_id == "R-M1-001"


def test_denied_call_matches_explicit_deny_rule():
    result = run_pipeline("research-agent-01", "http.post", header_agent_id="research-agent-01")
    assert result.decision == Decision.DENY
    assert result.reason == "matched_explicit_deny"
    assert result.policy_id == "R-M1-002"


def test_no_matching_rule_is_default_deny():
    """Invariant §3.2 (no-implicit-allow), exercised against the M1 hardcoded table specifically:
    a role/tool pair absent from HARDCODED_RULES must deny, not silently pass through."""
    result = run_pipeline("research-agent-01", "db.query", header_agent_id="research-agent-01")
    assert result.decision == Decision.DENY
    assert result.reason == "no_matching_rule"
    assert result.policy_id == "DEFAULT_DENY"


def test_unregistered_agent_denied_at_identity_stage():
    result = run_pipeline("nobody", "http.get", header_agent_id="nobody")
    assert result.decision == Decision.DENY
    assert result.reason == "identity_verification_failed"
    assert result.role is None


def test_header_agent_id_must_match_body_agent_id():
    """The M1 identity stub's one real check: a caller can't claim a different agent_id in the
    body than the one asserted by the header it actually sent."""
    result = run_pipeline("research-agent-01", "http.get", header_agent_id="someone-else")
    assert result.decision == Decision.DENY
    assert result.reason == "identity_verification_failed"


def test_every_pipeline_stage_reports_a_latency():
    result = run_pipeline("research-agent-01", "http.get", header_agent_id="research-agent-01")
    for stage in PIPELINE_STAGES:
        assert stage in result.latency_ms
    assert result.latency_ms["total"] == pytest.approx(
        sum(result.latency_ms[s] for s in PIPELINE_STAGES)
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


def _sample_event() -> dict:
    return {
        "schema_version": "1.0",
        "timestamp": "2026-08-09T00:00:00+00:00",
        "trace_id": "t1",
        "session_id": "s1",
        "agent_id": "research-agent-01",
        "role": "research_agent",
        "tool": "http.get",
        "action": "read",
        "destination": {"fqdn": "example.com", "ip": None, "port": 443, "protocol": "https"},
        "resource": "/",
        "data_classification": "internal",
        "session_taint": "clean",
        "risk_score": 0,
        "risk_factors": [],
        "policy_id": "R-M1-001",
        "policy_bundle_version": "m1-hardcoded",
        "decision": "ALLOW",
        "reason": "matched_explicit_allow",
        "latency_ms": {s: 0.0 for s in PIPELINE_STAGES} | {"total": 0.0},
    }
