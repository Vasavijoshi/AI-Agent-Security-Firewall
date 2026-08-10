"""Tests for dashboard/app.py's pure event-parsing functions (risk_buckets, top_denied_destinations)
— the only parts of a Streamlit page body that are meaningfully unit-testable without a Streamlit
runtime. The rest of dashboard/app.py was verified by actually running it locally against a
seeded eventstore (not part of this automated suite — see the M3 summary for what that covered)."""

from __future__ import annotations

from dashboard.app import risk_buckets, top_denied_destinations


def _event(decision, risk_score=0, fqdn=None, resource=None):
    return {
        "decision": decision,
        "risk_score": risk_score,
        "destination": {"fqdn": fqdn},
        "resource": resource,
    }


def test_risk_buckets_sorts_into_the_four_named_bands():
    events = [_event("ALLOW", 0), _event("ALLOW", 30), _event("DENY", 60), _event("QUARANTINE", 90)]
    buckets = risk_buckets(events)
    assert buckets["0-24 (LOW)"] == 1
    assert buckets["25-49 (MODERATE)"] == 1
    assert buckets["50-74 (HIGH)"] == 1
    assert buckets["75-100 (CRITICAL)"] == 1


def test_risk_buckets_on_no_events_is_all_zero():
    buckets = risk_buckets([])
    assert all(v == 0 for v in buckets.values())


def test_top_denied_destinations_only_counts_deny_and_quarantine():
    events = [
        _event("DENY", fqdn="evil.example.com"),
        _event("DENY", fqdn="evil.example.com"),
        _event("QUARANTINE", resource="credentials"),
        _event("ALLOW", fqdn="api.trusted-news.com"),  # must not be counted
    ]
    top = top_denied_destinations(events)
    assert ("evil.example.com", 2) in top
    assert ("credentials", 1) in top
    assert not any(dest == "api.trusted-news.com" for dest, _ in top)


def test_top_denied_destinations_respects_limit():
    events = [_event("DENY", fqdn=f"host{i}.example.com") for i in range(15)]
    top = top_denied_destinations(events, limit=5)
    assert len(top) == 5


def test_top_denied_destinations_falls_back_to_resource_when_no_fqdn():
    events = [_event("DENY", resource="hr_salaries")]
    top = top_denied_destinations(events)
    assert top == [("hr_salaries", 1)]
