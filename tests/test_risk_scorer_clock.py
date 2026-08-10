"""Tests for risk/scorer.py's injectable clock (risk.scorer.set_clock()) — added so the rate-window
logic (_is_rate_anomalous/record_outcome) can be driven deterministically during corpus replay
(evals/score.py) instead of reading the real wall clock, which would make RATE_ANOMALY a property
of how fast a replay loop iterates rather than a property of the traffic being scored.

The property that matters: the clock must affect verdicts ONLY through the rate window. A single
isolated call — nothing else nearby in whatever time source is active — must score identically
regardless of what the clock says, since nothing about that one call's own history changes.
"""

from __future__ import annotations

import time

import risk.scorer as risk_scorer
from attacks.common import reset_process_state, run_locally
from risk.scorer import RiskScorer


def _isolated_call_at(clock_value: float):
    """Reset all behavioral state, warm up the baseline, set the clock to a single fixed value,
    and make exactly one call — isolated enough that RATE_ANOMALY can never fire (one call is
    always < the 5-call/60s threshold), so nothing about *this* result should depend on what the
    clock said, only on the request itself."""
    reset_process_state()
    risk_scorer.set_clock(lambda: clock_value)
    try:
        RiskScorer.warm_up()
        result, _event = run_locally(
            role="research_agent",
            service="agent",
            tool="http.get",
            arguments={"url": "https://api.trusted-news.com/x"},
            session_id="clock-isolation-test",
        )
        return result
    finally:
        risk_scorer.set_clock(time.time)


def test_clock_value_does_not_affect_an_isolated_call():
    """Same record, wildly different absolute clock values, no other calls nearby in either run —
    decision and full factor vector must be identical."""
    result_early = _isolated_call_at(1_000.0)
    result_late = _isolated_call_at(1_000_000_000.0)

    assert result_early.decision == result_late.decision
    assert result_early.risk_score == result_late.risk_score
    assert result_early.risk_factors == result_late.risk_factors
    assert not any(f["code"] == "RATE_ANOMALY" for f in result_early.risk_factors)


def test_set_clock_actually_changes_what_is_rate_anomalous_sees():
    """The other half of the property: the clock DOES matter when there's a real rate window to
    evaluate — five prior calls within 60s of the clock's current value trips RATE_ANOMALY; the
    same five calls, now more than 60s in the past relative to a later clock value, must not."""
    reset_process_state()
    try:
        risk_scorer.set_clock(lambda: 0.0)
        risk_scorer._CALL_TIMES["agent"] = [0.0, 1.0, 2.0, 3.0, 4.0]  # 5 calls "just now"

        risk_scorer.set_clock(lambda: 5.0)  # 5s later: all 5 still inside the 60s window
        assert risk_scorer._is_rate_anomalous("agent") is True

        risk_scorer.set_clock(lambda: 1000.0)  # far later: all 5 now outside the 60s window
        assert risk_scorer._is_rate_anomalous("agent") is False
    finally:
        risk_scorer.set_clock(time.time)
        risk_scorer._CALL_TIMES.pop("agent", None)
