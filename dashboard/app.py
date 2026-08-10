"""Streamlit dashboard: reads the real eventstore over HTTP (events/app.py's GET /events) and
renders decisions, risk factors, and denial reasons — no separate event format of its own.

WHY no secrets ever appear here: this reads events/schema.json's own event shape, which never
carries a DLP-matched value or credential to begin with (dlp/detectors.py's own rule: scan()
returns detector names and severities only) — there is nothing to redact because nothing sensitive
was ever written to the store this dashboard reads from.

WHY the page body lives in main(), guarded by `if __name__ == "__main__"`, rather than running at
module level: `streamlit run app.py` executes this file with __name__ == "__main__" (Streamlit's
own execution model), so that guard doesn't change how the app runs — but it does mean a plain
`import dashboard.app` (tests/test_dashboard.py, importing risk_buckets/top_denied_destinations)
no longer tries to fetch a live eventstore and call st.stop() outside a real Streamlit session,
which errors immediately with no ScriptRunContext to stop.
"""

from __future__ import annotations

import os
from collections import Counter
from typing import Any

import httpx
import streamlit as st

EVENTSTORE_URL = os.environ.get("EVENTSTORE_URL", "http://eventstore:8090")


def risk_buckets(events: list[dict[str, Any]]) -> dict[str, int]:
    """Pure event-parsing logic, pulled out of the page body so it's unit-testable without a
    Streamlit runtime (tests/test_dashboard.py)."""
    buckets = {"0-24 (LOW)": 0, "25-49 (MODERATE)": 0, "50-74 (HIGH)": 0, "75-100 (CRITICAL)": 0}
    for e in events:
        score = e.get("risk_score", 0)
        if score >= 75:
            buckets["75-100 (CRITICAL)"] += 1
        elif score >= 50:
            buckets["50-74 (HIGH)"] += 1
        elif score >= 25:
            buckets["25-49 (MODERATE)"] += 1
        else:
            buckets["0-24 (LOW)"] += 1
    return buckets


def top_denied_destinations(events: list[dict[str, Any]], limit: int = 10) -> list[tuple[str, int]]:
    """Same reasoning as risk_buckets(): pure, unit-testable event parsing."""
    denied = [e for e in events if e["decision"] in ("DENY", "QUARANTINE")]
    counts: Counter[str] = Counter()
    for e in denied:
        fqdn = (e.get("destination") or {}).get("fqdn")
        counts[fqdn or e.get("resource") or "(none)"] += 1
    return counts.most_common(limit)


def _fetch_events(url: str) -> list[dict[str, Any]] | None:
    """Returns None on a fetch failure (eventstore unreachable) so the caller can distinguish that
    from "reachable, zero events so far" — a real live-stack outage vs. an honestly empty demo."""
    try:
        resp = httpx.get(f"{url}/events", timeout=5.0)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError:
        return None


def main() -> None:
    st.set_page_config(page_title="AgentFW", layout="wide")
    st.title("AgentFW")
    st.caption("Zero Trust enforcement dashboard — reads the live event store, nothing fabricated.")

    events = st.cache_data(ttl=3.0)(_fetch_events)(EVENTSTORE_URL)

    if events is None:
        st.error(f"Could not reach the event store at {EVENTSTORE_URL}. Is the stack running?")
        st.stop()

    if not events:
        st.info(
            "No events yet. Run `python attacks/run_all.py` or drive an agent session "
            "(`docker compose logs agent`) to populate the store, then reload."
        )
        st.stop()

    decisions = Counter(e["decision"] for e in events)

    # --- summary row ---
    cols = st.columns(5)
    cols[0].metric("Total events", len(events))
    cols[1].metric("Allowed", decisions.get("ALLOW", 0) + decisions.get("ALLOW_REDACTED", 0))
    cols[2].metric("Denied", decisions.get("DENY", 0))
    cols[3].metric("Quarantined", decisions.get("QUARANTINE", 0))
    cols[4].metric("Distinct agents", len({e["agent_id"] for e in events}))

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("Decisions")
        st.bar_chart(dict(decisions))

    with right:
        st.subheader("Risk-score distribution")
        st.bar_chart(risk_buckets(events))

    st.divider()

    left2, right2 = st.columns(2)

    with left2:
        st.subheader("Top denied destinations")
        top = top_denied_destinations(events)
        if top:
            st.bar_chart(dict(top))
        else:
            st.caption("No denials recorded yet.")

    with right2:
        st.subheader("Per-agent taint status")
        # WHY "latest event per agent" not "any tainted event": session_taint is scoped to a
        # session, not permanently to an agent (AGENTFW_CONTEXT.md invariant §3.5 — monotonic
        # *within a session*) — showing each agent's most recent known state is the honest
        # summary, not a claim that taint is a permanent property of the agent itself.
        latest_by_agent: dict[str, dict[str, Any]] = {}
        for e in events:
            latest_by_agent[e["agent_id"]] = e  # events oldest-first; last write wins
        rows = [
            {"agent_id": agent_id, "role": e["role"], "session_taint": e["session_taint"]}
            for agent_id, e in sorted(latest_by_agent.items())
        ]
        st.dataframe(rows, use_container_width=True, hide_index=True)

    st.divider()

    # --- live feed ---
    st.subheader("Live event feed (most recent first)")
    recent = list(reversed(events))[:50]
    st.dataframe(
        [
            {
                "timestamp": e["timestamp"],
                "agent_id": e["agent_id"],
                "role": e["role"],
                "tool": e["tool"],
                "decision": e["decision"],
                "reason": e["reason"],
                "risk_score": e["risk_score"],
                "trace_id": e["trace_id"],
            }
            for e in recent
        ],
        use_container_width=True,
        hide_index=True,
    )

    st.divider()

    # --- detail view ---
    st.subheader("Event detail")
    trace_ids = [e["trace_id"] for e in recent]
    selected = st.selectbox("trace_id (most recent 50 shown above)", trace_ids)
    detail = next(e for e in recent if e["trace_id"] == selected)

    d1, d2 = st.columns(2)
    with d1:
        st.json(
            {
                k: detail[k]
                for k in (
                    "trace_id",
                    "session_id",
                    "agent_id",
                    "role",
                    "tool",
                    "action",
                    "destination",
                    "resource",
                    "data_classification",
                    "session_taint",
                )
            }
        )
    with d2:
        st.json(
            {
                k: detail[k]
                for k in ("decision", "reason", "policy_id", "policy_bundle_version", "latency_ms")
            }
        )

    st.markdown("**Full risk factor vector:**")
    if detail["risk_factors"]:
        st.dataframe(detail["risk_factors"], use_container_width=True, hide_index=True)
    else:
        st.caption(f"risk_score={detail['risk_score']} — no contributing factors (clean call).")


if __name__ == "__main__":
    main()
