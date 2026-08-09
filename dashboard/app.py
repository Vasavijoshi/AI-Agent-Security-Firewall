"""Streamlit dashboard: reads the event store, shows decisions, risk factors, and denial reasons."""

import streamlit as st

# WHY this much and no more in M1: the dashboard is M3 scope (AGENTFW_CONTEXT.md §9). This is
# just enough real Streamlit code that `docker compose up -d` brings up a page that honestly says
# what's here, rather than either an unexplained blank page or fabricated M3 functionality.
st.title("AgentFW")
st.caption("Dashboard arrives in M3 — event browsing, risk factors, denial reasons.")
