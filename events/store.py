"""Durable append-and-flush event writer: log-or-deny — a write failure here denies the action,
never allows it."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

# WHY: hand-checked against events/schema.json's "required" list rather than pulling in a JSON
# Schema validator — a 13th dependency to check ~18 key names isn't worth it (AGENTFW_CONTEXT.md
# §1 dependency budget). This is a presence check, not full schema validation (types, enums,
# nested required fields aren't checked here); events/schema.json remains the source of truth
# for what "conforming" fully means.
REQUIRED_FIELDS = (
    "schema_version",
    "timestamp",
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
    "risk_score",
    "risk_factors",
    "policy_id",
    "policy_bundle_version",
    "decision",
    "reason",
    "latency_ms",
)


_CREATE_TABLE_SQL = (
    "CREATE TABLE IF NOT EXISTS events ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "trace_id TEXT NOT NULL, "
    "session_id TEXT NOT NULL, "
    "decision TEXT NOT NULL, "
    "timestamp TEXT NOT NULL, "
    "payload TEXT NOT NULL)"
)


class EventWriteError(Exception):
    """Raised when a security event cannot be validated or durably written.

    Callers must treat this as a signal to deny the action (invariant §3.4, log-or-deny) — never
    catch this and proceed as if the event had been recorded.
    """


def write_event(event: dict[str, Any], db_path: str) -> None:
    """Validate and durably append one security event. Raises EventWriteError on any failure."""
    missing = [f for f in REQUIRED_FIELDS if f not in event]
    if missing:
        raise EventWriteError(f"event missing required fields: {missing}")

    try:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(db_path) as conn:
            conn.execute(_CREATE_TABLE_SQL)
            conn.execute(
                "INSERT INTO events (trace_id, session_id, decision, timestamp, payload) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    event["trace_id"],
                    event["session_id"],
                    event["decision"],
                    event["timestamp"],
                    json.dumps(event),
                ),
            )
            conn.commit()
            # WHY no explicit os.fsync: sqlite3's default synchronous=FULL pragma already fsyncs
            # the journal and the database file on commit. Durability comes from that default, not
            # from anything added here — changing synchronous mode would silently break it.
    except (sqlite3.Error, OSError) as exc:
        raise EventWriteError(str(exc)) from exc


def read_all_events(db_path: str) -> list[dict[str, Any]]:
    """Read every logged event, oldest first. Used by the dashboard and by tests to verify logging.

    Returns an empty list, never an error, against a database that has no `events` table yet — a
    dashboard opened before the first event was ever written, or a write that failed validation
    before the table was created, are both "nothing logged," not a fault to surface.
    """
    with sqlite3.connect(db_path) as conn:
        conn.execute(_CREATE_TABLE_SQL)
        rows = conn.execute("SELECT payload FROM events ORDER BY id").fetchall()
    return [json.loads(row[0]) for row in rows]


# --- quarantine persistence (pre-M3 ruling) ---
# WHY a dedicated table, not "replay the event log to compute current state": quarantine state is
# current-membership, not history — a small table that IS the current state is simpler and cheaper
# to query on every pipeline run than reconstructing "who's currently quarantined" from a stream of
# enter/release events every time. The event log still separately records *why* (the triggering
# tool-call's own event carries the risk factors / threat-intel hit that caused it).
_QUARANTINE_TABLE_SQL = (
    "CREATE TABLE IF NOT EXISTS quarantine ("
    "agent_id TEXT PRIMARY KEY, "
    "reason TEXT NOT NULL, "
    "entered_at TEXT NOT NULL)"
)


def quarantine_enter(agent_id: str, reason: str, entered_at: str, db_path: str) -> None:
    """Idempotent: an already-quarantined agent keeps its original reason and entered_at — see
    pep/quarantine.py's WHY (there's nothing time-based to restart, since exit is manual)."""
    with sqlite3.connect(db_path) as conn:
        conn.execute(_QUARANTINE_TABLE_SQL)
        conn.execute(
            "INSERT OR IGNORE INTO quarantine (agent_id, reason, entered_at) VALUES (?, ?, ?)",
            (agent_id, reason, entered_at),
        )
        conn.commit()


def quarantine_release(agent_id: str, db_path: str) -> bool:
    """Returns True if the agent was actually quarantined, so the caller can tell a real release
    apart from a no-op on an unrecognized agent_id."""
    with sqlite3.connect(db_path) as conn:
        conn.execute(_QUARANTINE_TABLE_SQL)
        cursor = conn.execute("DELETE FROM quarantine WHERE agent_id = ?", (agent_id,))
        conn.commit()
        return cursor.rowcount > 0


def quarantine_list(db_path: str) -> dict[str, str]:
    """agent_id -> reason, for every currently-quarantined agent."""
    with sqlite3.connect(db_path) as conn:
        conn.execute(_QUARANTINE_TABLE_SQL)
        rows = conn.execute("SELECT agent_id, reason FROM quarantine").fetchall()
    return dict(rows)


def quarantine_is_active(agent_id: str, db_path: str) -> bool:
    with sqlite3.connect(db_path) as conn:
        conn.execute(_QUARANTINE_TABLE_SQL)
        row = conn.execute("SELECT 1 FROM quarantine WHERE agent_id = ?", (agent_id,)).fetchone()
    return row is not None
