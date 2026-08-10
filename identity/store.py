"""Identity's own durable digest-pin store: a local SQLite file, not the shared eventstore.

# WHY local, not eventstore (pre-M3 ruling, round 5, correcting round 4): a digest pin is
# identity's own state about what it has decided to trust — it was never a security *event* (that's
# still stdout, see issuer.py's WHY), and routing it through eventstore was the thing that forced
# identity onto egress-net in the first place. A component that mints workload identity is a
# high-value target; giving it a route to the internet turns a compromise into an exfiltration
# path, regardless of whether identity's own code ever intends to use that route. Local storage
# removes the need for the route at all — identity stays agent-net-only, matching every other
# "pep is the only dual-homed container" claim in this repo.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

_CREATE_TABLE_SQL = (
    "CREATE TABLE IF NOT EXISTS digest_pins ("
    "service TEXT PRIMARY KEY, "
    "digest TEXT NOT NULL, "
    "pinned_at TEXT NOT NULL)"
)


def get_or_set(service: str, observed_digest: str, pinned_at: str, db_path: str) -> str:
    """Return the pinned digest for `service`, pinning `observed_digest` as the trusted value if
    no pin exists yet — trust-on-first-use. Race-safe by construction, not by locking: INSERT OR
    IGNORE plus a read-back means two near-simultaneous "first" attestations for the same service
    can't each believe their own digest won (see events/store.py's original digest_pin_get_or_set,
    which this replaces one-for-one, for the same argument in more detail)."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(_CREATE_TABLE_SQL)
        conn.execute(
            "INSERT OR IGNORE INTO digest_pins (service, digest, pinned_at) VALUES (?, ?, ?)",
            (service, observed_digest, pinned_at),
        )
        conn.commit()
        row = conn.execute(
            "SELECT digest FROM digest_pins WHERE service = ?", (service,)
        ).fetchone()
    return row[0]


def clear(service: str, db_path: str) -> bool:
    """The only way to change a pin: delete it, so the next attestation re-establishes trust from
    scratch (for a legitimate rebuild). Returns True if a pin actually existed. Called only from
    identity/admin_cli.py — see its module docstring for why this has no HTTP route."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(_CREATE_TABLE_SQL)
        cursor = conn.execute("DELETE FROM digest_pins WHERE service = ?", (service,))
        conn.commit()
        return cursor.rowcount > 0


def list_all(db_path: str) -> dict[str, str]:
    """service -> pinned digest, for every service that has ever attested successfully."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(_CREATE_TABLE_SQL)
        rows = conn.execute("SELECT service, digest FROM digest_pins").fetchall()
    return dict(rows)
