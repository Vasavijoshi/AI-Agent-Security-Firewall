"""Local O(1) set lookup against known-bad destinations — no network call, cheap enough to run
before inspection (AGENTFW_CONTEXT.md §2 stage 4)."""

from __future__ import annotations

from pathlib import Path

_LISTS_DIR = Path(__file__).parent / "lists"


def _load_set(filename: str) -> frozenset[str]:
    path = _LISTS_DIR / filename
    if not path.exists():
        return frozenset()
    return frozenset(
        line.strip().lower()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


_MALICIOUS_FQDNS = _load_set("malicious_fqdns.txt")


def is_known_bad(fqdn: str | None) -> bool:
    """Exact match or parent-domain match — a listed parent domain covers all its subdomains, so
    `evil.example.com` on the list also flags `a.b.evil.example.com`."""
    if not fqdn:
        return False
    fqdn = fqdn.lower()
    if fqdn in _MALICIOUS_FQDNS:
        return True
    labels = fqdn.split(".")
    return any(".".join(labels[i:]) in _MALICIOUS_FQDNS for i in range(1, len(labels)))
