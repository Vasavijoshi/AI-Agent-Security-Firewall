"""Request canonicalization: punycode/homoglyph domains, URL-encoded traversal, userinfo tricks,
case folding.

# WHY this is a security step, not plumbing (AGENTFW_CONTEXT.md §2 stage 2): every confused-deputy
# trick this module closes — `http://evil.com@trusted.com/`, `%2e%2e` traversal, a Cyrillic
# homoglyph domain, an explicit :443 that would otherwise fail an exact-match allowlist pattern —
# works by exploiting the gap between what a request *looks like* and what it *is*. Evaluate and
# forward the canonical form, never the original (pep/pipeline.py stage 2): a rule that matched
# the canonical form must also be what actually goes out over the wire, or the two could disagree.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}
# WHY capped, not "decode until stable with no limit": a pathological input crafted to never
# stabilize (or to stabilize only after an absurd number of rounds) must not hang this stage.
# Five rounds comfortably covers double- and triple-encoding, which is the realistic attack shape.
_MAX_DECODE_ROUNDS = 5


@dataclass(frozen=True)
class NormalizedURL:
    url: str
    fqdn: str | None
    port: int | None
    path: str
    scheme: str | None


def normalize_url(raw_url: str) -> NormalizedURL:
    """Canonicalize a URL: lowercase + punycode the host, strip userinfo, fold the default port
    away, decode percent-encoding (repeatedly) and collapse path traversal, and resolve duplicate
    query parameters to one deterministic value each."""
    parts = urlsplit(raw_url)
    scheme = (parts.scheme or "").lower() or None

    fqdn = _normalize_host(parts.hostname) if parts.hostname else None
    port = parts.port
    if port is not None and _DEFAULT_PORTS.get(scheme or "") == port:
        port = None  # WHY: :443 on https and :80 on http are equivalent to no port at all.

    path = normalize_path(parts.path)
    query = _normalize_query(parts.query)

    # WHY netloc is rebuilt from fqdn + port only, never from parts.netloc: that's precisely what
    # drops any userinfo (`user:pass@`) that was present on the original — it never makes it into
    # the canonical form, so it can't leak into a forwarded request or a logged event either.
    netloc = fqdn or ""
    if port is not None:
        netloc = f"{netloc}:{port}"

    url = urlunsplit((scheme or "", netloc, path, query, ""))
    return NormalizedURL(url=url, fqdn=fqdn, port=port, path=path, scheme=scheme)


def normalize_path(raw_path: str) -> str:
    """Decode percent-encoding and collapse `.`/`..` segments. Always root-anchored during
    collapse — even a path with no leading slash is treated as if it were, so `data/../../etc`
    can't walk upward past wherever the caller intended it to be confined, the same way an
    absolute path already can't (AGENTFW_CONTEXT.md §2: this is exactly the traversal case)."""
    if not raw_path:
        return raw_path
    decoded = _decode_repeatedly(raw_path)
    return posixpath.normpath("/" + decoded.lstrip("/"))


def _decode_repeatedly(value: str) -> str:
    for _ in range(_MAX_DECODE_ROUNDS):
        decoded = unquote(value)
        if decoded == value:
            return decoded
        value = decoded
    return value


def _normalize_host(hostname: str) -> str:
    hostname = hostname.lower()
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError:
        # WHY fall back instead of raising: a host idna rejects (e.g. an empty label) is malformed,
        # not necessarily malicious — it should fail policy matching downstream like any other
        # unrecognized destination, not take down the normalization stage that runs before policy
        # even sees it.
        return hostname


def _normalize_query(raw_query: str) -> str:
    if not raw_query:
        return ""
    pairs = parse_qsl(raw_query, keep_blank_values=True)
    # WHY last-occurrence-wins, sorted by key: real frameworks disagree on which duplicate query
    # parameter wins (Flask's `.get()` takes the first, Django's the last) — that disagreement
    # between systems is exactly what parameter-pollution attacks exploit. One fixed, documented
    # answer here means the value evaluation sees is guaranteed to be the value that gets
    # forwarded; sorting makes the result independent of the original key order.
    deduped: dict[str, str] = {}
    for key, value in pairs:
        deduped[key] = value
    return urlencode(sorted(deduped.items()))
