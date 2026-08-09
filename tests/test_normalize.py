"""Tests for pep/normalize.py, written before the implementation (AGENTFW_CONTEXT.md §2 stage 2:
"a security step, not plumbing"). Covers the seven concerns named in the pre-M3 ruling: IDN/
punycode, percent-decoding (incl. double-encoding), path traversal collapse, userinfo stripping,
host lowercasing, default-port folding, duplicate parameter handling.
"""

from __future__ import annotations

from pep.normalize import normalize_path, normalize_url

# =====================================================================================
# IDN / punycode
# =====================================================================================


def test_unicode_host_is_converted_to_ascii_punycode():
    result = normalize_url("https://münchen.de/x")
    assert result.fqdn is not None
    assert result.fqdn.isascii()
    assert result.fqdn.startswith("xn--")


def test_homoglyph_domain_normalizes_to_a_different_fqdn_than_the_real_one():
    """The security property isn't "detect homoglyphs" — it's that a Cyrillic 'а' and a Latin 'a'
    are genuinely different domains, and normalization must not collapse them into looking like
    the same allowlisted string. Punycode gives each a stable, distinct ASCII form; the allowlist
    match then fails for the impostor the same way it fails for any other unlisted domain."""
    homoglyph = normalize_url("https://аpple.com/x")  # Cyrillic а, not Latin a
    real = normalize_url("https://apple.com/x")
    assert homoglyph.fqdn != real.fqdn


def test_already_ascii_host_passes_through_unchanged_besides_case():
    result = normalize_url("https://api.trusted-news.com/x")
    assert result.fqdn == "api.trusted-news.com"


def test_malformed_host_does_not_crash_normalization():
    """A host idna encoding rejects (e.g. an empty label) must degrade to the lowercased raw host,
    not raise — a malformed destination should fail policy matching normally, not take down the
    pipeline stage that runs before policy even gets a look at it."""
    result = normalize_url("https://a..b.com/x")
    assert result.fqdn == "a..b.com"


# =====================================================================================
# Percent-decoding, including double-encoding
# =====================================================================================


def test_percent_encoded_path_is_decoded():
    result = normalize_url("https://trusted.com/%2e%2e/secret")
    assert result.path == "/secret"  # decoded to "/../secret", then traversal-collapsed


def test_double_percent_encoded_path_is_fully_decoded():
    # %252e -> %2e -> "."  (decoded twice)
    result = normalize_url("https://trusted.com/%252e%252e/secret")
    assert result.path == "/secret"


def test_percent_decoding_does_not_loop_forever_on_pathological_input():
    # A string that keeps "looking encoded" no matter how many times you decode it must not hang
    # normalize_url or loop indefinitely — the decoder caps its iteration count.
    result = normalize_url("https://trusted.com/%2525252525252525/x")
    assert result.path is not None  # returned something; didn't hang or raise


# =====================================================================================
# Path traversal collapse
# =====================================================================================


def test_path_traversal_is_collapsed():
    result = normalize_url("https://trusted.com/a/b/../../etc/passwd")
    assert result.path == "/etc/passwd"


def test_path_traversal_cannot_escape_above_root():
    result = normalize_url("https://trusted.com/../../../etc/passwd")
    assert result.path == "/etc/passwd"


def test_normalize_path_collapses_traversal_for_file_read():
    assert normalize_path("/data/../../etc/passwd") == "/etc/passwd"


# =====================================================================================
# Userinfo stripping — the classic http://evil.com@trusted.com/ trick
# =====================================================================================


def test_userinfo_is_stripped_and_the_real_host_wins():
    result = normalize_url("http://evil.com@trusted.com/")
    assert result.fqdn == "trusted.com"
    assert "evil.com" not in result.url


def test_userinfo_with_password_is_also_stripped():
    result = normalize_url("http://user:pass@trusted.com/x")
    assert result.fqdn == "trusted.com"
    assert "user" not in result.url
    assert "pass" not in result.url


# =====================================================================================
# Host lowercasing
# =====================================================================================


def test_host_is_lowercased():
    result = normalize_url("https://API.Trusted-News.COM/X")
    assert result.fqdn == "api.trusted-news.com"


def test_path_case_is_preserved():
    """Only the host is case-folded — paths can be case-sensitive on the server, so lowercasing
    them would change what's actually being requested, not just how it's spelled."""
    result = normalize_url("https://trusted.com/CaseSensitivePath")
    assert result.path == "/CaseSensitivePath"


# =====================================================================================
# Default-port folding
# =====================================================================================


def test_default_https_port_is_folded_away():
    result = normalize_url("https://api.trusted-news.com:443/x")
    assert result.port is None
    assert ":443" not in result.url


def test_default_http_port_is_folded_away():
    result = normalize_url("http://api.trusted-news.com:80/x")
    assert result.port is None
    assert ":80" not in result.url


def test_non_default_port_is_preserved():
    result = normalize_url("https://api.trusted-news.com:8443/x")
    assert result.port == 8443
    assert ":8443" in result.url


# =====================================================================================
# Duplicate parameter handling
# =====================================================================================


def test_duplicate_query_params_resolve_deterministically():
    """WHY "last wins", sorted by key: real frameworks disagree on this (Flask's `.get()` returns
    the first value, Django's the last) — that disagreement between systems is exactly what
    parameter-pollution attacks exploit. This project just needs ONE fixed, documented answer so
    evaluation and forwarding never disagree with each other."""
    result = normalize_url("https://trusted.com/x?id=1&id=2&a=3")
    assert result.url.endswith("?a=3&id=2")


def test_single_valued_params_are_unaffected():
    result = normalize_url("https://trusted.com/x?a=1&b=2")
    assert "a=1" in result.url
    assert "b=2" in result.url


# =====================================================================================
# Idempotence — normalize(normalize(x)) == normalize(x)
# =====================================================================================


def test_normalize_url_is_idempotent_on_its_own_output():
    once = normalize_url("https://API.Trusted-News.COM:443/a/b/../c?id=1&id=2")
    twice = normalize_url(once.url)
    assert twice.url == once.url
    assert twice.fqdn == once.fqdn
    assert twice.port == once.port
    assert twice.path == once.path


def test_normalize_path_is_idempotent_on_its_own_output():
    once = normalize_path("/a/b/../../c/./d")
    assert normalize_path(once) == once
