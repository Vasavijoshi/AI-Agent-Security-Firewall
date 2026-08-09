"""Regex secret detectors (AWS keys, JWTs, PEM, PAN/Luhn, connection strings) plus Shannon
entropy on long tokens.

WHY the matched value is never part of what this module returns: a DLP log that records the
secret it found is a secret store with worse access control (AgentFW_Architecture_v1.md §13).
scan() returns detector names and severities only — callers that need to log a finding log the
code, never `match.group(0)`.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

_ENTROPY_THRESHOLD = 4.0  # bits/char — common heuristic for high-entropy secret-shaped tokens
_MIN_TOKEN_LEN = 20


@dataclass(frozen=True)
class Finding:
    detector: str
    severity: str  # "BLOCK" (structured, high-confidence secret) or "REDACT" (PII / low-confidence)


def _luhn_valid(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# WHY no generic "AWS secret access key" pattern: a bare 40-char base64 blob is indistinguishable
# from random unrelated data without context — a dedicated regex for it would be low-precision by
# construction. The entropy detector below catches it the same way it catches any other
# unstructured high-entropy secret; the AWS *access key ID* below is high-precision because of its
# distinctive AKIA prefix.
_REGEX_DETECTORS: tuple[tuple[str, re.Pattern[str], str, object], ...] = (
    ("AWS_ACCESS_KEY_ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "BLOCK", None),
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        "BLOCK",
        None,
    ),
    (
        "PEM_PRIVATE_KEY",
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"),
        "BLOCK",
        None,
    ),
    (
        "CONNECTION_STRING",
        re.compile(
            r"\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:@]+:[^\s:@]+@[^\s/]+"
        ),
        "BLOCK",
        None,
    ),
    (
        "CARD_NUMBER",
        re.compile(r"\b(?:\d[ -]?){13,19}\b"),
        "BLOCK",
        _luhn_valid,
    ),
    (
        "AADHAAR",
        # WHY (?<!\d)...(?!\s?\d), not \b on both ends: \b sits between a digit and a following
        # space, so a plain \b pattern also matches the first 12 digits of a longer card number
        # split into space-separated groups of 4. This requires the match to be exactly 12 digits,
        # not a prefix of a longer digit run.
        re.compile(r"(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\s?\d)"),
        "REDACT",  # PII, not a credential — lower severity than the structured-secret detectors
        None,
    ),
)


def _shannon_entropy(token: str) -> float:
    if not token:
        return 0.0
    counts = Counter(token)
    length = len(token)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def scan(text: str) -> list[Finding]:
    """Scan `text` (tool arguments, a response body — anything about to cross the boundary) for
    secret-shaped content. Cheapest, highest-precision detectors run first; this stays a pure
    function with no logging of its own, so it's safe to call speculatively."""
    findings: list[Finding] = []
    for name, pattern, severity, validator in _REGEX_DETECTORS:
        for match in pattern.finditer(text):
            if validator is None or validator(match.group(0)):
                findings.append(Finding(name, severity))

    for token in text.split():
        if len(token) >= _MIN_TOKEN_LEN and _shannon_entropy(token) >= _ENTROPY_THRESHOLD:
            findings.append(Finding("HIGH_ENTROPY_TOKEN", "REDACT"))

    return findings


# WHY a card number can still also trigger AADHAAR: a 16-digit card in four space-separated groups
# of four contains a 12-digit, four-groups-of-... no, three-groups-of-four substring that is
# shape-identical to an Aadhaar number. Fully disambiguating card-shaped from Aadhaar-shaped digit
# runs would need more context than a regex has. Harmless in practice: outcome() takes the worst
# severity across all findings, so an overlap never under-reports.
def outcome(findings: list[Finding]) -> str:
    """PASS | REDACT | BLOCK — the worst severity among all findings, or PASS if none."""
    if any(f.severity == "BLOCK" for f in findings):
        return "BLOCK"
    if findings:
        return "REDACT"
    return "PASS"
