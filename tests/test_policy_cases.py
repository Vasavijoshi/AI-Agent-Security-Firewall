"""Runs the declarative given/expect fixtures in tests/policy/*.yaml against the real engine and
the real default bundle — the policy regression suite AGENTFW_CONTEXT.md §9 requires for M2."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from policy.engine import evaluate, load_bundle

BUNDLE = load_bundle("policy/bundles/default.yaml")
CASES_DIR = Path(__file__).parent / "policy"


def _load_cases() -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    cases = []
    for path in sorted(CASES_DIR.glob("*.yaml")):
        for case in yaml.safe_load(path.read_text(encoding="utf-8")):
            cases.append((f"{path.stem}::{case['name']}", case["given"], case["expect"]))
    return cases


CASES = _load_cases()


def test_at_least_20_cases_loaded():
    # WHY this exists as its own assertion, not just a side effect of parametrize collecting
    # something: a YAML typo that empties a file silently drops cases from the parametrized test
    # rather than failing it — this makes "the suite got smaller" a loud failure on its own.
    assert len(CASES) >= 20


@pytest.mark.parametrize("case_id,given,expect", CASES, ids=[c[0] for c in CASES])
def test_policy_case(case_id: str, given: dict[str, Any], expect: dict[str, Any]) -> None:
    result = evaluate(
        BUNDLE,
        role=given["role"],
        tool=given["tool"],
        fqdn=given.get("fqdn"),
        resource=given.get("resource"),
        session_taint=given.get("taint", "clean"),
    )
    assert result.decision.name == expect["decision"], case_id
    if "policy_id" in expect:
        assert result.policy_id == expect["policy_id"], case_id
    if "reason" in expect:
        assert result.reason == expect["reason"], case_id
