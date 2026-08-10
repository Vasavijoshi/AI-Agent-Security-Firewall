"""Tests for policy/compiler.py's east-west validation (pre-M3 ruling, round 4): an unknown
source or destination workload in east_west_rules must fail the build, the same way an unknown
role in the main rule table already does.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from policy.compiler import KNOWN_WORKLOADS, BundleInvalidError, compile_bundle
from policy.engine import Decision, EastWestRule, load_bundle

BASE_BUNDLE = load_bundle("policy/bundles/default.yaml")


def test_default_bundle_still_compiles_with_the_new_check():
    """The real bundle's east_west_rules is empty — nothing for the new check to reject."""
    compile_bundle("policy/bundles/default.yaml")


def test_unknown_source_workload_fails_the_build(tmp_path):
    bundle = replace(
        BASE_BUNDLE,
        east_west_rules=(
            EastWestRule("EW-BAD", 100, "not-a-real-service", "agent", "invoke", Decision.ALLOW),
        ),
    )
    _assert_fails_with(bundle, tmp_path, "UNKNOWN_WORKLOAD", "not-a-real-service")


def test_unknown_dest_workload_fails_the_build(tmp_path):
    bundle = replace(
        BASE_BUNDLE,
        east_west_rules=(
            EastWestRule("EW-BAD", 100, "agent", "not-a-real-service", "invoke", Decision.ALLOW),
        ),
    )
    _assert_fails_with(bundle, tmp_path, "UNKNOWN_WORKLOAD", "not-a-real-service")


def test_wildcard_source_and_dest_are_never_flagged(tmp_path):
    bundle = replace(
        BASE_BUNDLE,
        east_west_rules=(EastWestRule("EW-1", 100, "*", "*", "invoke", Decision.DENY),),
    )
    _write_and_compile(bundle, tmp_path)  # must not raise


def test_known_workloads_matches_the_registered_multi_agent_services():
    assert KNOWN_WORKLOADS == {"agent", "finance-agent", "support-agent"}


def _write_and_compile(bundle, tmp_path):
    """compile_bundle() takes a path, so round-trip the modified Bundle back to YAML rather than
    poking at internals compile_bundle() doesn't expose a way to inject."""
    import yaml

    path = tmp_path / "bundle.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "metadata": {
                    "version": bundle.version,
                    "not_valid_after": bundle.not_valid_after,
                    "fail_safe_after": bundle.fail_safe_after,
                },
                "rules": [_rule_to_dict(r) for r in bundle.rules],
                "east_west_rules": [_ew_rule_to_dict(r) for r in bundle.east_west_rules],
            }
        ),
        encoding="utf-8",
    )
    return compile_bundle(str(path))


def _assert_fails_with(bundle, tmp_path, code: str, snippet: str):
    with pytest.raises(BundleInvalidError) as exc_info:
        _write_and_compile(bundle, tmp_path)
    message = str(exc_info.value)
    assert code in message
    assert snippet in message


def _rule_to_dict(r) -> dict:
    d = {
        "id": r.id,
        "priority": r.priority,
        "role": r.role,
        "tool": list(r.tool),
        "effect": r.effect.name,
    }
    if r.critical_path:
        d["critical_path"] = True
    if r.destination is not None:
        d["destination"] = list(r.destination)
    if r.resource is not None:
        d["resource"] = list(r.resource)
    conditions = {}
    if r.max_data_class is not None:
        conditions["max_data_class"] = r.max_data_class
    if r.session_taint is not None:
        conditions["session_taint"] = list(r.session_taint)
    if conditions:
        d["conditions"] = conditions
    if r.inspect:
        d["inspect"] = True
    if r.reason:
        d["reason"] = r.reason
    return d


def _ew_rule_to_dict(r) -> dict:
    return {
        "id": r.id,
        "priority": r.priority,
        "source_workload": r.source_workload,
        "dest_workload": r.dest_workload,
        "action": r.action,
        "effect": r.effect.name,
    }
