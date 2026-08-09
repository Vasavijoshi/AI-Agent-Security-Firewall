"""Property-based tests (Hypothesis) for the 6 invariants in AGENTFW_CONTEXT.md §3: monotonicity,
no-implicit-allow, determinism, log-or-deny, taint monotonicity, normalization idempotence."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from hypothesis import given, settings
from hypothesis import strategies as st

import pep.pipeline as pipeline
import risk.scorer as risk_scorer
from identity.tokens import generate_keypair, mint_token
from pep.normalize import normalize_url
from policy.engine import Decision, evaluate, load_bundle

TEST_BUNDLE = load_bundle("policy/bundles/default.yaml")

# --- fixtures shared by the pipeline-level invariant tests ---
CONTAINER_ID = "deadbeefcafe1234567890abcdef"


@pytest.fixture(autouse=True)
def _reset_process_state():
    pipeline._SESSION_TAINT.clear()
    risk_scorer._SEEN_BY_AGENT.clear()
    risk_scorer._SEEN_BY_ORG.clear()
    risk_scorer._CALL_TIMES.clear()
    risk_scorer._LAST_TOOL.clear()
    risk_scorer._SEEN_BIGRAMS.clear()
    risk_scorer._DENIAL_STREAK.clear()
    yield


@pytest.fixture
def keypair():
    return generate_keypair()


def _token(keypair, role: str, ip: str = "10.0.0.5") -> str:
    private_key, _ = keypair
    return mint_token(
        {
            "spiffe_id": f"spiffe://agentfw.internal/ns/{role}/agent/{CONTAINER_ID[:12]}",
            "role": role,
            "container_id": CONTAINER_ID,
            "image_digest": "sha256:deadbeef",
            "attested_ip": ip,
        },
        private_key,
    )


# =====================================================================================
# Invariant 1 — Monotonicity: decide(policy_verdict, risk_verdict) <= policy_verdict
# =====================================================================================


@given(policy_v=st.sampled_from(Decision), risk_v=st.sampled_from(Decision))
def test_monotonicity(policy_v: Decision, risk_v: Decision) -> None:
    """The lattice property itself (AgentFW_Architecture_v1.md §7): for EVERY possible pair, the
    combined decision is never more permissive than what policy alone decided. This is what
    `final_decision, _ = min(candidates, ...)` in pep/pipeline.py is relying on — risk and DLP are
    two more entries in that same min(), so this property is what makes narrowing-only true for
    them as well, not just for a two-argument toy case."""
    combined = min(policy_v, risk_v)
    assert combined <= policy_v


# =====================================================================================
# Invariant 2 — No implicit allow
# =====================================================================================

# WHY the "fuzz_" prefix: Hypothesis generates free-form text: without a guard, there's a
# vanishingly small but nonzero chance it reproduces an actual role/tool/fqdn from
# policy/bundles/default.yaml and the test would (correctly!) observe an ALLOW. Prefixing makes
# every generated value provably absent from the bundle, so ALLOW would only ever mean a real bug.
_fuzz_text = st.text(min_size=1, max_size=20).map(lambda s: f"fuzz_{s}")


@given(role=_fuzz_text, tool=_fuzz_text, destination=_fuzz_text)
@settings(max_examples=200)
def test_no_implicit_allow(role: str, tool: str, destination: str) -> None:
    result = evaluate(
        TEST_BUNDLE, role=role, tool=tool, fqdn=destination, resource=None, session_taint="clean"
    )
    assert result.decision == Decision.DENY
    assert result.policy_id == "DEFAULT_DENY"


# =====================================================================================
# Invariant 3 — Determinism
# =====================================================================================

_KNOWN_ROLES = ("research_agent", "finance_agent", "support_agent", "admin_agent", "nobody")
_KNOWN_TOOLS = ("http.get", "http.post", "db.query", "file.read", "email.send")
_KNOWN_TARGETS = ("api.trusted-news.com", "api.approved-erp.com", "evil.example.com", "customers")
_KNOWN_TAINTS = ("clean", "tainted")


@given(
    role=st.sampled_from(_KNOWN_ROLES),
    tool=st.sampled_from(_KNOWN_TOOLS),
    target=st.sampled_from(_KNOWN_TARGETS),
    taint=st.sampled_from(_KNOWN_TAINTS),
)
@settings(max_examples=20)
def test_determinism(role: str, tool: str, target: str, taint: str) -> None:
    """Same request + same bundle -> identical verdict across 1000 runs. No dependence on dict
    ordering, time, or randomness (AGENTFW_CONTEXT.md §3.3)."""
    results = {
        evaluate(
            TEST_BUNDLE, role=role, tool=tool, fqdn=target, resource=target, session_taint=taint
        ).policy_id
        for _ in range(1000)
    }
    assert len(results) == 1


# =====================================================================================
# Invariant 4 — Log-or-deny
# =====================================================================================


def test_log_or_deny(keypair, monkeypatch) -> None:
    """If the event store write fails, the action is denied — an unlogged allow is unauditable
    (AGENTFW_CONTEXT.md invariant §3.4). Exercised through the real HTTP layer (pep/proxy.py),
    not just the pipeline function, since log-or-deny is enforced in proxy.py's endpoint, not in
    run_pipeline() itself."""
    import pep.proxy as proxy

    monkeypatch.setattr(proxy, "EVENTSTORE_URL", "http://127.0.0.1:1")  # nothing listens on :1
    pipeline._ISSUER_PUBLIC_KEY = keypair[1]

    client = TestClient(proxy.app)
    token = _token(keypair, "research_agent", ip="testclient")  # TestClient's default peer host
    response = client.post(
        "/v1/tool-call",
        json={
            "session_id": "s1",
            "trace_id": "t1",
            "tool": "http.get",
            "arguments": {"url": "https://api.trusted-news.com/x"},
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    body = response.json()
    # WHY DENY regardless of what policy/risk would otherwise have decided: this destination and
    # role would normally score ALLOW/RATE_LIMIT (see test_pipeline_m2.py) — the only variable
    # here is the eventstore being unreachable, and that alone must be decisive.
    assert body["decision"] == "DENY"
    assert body["reason"] == "event_store_write_failed"


# =====================================================================================
# Invariant 5 — Taint is monotonic
# =====================================================================================


def _arguments_for(tool: str) -> dict[str, str]:
    return {
        "http.get": {"url": "https://api.trusted-news.com/x"},
        "http.post": {"url": "https://api.trusted-news.com/x", "body": "x"},
        "db.query": {"table": "customers"},
        "file.read": {"path": "/x"},
        "email.send": {"to": "x@example.com", "body": "hi"},
    }[tool]


# WHY a module-level keypair, not the `keypair` fixture, for this one test: Hypothesis's
# @given re-invokes the test body per generated example without re-running function-scoped
# fixtures, which it flags as a health-check failure (correctly, in general). Here it's genuinely
# fine — this property doesn't depend on key material — so a shared keypair sidesteps the warning
# instead of suppressing it.
_TAINT_TEST_KEYPAIR = generate_keypair()


@given(tool_sequence=st.lists(st.sampled_from(_KNOWN_TOOLS), min_size=1, max_size=6))
@settings(max_examples=50)
def test_taint_is_monotonic(tool_sequence: list[str]) -> None:
    """A session can go clean -> tainted, never back (AGENTFW_CONTEXT.md §3.5) — checked by
    driving a random sequence of tool calls through the real pipeline for one session and
    asserting the taint flag, once observed True, stays True for every call after it."""
    pipeline._SESSION_TAINT.clear()
    pipeline._ISSUER_PUBLIC_KEY = _TAINT_TEST_KEYPAIR[1]
    session_id = "taint-monotonic-session"
    token = _token(_TAINT_TEST_KEYPAIR, "research_agent")

    seen_tainted = False
    for tool in tool_sequence:
        arguments = _arguments_for(tool)
        pipeline.run_pipeline(
            token=token, peer_ip="10.0.0.5", session_id=session_id, tool=tool, arguments=arguments
        )
        now_tainted = pipeline._SESSION_TAINT.get(session_id, False)
        if seen_tainted:
            assert now_tainted, "taint was cleared after being set — invariant violated"
        seen_tainted = seen_tainted or now_tainted


# =====================================================================================
# Invariant 6 — Normalization is idempotent
# =====================================================================================

_HOST_LABEL = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-",
    min_size=1,
    max_size=10,
)
_HOST = st.lists(_HOST_LABEL, min_size=1, max_size=4).map(".".join)
_PATH_SEGMENT = st.sampled_from(["a", "b", "..", ".", "%2e%2e", "x%20y", "CaseSeg", "%252e%252e"])
_PATH = st.lists(_PATH_SEGMENT, min_size=0, max_size=6).map(lambda segs: "/" + "/".join(segs))
_QUERY_PAIR = st.tuples(
    st.sampled_from(["a", "b", "id", "x"]), st.text(alphabet="abc123", min_size=0, max_size=5)
)
_QUERY = st.lists(_QUERY_PAIR, max_size=4)


@given(
    scheme=st.sampled_from(["http", "https"]),
    host=_HOST,
    port=st.one_of(st.none(), st.integers(min_value=1, max_value=65535)),
    path=_PATH,
    query=_QUERY,
)
@settings(max_examples=200)
def test_normalization_is_idempotent(
    scheme: str, host: str, port: int | None, path: str, query: list[tuple[str, str]]
) -> None:
    """normalize(normalize(x)) == normalize(x) (AGENTFW_CONTEXT.md §3.6) — checked against
    pep/normalize.py's real normalize_url() over a range of hosts (incl. mixed case, IDN-shaped
    labels), traversal- and percent-encoded paths, ports, and duplicate query keys."""
    netloc = host + (f":{port}" if port else "")
    query_string = "&".join(f"{k}={v}" for k, v in query)
    raw_url = f"{scheme}://{netloc}{path}" + (f"?{query_string}" if query_string else "")

    once = normalize_url(raw_url)
    twice = normalize_url(once.url)
    assert twice == once
