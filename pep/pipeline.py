"""The fixed 8-stage decision pipeline: identity, normalize, policy, threat intel, DLP, risk,
decide, log."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

import dlp.detectors as dlp
import risk.scorer as risk
import threat_intel.feed as threat_intel
from identity.tokens import TokenInvalidError, public_key_from_b64, verify_token
from policy.compiler import compile_bundle
from policy.engine import EXECUTABLE_DECISIONS, Decision, evaluate

IDENTITY_ISSUER_URL = os.environ.get("IDENTITY_ISSUER_URL", "http://identity:8082")
POLICY_BUNDLE_PATH = os.environ.get("POLICY_BUNDLE_PATH", "policy/bundles/default.yaml")

ACTION_MAP = {
    "http.get": "read",
    "http.post": "write",
    "db.query": "read",
    "file.read": "read",
    "email.send": "write",
}

PIPELINE_STAGES = (
    "identity",
    "normalize",
    "policy",
    "threat_intel",
    "dlp",
    "risk",
    "decision",
    "log",
)

# WHY loaded and compiled once at import time, not per-request: policy/compiler.py's job is to
# catch a broken bundle before it can ever be enforced — running it once at process start (and
# crashing loudly if it fails) is what "never load unverified policy" means in code
# (AGENTFW_Architecture_v1.md §16). A bad bundle should be a deploy-time failure, not a runtime one.
BUNDLE, BUNDLE_WARNINGS = compile_bundle(POLICY_BUNDLE_PATH)

# --- in-memory session state (per-process — see risk/scorer.py's module docstring for the same
# trade-off applied here) ---
_SESSION_TAINT: dict[str, bool] = {}
_ISSUER_PUBLIC_KEY = None  # lazily fetched; type is Ed25519PublicKey once set


@dataclass
class PipelineResult:
    decision: Decision
    reason: str
    policy_id: str
    role: str | None
    agent_key: str
    session_taint: str
    data_classification: str
    risk_score: int
    risk_factors: list[dict[str, Any]] = field(default_factory=list)
    latency_ms: dict[str, float] = field(default_factory=dict)


def run_pipeline(
    *,
    token: str | None,
    peer_ip: str | None,
    session_id: str,
    tool: str,
    arguments: dict[str, Any],
) -> PipelineResult:
    """Run the full 8-stage pipeline (stage 8's actual write happens in pep/proxy.py; this
    function returns everything the event needs). Never raises for a bad caller, bad tool, or bad
    request shape — those are DENY outcomes; exceptions stay reserved for genuine faults (e.g. the
    issuer being unreachable, which also resolves to DENY, just via a different reason string)."""
    latency: dict[str, float] = {}

    # --- Stage 1: identity verification ---
    t0 = time.perf_counter()
    role, agent_key, id_reason = _verify_identity(token, peer_ip)
    latency["identity"] = _elapsed_ms(t0)
    if role is None:
        return _deny_early(id_reason, "IDENTITY_DENY", agent_key, latency)

    # --- Stage 2: request normalization (no-op — pep/normalize.py is not M2 scope; see
    # AGENTFW_CONTEXT.md §4) ---
    t0 = time.perf_counter()
    fqdn, resource = extract_target(tool, arguments)
    latency["normalize"] = _elapsed_ms(t0)

    # --- Stage 3: policy evaluation ---
    t0 = time.perf_counter()
    session_taint = "tainted" if _SESSION_TAINT.get(session_id, False) else "clean"
    policy_result = evaluate(
        BUNDLE, role=role, tool=tool, fqdn=fqdn, resource=resource, session_taint=session_taint
    )
    latency["policy"] = _elapsed_ms(t0)

    # --- Stage 4: threat intel ---
    t0 = time.perf_counter()
    ti_hit = threat_intel.is_known_bad(fqdn)
    latency["threat_intel"] = _elapsed_ms(t0)

    # --- Stage 5: DLP / data classification ---
    t0 = time.perf_counter()
    data_class = policy_result.max_data_class or "public"
    dlp_decision, dlp_reason = Decision.ALLOW, "dlp_pass"
    if policy_result.decision == Decision.ALLOW and (policy_result.inspect or _is_external(fqdn)):
        # WHY "url" is excluded from the scan: it's the destination, already governed separately
        # by policy (stage 3) — and URLs are structurally diverse enough (scheme, dots, slashes,
        # a mix of cases) to trip a generic entropy threshold on their own, which would flag
        # nearly every http.get as a false positive. The actual exfiltration risk is in what's
        # being SENT (a POST/email body, a query filter), not the address it's sent to.
        blob = " ".join(str(v) for k, v in arguments.items() if k != "url")
        findings = dlp.scan(blob)
        verdict = dlp.outcome(findings)
        dlp_decision = {
            "PASS": Decision.ALLOW,
            "REDACT": Decision.ALLOW_REDACTED,
            "BLOCK": Decision.DENY,
        }[verdict]
        dlp_reason = {"PASS": "dlp_pass", "REDACT": "dlp_redact", "BLOCK": "dlp_block"}[verdict]
    latency["dlp"] = _elapsed_ms(t0)

    # --- Stage 6: risk + behavior scoring ---
    t0 = time.perf_counter()
    risk_result = risk.score(
        agent_id=agent_key,
        role=role,
        tool=tool,
        destination_key=fqdn or resource,
        action=ACTION_MAP.get(tool, "unknown"),
        data_class=data_class,
        session_taint=session_taint,
        threat_intel_hit=ti_hit,
    )
    latency["risk"] = _elapsed_ms(t0)

    # --- Stage 7: decision — final = min(policy, dlp, risk) on the lattice ---
    # WHY min() over a list of (decision, reason) tuples: this reports *which* stage produced the
    # narrowest verdict, not just the verdict itself — an operator reading `reason` in an event
    # should be able to tell taint_ceiling from dlp_block from a HIGH risk band without decoding
    # four separate fields.
    t0 = time.perf_counter()
    candidates = [
        (policy_result.decision, policy_result.reason),
        (dlp_decision, dlp_reason),
        (risk_result.decision_ceiling, f"risk_band_{risk_result.band.lower()}"),
    ]
    final_decision, final_reason = min(candidates, key=lambda c: c[0])
    latency["decision"] = _elapsed_ms(t0)

    if tool == "http.get" and final_decision in EXECUTABLE_DECISIONS:
        # WHY unconditional, not domain-specific: fetching ANY external content is how untrusted
        # instructions enter (AGENTFW_CONTEXT.md §10) — an allowlisted domain is still someone
        # else's content. Taint is monotonic (invariant §3.5): only ever set True, never cleared.
        _SESSION_TAINT[session_id] = True

    risk.record_outcome(
        agent_id=agent_key,
        role=role,
        tool=tool,
        destination_key=fqdn or resource,
        decision=final_decision,
    )

    return PipelineResult(
        decision=final_decision,
        reason=final_reason,
        policy_id=policy_result.policy_id,
        role=role,
        agent_key=agent_key,
        session_taint=session_taint,
        data_classification=data_class,
        risk_score=risk_result.score,
        risk_factors=[
            {"code": f.code, "points": f.points, "human_reason": f.human_reason}
            for f in risk_result.factors
        ],
        latency_ms=_finalize(latency),
    )


def _verify_identity(token: str | None, peer_ip: str | None) -> tuple[str | None, str, str]:
    """Returns (role, agent_key, reason). role is None on any failure; agent_key is always a
    string (the peer IP, if identity couldn't be established) so risk/event logging always has
    *something* to key on — an unauthenticated caller still gets tracked, just not authorized."""
    fallback_key = peer_ip or "unknown"
    if not token:
        return None, fallback_key, "identity_verification_failed: no token presented"
    try:
        public_key = _get_issuer_public_key()
        claims = verify_token(token, public_key)
    except TokenInvalidError as exc:
        return None, fallback_key, f"identity_verification_failed: {exc}"
    except httpx.HTTPError:
        return None, fallback_key, "identity_verification_failed: issuer unreachable"

    # --- container binding: the connection presenting this token must be the same one the
    # issuer attested (AGENTFW_CONTEXT.md §2) — a stolen token replayed from elsewhere fails here
    # even though its signature is perfectly valid.
    if peer_ip is None or claims.get("attested_ip") != peer_ip:
        return None, fallback_key, "identity_verification_failed: container binding mismatch"

    return claims["role"], claims.get("container_id", fallback_key)[:12], "ok"


def _get_issuer_public_key():
    global _ISSUER_PUBLIC_KEY
    if _ISSUER_PUBLIC_KEY is None:
        resp = httpx.get(f"{IDENTITY_ISSUER_URL}/public-key", timeout=5.0)
        resp.raise_for_status()
        _ISSUER_PUBLIC_KEY = public_key_from_b64(resp.json()["public_key"])
    return _ISSUER_PUBLIC_KEY


def extract_target(tool: str, arguments: dict[str, Any]) -> tuple[str | None, str | None]:
    if tool.startswith("http."):
        parsed = urlparse(arguments.get("url", ""))
        return parsed.hostname, (parsed.path or None)
    if tool == "db.query":
        return None, arguments.get("table")
    if tool == "file.read":
        return None, arguments.get("path")
    if tool == "email.send":
        return None, arguments.get("to")
    return None, None


def _is_external(fqdn: str | None) -> bool:
    return fqdn is not None and not fqdn.endswith(".internal")


def _deny_early(
    reason: str, policy_id: str, agent_key: str, latency: dict[str, float]
) -> PipelineResult:
    return PipelineResult(
        decision=Decision.DENY,
        reason=reason,
        policy_id=policy_id,
        role=None,
        agent_key=agent_key,
        session_taint="clean",
        data_classification="internal",
        risk_score=0,
        risk_factors=[],
        latency_ms=_finalize(latency),
    )


def _elapsed_ms(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000


def _finalize(latency: dict[str, float]) -> dict[str, float]:
    for stage in PIPELINE_STAGES:
        latency.setdefault(stage, 0.0)
    latency["total"] = sum(latency[stage] for stage in PIPELINE_STAGES)
    return latency
