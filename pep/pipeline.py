"""The fixed 8-stage decision pipeline: identity, normalize, policy, threat intel, DLP, risk,
decide, log."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

import dlp.detectors as dlp
import pep.quarantine as quarantine
import risk.scorer as risk
import threat_intel.feed as threat_intel
from identity.tokens import TokenInvalidError, public_key_from_b64, verify_token
from pep.normalize import normalize_path, normalize_url
from policy.compiler import compile_bundle
from policy.engine import (
    BLOCKED_DECISIONS,
    EXECUTABLE_DECISIONS,
    Decision,
    evaluate,
    evaluate_east_west,
)

IDENTITY_ISSUER_URL = os.environ.get("IDENTITY_ISSUER_URL", "http://identity:8082")
POLICY_BUNDLE_PATH = os.environ.get("POLICY_BUNDLE_PATH", "policy/bundles/default.yaml")

ACTION_MAP = {
    "http.get": "read",
    "http.post": "write",
    "db.query": "read",
    "file.read": "read",
    "email.send": "write",
    "agent.invoke": "invoke",
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
    normalized_arguments: dict[str, Any] = field(default_factory=dict)


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
    role, agent_key, workload_key, id_reason = _verify_identity(token, peer_ip)
    latency["identity"] = _elapsed_ms(t0)
    if role is None:
        return _deny_early(id_reason, "IDENTITY_DENY", agent_key, latency)

    # --- Quarantine gate: absolute, checked before any policy/risk work runs ---
    # WHY here, not folded into stage 1: identity succeeded — the token's signature, expiry, and
    # container binding are all genuinely valid. This is a separate question: is THIS identity
    # currently blocked, regardless of what it's asking for. "Regardless of policy" means exactly
    # that — no rule, however permissive, can override it (pep/quarantine.py: exit is manual only).
    try:
        quarantined = quarantine.is_quarantined(workload_key)
    except quarantine.QuarantineCheckUnavailable:
        # WHY a distinct reason, not AGENT_QUARANTINED: conflating "checked and found genuinely
        # quarantined" with "couldn't check, failing safe" would hide an eventstore outage behind
        # a misleading label — see pep/quarantine.py's QuarantineCheckUnavailable docstring.
        return _deny_early(
            "quarantine_check_unavailable", "QUARANTINE_CHECK_FAILED", agent_key, latency
        )
    if quarantined:
        return _deny_early("AGENT_QUARANTINED", "QUARANTINE_DENY", agent_key, latency)

    # --- Stage 2: request normalization ---
    # WHY the canonical form replaces `arguments` for every stage from here on, including what
    # eventually gets forwarded: evaluating against one form and forwarding another is exactly the
    # confused-deputy gap pep/normalize.py exists to close (AGENTFW_CONTEXT.md §2).
    t0 = time.perf_counter()
    arguments = normalize_arguments(tool, arguments)
    fqdn, resource = extract_target(tool, arguments)
    latency["normalize"] = _elapsed_ms(t0)

    # --- Stage 3: policy evaluation ---
    # WHY "agent.invoke" branches to a different evaluator entirely, not just a different rule
    # table: it's asking a different question. Every other tool asks "may THIS ROLE reach THIS
    # DESTINATION" — agent.invoke asks "may THIS WORKLOAD reach THAT WORKLOAD," which
    # policy/engine.py's evaluate() has no vocabulary for (its rules match role/tool/destination,
    # not source/dest workload pairs). A valid token proves who's asking; it says nothing about
    # who they're allowed to ask (AGENTFW_CONTEXT.md pre-M3 multi-agent ruling).
    t0 = time.perf_counter()
    session_taint = "tainted" if _SESSION_TAINT.get(session_id, False) else "clean"
    if tool == "agent.invoke":
        policy_result = evaluate_east_west(
            BUNDLE,
            source_workload=workload_key,
            dest_workload=str(arguments.get("target_service", "")),
            action="invoke",
        )
    else:
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
    # WHY workload_key here, not agent_key: behavioral history ("has this agent called this
    # destination before") is a fact about the deployed workload, which risk/baseline.jsonl can
    # pre-seed because it's known from the registry ahead of time — not about this one ephemeral
    # container process, which didn't exist when the baseline was written. The event log still
    # uses the more specific agent_key (below) for forensic purposes; only risk scoring and
    # quarantine use the stable key.
    t0 = time.perf_counter()
    risk_result = risk.score(
        agent_id=workload_key,
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
        agent_id=workload_key,
        role=role,
        tool=tool,
        destination_key=fqdn or resource,
        decision=final_decision,
    )

    # --- Quarantine triggers: risk CRITICAL, a threat-intel hit, or >=5 denials in 60s ---
    # WHY checked here, after the verdict, rather than folded into stage 6/7: entering quarantine
    # is a *response* to this call's outcome, not part of deciding it — this call itself is
    # already governed by the ordinary decision above; only the *next* call from this agent will
    # see the quarantine gate. WHY BLOCKED_DECISIONS (DENY or QUARANTINE), not DENY alone: a call
    # already narrowed to QUARANTINE by this same risk score still represents a blocked action for
    # counting purposes — record_denial() must run for every blocked call regardless of the other
    # two triggers, so the 60s counter doesn't miss calls that were blocked for unrelated reasons.
    if final_decision in BLOCKED_DECISIONS and quarantine.record_denial(workload_key):
        quarantine.enter(workload_key, "5+ denials within 60 seconds")
    if risk_result.band == "CRITICAL":
        quarantine.enter(workload_key, "risk score reached CRITICAL band")
    if ti_hit:
        quarantine.enter(workload_key, "threat-intelligence hit on destination")

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
        normalized_arguments=arguments,
    )


def _verify_identity(token: str | None, peer_ip: str | None) -> tuple[str | None, str, str, str]:
    """Returns (role, agent_key, workload_key, reason). role is None on any failure.

    agent_key and workload_key are always strings (falling back to the peer IP) so risk/event
    logging always has *something* to key on — an unauthenticated caller still gets tracked, just
    not authorized. They diverge on success: agent_key is the specific container instance (for
    event-log forensics), workload_key is the stable, registry-known identity (for risk scoring
    and quarantine — see the WHY at their call sites in run_pipeline)."""
    fallback_key = peer_ip or "unknown"
    if not token:
        return None, fallback_key, fallback_key, "identity_verification_failed: no token presented"
    try:
        public_key = _get_issuer_public_key()
        claims = verify_token(token, public_key)
    except TokenInvalidError as exc:
        return None, fallback_key, fallback_key, f"identity_verification_failed: {exc}"
    except httpx.HTTPError:
        return None, fallback_key, fallback_key, "identity_verification_failed: issuer unreachable"

    # --- container binding: the connection presenting this token must be the same one the
    # issuer attested (AGENTFW_CONTEXT.md §2) — a stolen token replayed from elsewhere fails here
    # even though its signature is perfectly valid.
    if peer_ip is None or claims.get("attested_ip") != peer_ip:
        return (
            None,
            fallback_key,
            fallback_key,
            "identity_verification_failed: container binding mismatch",
        )

    agent_key = claims.get("container_id", fallback_key)[:12]
    workload_key = claims.get("service") or agent_key
    return claims["role"], agent_key, workload_key, "ok"


def _get_issuer_public_key():
    global _ISSUER_PUBLIC_KEY
    if _ISSUER_PUBLIC_KEY is None:
        resp = httpx.get(f"{IDENTITY_ISSUER_URL}/public-key", timeout=5.0)
        resp.raise_for_status()
        _ISSUER_PUBLIC_KEY = public_key_from_b64(resp.json()["public_key"])
    return _ISSUER_PUBLIC_KEY


def extract_target(tool: str, arguments: dict[str, Any]) -> tuple[str | None, str | None]:
    """Read the destination/resource out of `arguments`. Called after normalize_arguments() has
    already run (see run_pipeline's stage 2), so a bare urlsplit is sufficient here — the
    canonicalizing work (punycode, traversal collapse, userinfo strip, ...) already happened once,
    in pep/normalize.py, and doesn't need repeating."""
    if tool.startswith("http."):
        parsed = urlsplit(arguments.get("url", ""))
        return parsed.hostname, (parsed.path or None)
    if tool == "db.query":
        return None, arguments.get("table")
    if tool == "file.read":
        return None, arguments.get("path")
    if tool == "email.send":
        return None, arguments.get("to")
    if tool == "agent.invoke":
        return None, arguments.get("target_service")
    return None, None


def normalize_arguments(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of `arguments` with URL/path fields replaced by their canonical form
    (pep/normalize.py) — this is what every stage from here on sees, and what eventually gets
    forwarded (pep/proxy.py's _execute()), never the caller's original."""
    normalized = dict(arguments)
    if tool.startswith("http.") and "url" in normalized:
        normalized["url"] = normalize_url(normalized["url"]).url
    if tool == "file.read" and "path" in normalized:
        normalized["path"] = normalize_path(normalized["path"])
    return normalized


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
