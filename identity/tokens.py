"""Ed25519 mint/verify for short-lived workload tokens — pure crypto, no FastAPI or Docker-socket
dependency, so pep can import this without pulling in either."""

from __future__ import annotations

import base64
import binascii
import json
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# AGENTFW_CONTEXT.md §2 (resolved M0): exp = iat + 15min.
TOKEN_TTL_SECONDS = 15 * 60


class TokenInvalidError(Exception):
    """Raised by verify_token() for any bad signature, malformed token, or expired token.

    The caller (pep/pipeline.py stage 1) treats every subtype of failure identically —
    identity_verification_failed, full stop — so this is one exception type, not a hierarchy: a
    finer-grained distinction would just invite a caller to someday handle one case more leniently
    than another, which is exactly the mistake this stage exists to prevent.
    """


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def public_key_to_b64(public_key: Ed25519PublicKey) -> str:
    return base64.urlsafe_b64encode(public_key.public_bytes_raw()).decode("ascii")


def public_key_from_b64(data: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(data))


def mint_token(claims: dict[str, Any], private_key: Ed25519PrivateKey) -> str:
    """`claims` must not set iat/exp — those are stamped here, never by the caller, so a caller
    can't hand itself a longer-lived token than the issuer intends."""
    now = int(time.time())
    payload = {**claims, "iat": now, "exp": now + TOKEN_TTL_SECONDS}
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = private_key.sign(payload_bytes)
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii")
    sig_b64 = base64.urlsafe_b64encode(signature).decode("ascii")
    return f"{payload_b64}.{sig_b64}"


def verify_token(token: str, public_key: Ed25519PublicKey) -> dict[str, Any]:
    """Verify signature and expiry. Returns the claims dict on success, raises TokenInvalidError
    otherwise. Does NOT check container binding — that's the caller's job (it has to compare
    payload["container_id"] against something the transport layer told it), since this module has
    no notion of "the current connection."""
    try:
        payload_b64, sig_b64 = token.split(".")
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        signature = base64.urlsafe_b64decode(sig_b64)
    except (ValueError, binascii.Error) as exc:
        raise TokenInvalidError(f"malformed token: {exc}") from exc

    try:
        public_key.verify(signature, payload_bytes)
    except InvalidSignature as exc:
        raise TokenInvalidError("signature verification failed") from exc

    payload: dict[str, Any] = json.loads(payload_bytes)
    if payload.get("exp", 0) < time.time():
        raise TokenInvalidError("token expired")
    return payload
