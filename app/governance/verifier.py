"""Verification helpers for signed task capsules."""

from __future__ import annotations

import base64
import binascii
import logging
from pathlib import Path
from typing import Any

from app.config import Settings, get_settings
from app.governance.signer import canonicalize_capsule, resolve_ed25519_private_key_path
from app.models import SignedCapsule


logger = logging.getLogger(__name__)


def _load_ed25519_verify_key(settings: Settings):
    try:
        from nacl.signing import SigningKey, VerifyKey
    except Exception as exc:  # pragma: no cover - dependency-specific
        raise RuntimeError("PyNaCl is required for Ed25519 verification") from exc

    private_key_path = resolve_ed25519_private_key_path(settings)
    public_key_path = private_key_path.with_suffix(f"{private_key_path.suffix}.pub")
    if not public_key_path.exists():
        raise RuntimeError(
            f"Ed25519 public key file does not exist at {public_key_path}. "
            "Verification requires a public key file."
        )

    encoded_public_key = public_key_path.read_text(encoding="utf-8").strip()
    if not encoded_public_key:
        raise RuntimeError(f"Ed25519 public key file is empty: {public_key_path}")

    try:
        public_key_bytes = base64.b64decode(encoded_public_key, validate=True)
    except binascii.Error as exc:
        raise RuntimeError(
            f"Ed25519 public key file is not valid base64: {public_key_path}"
        ) from exc

    if len(public_key_bytes) != 32:
        raise RuntimeError(
            f"Ed25519 public key must be exactly 32 bytes; got {len(public_key_bytes)}"
        )
    return VerifyKey(public_key_bytes)


def _verify_sigstore_signature(payload_bytes: bytes, signature: dict[str, Any], settings: Settings) -> bool:
    try:
        import json

        from sigstore.models import Bundle, ClientTrustConfig
        from sigstore.verify import Verifier, policy
    except Exception as exc:  # pragma: no cover - optional dependency / API shape varies
        logger.warning("Sigstore verification unavailable: %s", exc)
        return False

    try:
        verifier = Verifier.from_trust_config(ClientTrustConfig.production())
        bundle = Bundle.from_json(json.dumps(signature))
        # Use the Identity policy to verify the specific GitHub Actions identity.
        verifier.verify_artifact(
            payload_bytes, 
            bundle, 
            policy.Identity(
                identity=settings.github_actions_identity,
                issuer=settings.github_actions_issuer,
            )
        )
        return True
    except Exception as exc:
        logger.warning("Sigstore verification failed: %s", exc)
        return False


def _verify_ed25519_signature(
    payload_bytes: bytes,
    signature: str,
    settings: Settings,
) -> bool:
    try:
        from nacl.exceptions import BadSignatureError
    except Exception as exc:  # pragma: no cover - dependency-specific
        logger.warning("PyNaCl verification dependency is unavailable: %s", exc)
        return False

    try:
        signature_bytes = base64.b64decode(signature, validate=True)
    except binascii.Error:
        return False

    try:
        verify_key = _load_ed25519_verify_key(settings)
        verify_key.verify(payload_bytes, signature_bytes)
        return True
    except (BadSignatureError, RuntimeError):
        return False


def verify_capsule(capsule: SignedCapsule, settings: Settings | None = None) -> bool:
    """Verify capsule expiry and signature validity."""

    if capsule.is_expired():
        return False

    payload_bytes = canonicalize_capsule(capsule)
    runtime_settings = settings or get_settings()
    signature = capsule.signature

    if isinstance(signature, dict):
        return _verify_sigstore_signature(payload_bytes, signature, runtime_settings)
    if isinstance(signature, str):
        return _verify_ed25519_signature(payload_bytes, signature, runtime_settings)
    return False
