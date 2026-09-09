"""Cryptographic signing for policy-approved task capsules."""

from __future__ import annotations

import abc
import base64
import binascii
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from app.config import Settings, get_settings
from app.models import PolicyDecision, SignedCapsule


logger = logging.getLogger(__name__)

DEFAULT_ED25519_PRIVATE_KEY_PATH = "data/ed25519.key"


def resolve_ed25519_private_key_path(settings: Settings) -> Path:
    """Return the configured Ed25519 private-key path with a safe default."""

    configured_path = settings.ed25519_private_key_path or DEFAULT_ED25519_PRIVATE_KEY_PATH
    return Path(configured_path)


def _utc_isoformat(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _json_compatible(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, list):
        return [_json_compatible(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_compatible(item) for key, item in value.items()}
    return value


def canonical_json_bytes(payload: Mapping[str, Any]) -> bytes:
    """Serialize payload using deterministic canonical JSON rules."""

    return json.dumps(
        _json_compatible(dict(payload)),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonicalize_capsule(capsule: SignedCapsule) -> bytes:
    """Return canonical JSON bytes for all capsule fields except signature."""

    payload = capsule.model_dump(mode="json", exclude={"signature"})
    return canonical_json_bytes(payload)


def _build_unsigned_capsule(
    policy_decision: PolicyDecision,
    capsule_expiry_hours: int,
) -> SignedCapsule:
    expiry = datetime.now(timezone.utc) + timedelta(hours=capsule_expiry_hours)
    return SignedCapsule(
        capsule_id=str(uuid4()),
        intent=policy_decision.intent,
        allowed_tools=sorted(policy_decision.final_tools, key=lambda tool: tool.value),
        target_paths=sorted(policy_decision.final_paths),
        trust_tier=policy_decision.trust_tier,
        expiry=_utc_isoformat(expiry),
        source_hash=policy_decision.source_hash,
        compiler_version=policy_decision.compiler_version,
        allowed_hosts=sorted(policy_decision.allowed_hosts),
        signature="",
    )


def _coerce_sigstore_bundle(raw_bundle: Any) -> dict[str, Any]:
    """Normalize common Sigstore signing return shapes into a JSON object."""

    if isinstance(raw_bundle, dict):
        return raw_bundle

    if hasattr(raw_bundle, "to_json") and callable(raw_bundle.to_json):
        raw_bundle = raw_bundle.to_json()
    elif hasattr(raw_bundle, "model_dump") and callable(raw_bundle.model_dump):
        dumped = raw_bundle.model_dump(mode="json")
        if isinstance(dumped, dict):
            return dumped
        raw_bundle = dumped

    if isinstance(raw_bundle, (bytes, bytearray)):
        raw_bundle = raw_bundle.decode("utf-8")

    if isinstance(raw_bundle, str):
        parsed = json.loads(raw_bundle)
        if isinstance(parsed, dict):
            return parsed

    raise TypeError("Sigstore signer returned an unsupported bundle format")


def _sigstore_sign(payload_bytes: bytes) -> dict[str, Any]:
    """Sign canonical bytes with Sigstore using ambient OIDC identity."""

    try:
        from sigstore.models import ClientTrustConfig
        from sigstore.oidc import IdentityToken, detect_credential
        from sigstore.sign import SigningContext
    except Exception as exc:  # pragma: no cover - optional dependency / API shape varies
        raise RuntimeError("Sigstore signing API is unavailable") from exc

    raw_token = detect_credential()
    if raw_token is None:
        raise RuntimeError("No ambient OIDC credential available for Sigstore signing")

    identity_token = IdentityToken(raw_token)
    ctx = SigningContext.from_trust_config(ClientTrustConfig.production())
    with ctx.signer(identity_token) as signer:
        bundle = signer.sign_artifact(payload_bytes)
    return _coerce_sigstore_bundle(bundle)


class CapsuleSigner(abc.ABC):
    """Abstract capsule signer used by ingestion and issuance flows."""

    @abc.abstractmethod
    async def sign(self, policy_decision: PolicyDecision) -> SignedCapsule:
        """Sign one policy decision and return a signed capsule."""


class Ed25519Signer(CapsuleSigner):
    """Sign capsules with a locally managed Ed25519 keypair."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        create_if_missing: bool = True,
    ) -> None:
        self._settings = settings or get_settings()
        self._private_key_path = resolve_ed25519_private_key_path(self._settings)
        self._create_if_missing = create_if_missing

    def _load_signing_key(self):
        try:
            from nacl.signing import SigningKey
        except Exception as exc:  # pragma: no cover - dependency-specific
            raise RuntimeError("PyNaCl is required for Ed25519 signing") from exc

        key_path = self._private_key_path
        if not key_path.exists():
            if not self._create_if_missing:
                raise RuntimeError(
                    f"Ed25519 private key not found at {key_path}; cannot use fallback signer"
                )

            key_path.parent.mkdir(parents=True, exist_ok=True)
            signing_key = SigningKey.generate()
            encoded_private_key = base64.b64encode(signing_key.encode()).decode("ascii")
            key_path.write_text(encoded_private_key, encoding="utf-8")
            os.chmod(str(key_path), 0o600)

            public_key_path = key_path.with_suffix(f"{key_path.suffix}.pub")
            encoded_public_key = base64.b64encode(signing_key.verify_key.encode()).decode("ascii")
            public_key_path.write_text(encoded_public_key, encoding="utf-8")

            logger.info("Generated Ed25519 keypair at %s", key_path)
            return signing_key

        try:
            os.chmod(str(key_path), 0o600)
        except OSError as exc:
            logger.warning("Could not set 0600 permissions on existing Ed25519 key: %s", exc)

        encoded_private_key = key_path.read_text(encoding="utf-8").strip()
        if not encoded_private_key:
            raise RuntimeError(f"Ed25519 private key file is empty: {key_path}")

        try:
            private_key_bytes = base64.b64decode(encoded_private_key, validate=True)
        except binascii.Error as exc:
            raise RuntimeError(
                f"Ed25519 private key file is not valid base64: {key_path}"
            ) from exc

        if len(private_key_bytes) != 32:
            raise RuntimeError(
                f"Ed25519 private key must be exactly 32 bytes; got {len(private_key_bytes)}"
            )
        return SigningKey(private_key_bytes)

    async def sign(self, policy_decision: PolicyDecision) -> SignedCapsule:
        unsigned_capsule = _build_unsigned_capsule(
            policy_decision,
            self._settings.capsule_expiry_hours,
        )
        payload_bytes = canonicalize_capsule(unsigned_capsule)
        signing_key = self._load_signing_key()
        signature = signing_key.sign(payload_bytes).signature
        encoded_signature = base64.b64encode(signature).decode("ascii")
        return unsigned_capsule.model_copy(update={"signature": encoded_signature})


class SigstoreSigner(CapsuleSigner):
    """Sign capsules with Sigstore, optionally falling back to Ed25519."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def sign(self, policy_decision: PolicyDecision) -> SignedCapsule:
        unsigned_capsule = _build_unsigned_capsule(
            policy_decision,
            self._settings.capsule_expiry_hours,
        )
        payload_bytes = canonicalize_capsule(unsigned_capsule)

        try:
            bundle = _sigstore_sign(payload_bytes)
            return unsigned_capsule.model_copy(update={"signature": bundle})
        except Exception as exc:
            logger.exception("Sigstore signing failed")
            
            if not self._settings.sigstore_fallback_enabled:
                raise RuntimeError("Sigstore signing failed and fallback is disabled") from exc
                
            try:
                fallback = Ed25519Signer(self._settings, create_if_missing=True)
            except Exception as fallback_exc:
                raise RuntimeError(
                    "Sigstore signing failed and Ed25519 fallback is unavailable"
                ) from fallback_exc

            logger.warning(
                "Falling back to Ed25519 signing after Sigstore failure: %s", exc
            )
            return await fallback.sign(policy_decision)


def create_signer(settings: Settings) -> CapsuleSigner:
    """Construct the signer configured for the current runtime."""

    if settings.signing_method == "sigstore":
        return SigstoreSigner(settings)
    return Ed25519Signer(settings)
