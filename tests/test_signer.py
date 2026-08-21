"""Tests for capsule signing and verification."""

from __future__ import annotations

import asyncio
import importlib.util
import os
from pathlib import Path
import shutil
from uuid import uuid4

import pytest

from app.config import Settings
from app.governance.signer import Ed25519Signer, SigstoreSigner, canonical_json_bytes
from app.governance.verifier import verify_capsule
from app.models import KnownTools, PolicyDecision, TrustTier


@pytest.fixture
def workspace_tmp_path() -> Path:
    base = Path(".pytest_tmp") / "signer"
    path = base / str(uuid4())
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def policy_decision() -> PolicyDecision:
    return PolicyDecision(
        allow=True,
        final_tools=[KnownTools.WRITE_FILE, KnownTools.READ_FILE],
        final_paths=["tests/**", "app/**"],
        trust_tier=TrustTier.CONTRIBUTOR,
        require_human_approval=False,
        denial_reason=None,
        intent="Update signer behavior",
        source_hash="a" * 64,
        compiler_version="1.0.0",
    )


def runtime_settings(tmp_path: Path, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "SIGNING_METHOD": "ed25519",
        "ED25519_PRIVATE_KEY_PATH": str(tmp_path / "ed25519.key"),
        "CAPSULE_EXPIRY_HOURS": 1,
    }
    values.update(overrides)
    return Settings(**values)


def test_ed25519_sign_then_verify_round_trip_succeeds(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    signer = Ed25519Signer(settings)

    capsule = asyncio.run(signer.sign(policy_decision()))

    assert verify_capsule(capsule, settings=settings) is True


def test_ed25519_verification_fails_on_tampered_capsule(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    signer = Ed25519Signer(settings)
    capsule = asyncio.run(signer.sign(policy_decision()))

    tampered = capsule.model_copy(update={"intent": "Escalated intent"})

    assert verify_capsule(tampered, settings=settings) is False


def test_expired_capsule_fails_verification(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path, CAPSULE_EXPIRY_HOURS=-1)
    signer = Ed25519Signer(settings)

    capsule = asyncio.run(signer.sign(policy_decision()))

    assert verify_capsule(capsule, settings=settings) is False


def test_canonical_json_is_deterministic() -> None:
    payload_one = {
        "capsule_id": "00000000-0000-0000-0000-000000000001",
        "intent": "Read docs",
        "allowed_tools": ["read_file", "write_file"],
        "target_paths": ["README.md", "docs/**"],
        "trust_tier": "contributor",
        "expiry": "2030-01-01T00:00:00Z",
        "source_hash": "f" * 64,
        "compiler_version": "1.0.0",
    }
    payload_two = {
        "source_hash": "f" * 64,
        "trust_tier": "contributor",
        "target_paths": ["README.md", "docs/**"],
        "intent": "Read docs",
        "compiler_version": "1.0.0",
        "expiry": "2030-01-01T00:00:00Z",
        "allowed_tools": ["read_file", "write_file"],
        "capsule_id": "00000000-0000-0000-0000-000000000001",
    }

    assert canonical_json_bytes(payload_one) == canonical_json_bytes(payload_two)


HAS_SIGSTORE = importlib.util.find_spec("sigstore") is not None
HAS_OIDC_IDENTITY = any(
    os.getenv(variable)
    for variable in (
        "SIGSTORE_IDENTITY_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "OIDC_ID_TOKEN",
    )
)


@pytest.mark.skipif(
    not (HAS_SIGSTORE and HAS_OIDC_IDENTITY),
    reason="Sigstore signing test requires sigstore and an ambient OIDC identity",
)
def test_sigstore_signing_path_when_oidc_is_available(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path, SIGNING_METHOD="sigstore")
    signer = SigstoreSigner(settings)

    capsule = asyncio.run(signer.sign(policy_decision()))

    assert verify_capsule(capsule, settings=settings) is True


def test_ed25519_verification_fails_if_only_private_key_exists(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    signer = Ed25519Signer(settings)
    capsule = asyncio.run(signer.sign(policy_decision()))
    
    pub_key = workspace_tmp_path / "ed25519.key.pub"
    if pub_key.exists():
        pub_key.unlink()
        
    assert verify_capsule(capsule, settings=settings) is False


def test_ed25519_verification_fails_if_public_key_empty(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    signer = Ed25519Signer(settings)
    capsule = asyncio.run(signer.sign(policy_decision()))
    
    pub_key = workspace_tmp_path / "ed25519.key.pub"
    pub_key.write_text("")
        
    assert verify_capsule(capsule, settings=settings) is False
