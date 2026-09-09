"""Tests for deterministic policy scope intersection and escalation."""

from __future__ import annotations

import uuid
from app.governance.policy import PolicyEngine
from app.models import CapsuleSummary, CompilerOutput, KnownTools, SessionHistory, TrustTier


SOURCE_HASH = "a" * 64


def compiler_output(
    tools: list[KnownTools], paths: list[str] | None = None
) -> CompilerOutput:
    return CompilerOutput(
        intent="Update the requested component",
        requested_tools=tools,
        target_paths=paths or ["src/component.py"],
        compiler_model="test-model",
        compiler_version="1.0.0",
    )


def session_history(**overrides: object) -> SessionHistory:
    return SessionHistory(thread_id="owner/repo#1", **overrides)


def evaluate(
    tools: list[KnownTools],
    tier: TrustTier,
    paths: list[str] | None = None,
    history: SessionHistory | None = None,
):
    return PolicyEngine().evaluate(
        compiler_output(tools, paths), tier, history or session_history(), SOURCE_HASH
    )


def test_external_tier_blocks_write_file_but_allows_read_file() -> None:
    decision = evaluate(
        [KnownTools.READ_FILE, KnownTools.WRITE_FILE], TrustTier.EXTERNAL
    )

    assert decision.allow is True
    assert decision.final_tools == [KnownTools.READ_FILE]


def test_external_tier_blocks_root_env_path() -> None:
    decision = evaluate(
        [KnownTools.READ_FILE], TrustTier.EXTERNAL, [".env", "src/component.py"]
    )

    assert decision.allow is True
    assert decision.final_paths == ["src/component.py"]


def test_external_tier_denies_more_than_five_permitted_files() -> None:
    paths = [f"src/module_{index}.py" for index in range(6)]
    decision = evaluate([KnownTools.READ_FILE], TrustTier.EXTERNAL, paths)

    assert decision.allow is False
    assert decision.denial_reason is not None
    assert "at most 5 target paths" in decision.denial_reason


def test_contributor_allows_write_file_but_blocks_execute_cmd() -> None:
    decision = evaluate(
        [KnownTools.WRITE_FILE, KnownTools.EXECUTE_CMD], TrustTier.CONTRIBUTOR
    )

    assert decision.allow is True
    assert decision.final_tools == [KnownTools.WRITE_FILE]


def test_maintainer_allows_all_tools_and_requires_approval_for_network() -> None:
    decision = evaluate(list(KnownTools), TrustTier.MAINTAINER)

    assert decision.allow is True
    assert decision.final_tools == list(KnownTools)
    assert decision.require_human_approval is True


def test_empty_final_tools_denies_request() -> None:
    decision = evaluate([KnownTools.NET_REQUEST], TrustTier.EXTERNAL)

    assert decision.allow is False
    assert decision.final_tools == []
    assert decision.denial_reason is not None


def test_session_history_with_three_recent_capsules_requires_approval() -> None:
    summary = CapsuleSummary(
        capsule_id="00000000-0000-0000-0000-000000000001",
        issued_at="2026-08-09T00:00:00Z",
        trust_tier=TrustTier.EXTERNAL,
        tools_count=1,
        paths_count=1,
    )
    history = session_history(recent_capsules=[summary, summary, summary])

    decision = evaluate([KnownTools.READ_FILE], TrustTier.EXTERNAL, history=history)

    assert decision.allow is True
    assert decision.require_human_approval is True


def test_denial_reason_is_meaningful() -> None:
    decision = evaluate([KnownTools.EXECUTE_CMD], TrustTier.CONTRIBUTOR)

    assert decision.allow is False
    assert decision.denial_reason is not None
    assert "No requested tools are permitted" in decision.denial_reason


def test_unanchored_glob_is_denied() -> None:
    decision = evaluate([KnownTools.READ_FILE], TrustTier.EXTERNAL, ["**/*.md"])

    assert decision.allow is False
    assert decision.denial_reason is not None
    assert "overly broad" in decision.denial_reason


def test_anchored_glob_is_allowed() -> None:
    decision = evaluate([KnownTools.READ_FILE], TrustTier.EXTERNAL, ["src/**/*.md"])

    assert decision.allow is True
    assert decision.final_paths == ["src/**/*.md"]


def test_external_tier_blocks_env_variant_paths() -> None:
    decision = evaluate(
        [KnownTools.READ_FILE],
        TrustTier.EXTERNAL,
        [".env.production", "src/app.py"],
    )

    assert decision.final_paths == ["src/app.py"]


def test_contributor_tier_blocks_git_and_env_variants() -> None:
    decision = evaluate(
        [KnownTools.WRITE_FILE],
        TrustTier.CONTRIBUTOR,
        [".git/hooks/pre-commit", ".env.local", "src/app.py"],
    )

    assert decision.final_paths == ["src/app.py"]


def test_maintainer_secrets_access_requires_approval() -> None:
    decision = evaluate([KnownTools.READ_FILE], TrustTier.MAINTAINER, [".env"])

    assert decision.allow is True
    assert decision.require_human_approval is True


def test_single_consecutive_high_scope_triggers_approval() -> None:
    history = session_history(consecutive_high_scope=1)

    decision = evaluate([KnownTools.READ_FILE], TrustTier.EXTERNAL, history=history)

    assert decision.allow is True
    assert decision.require_human_approval is True
