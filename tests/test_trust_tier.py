"""Tests for deterministic, fail-closed trust-tier resolution."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from github.GithubException import GithubException

from app.config import Settings
from app.ingestion.github_client import GitHubClient
from app.ingestion.trust_tier import PERMISSION_TO_TIER, resolve_trust_tier
from app.models import TrustTier


@pytest.fixture
def workspace_tmp_path() -> Path:
    base = Path(".pytest_tmp") / "trust-tier"
    path = base / str(uuid4())
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.mark.parametrize(
    ("permission", "expected_tier"),
    [
        ("admin", TrustTier.MAINTAINER),
        ("maintain", TrustTier.MAINTAINER),
        ("write", TrustTier.CONTRIBUTOR),
        ("triage", TrustTier.EXTERNAL),
        ("read", TrustTier.EXTERNAL),
        ("none", TrustTier.EXTERNAL),
    ],
)
def test_permission_mapping(permission: str, expected_tier: TrustTier) -> None:
    assert PERMISSION_TO_TIER[permission] is expected_tier


@pytest.mark.parametrize("permission", ["admin", "maintain", "write", "triage", "read", "none"])
def test_resolve_trust_tier_uses_github_permission(permission: str) -> None:
    with patch(
        "app.ingestion.trust_tier.GitHubClient.get_collaborator_permission",
        return_value=permission,
    ):
        result = asyncio.run(resolve_trust_tier("octocat", "owner/repo"))

    assert result.github_permission == permission
    assert result.trust_tier is PERMISSION_TO_TIER[permission]
    assert result.author == "octocat"
    assert result.repo_full_name == "owner/repo"


def test_unknown_permission_defaults_to_external() -> None:
    with patch(
        "app.ingestion.trust_tier.GitHubClient.get_collaborator_permission",
        return_value="superuser",
    ):
        result = asyncio.run(resolve_trust_tier("octocat", "owner/repo"))

    assert result.trust_tier is TrustTier.EXTERNAL
    assert result.github_permission == "none"


def test_github_404_defaults_to_external() -> None:
    with patch(
        "app.ingestion.trust_tier.GitHubClient.get_collaborator_permission",
        side_effect=GithubException(404, {"message": "Not Found"}),
    ):
        result = asyncio.run(resolve_trust_tier("octocat", "owner/repo"))

    assert result.trust_tier is TrustTier.EXTERNAL
    assert result.github_permission == "none"


def test_missing_github_configuration_defaults_to_external(caplog: pytest.LogCaptureFixture) -> None:
    result = asyncio.run(resolve_trust_tier("octocat", "owner/repo"))

    assert result.trust_tier is TrustTier.EXTERNAL
    assert result.github_permission == "none"
    assert "Unable to resolve GitHub permission" in caplog.text


def test_github_client_uses_app_installation_token_for_permission_lookup(
    workspace_tmp_path: Path,
) -> None:
    private_key_path = workspace_tmp_path / "github-app.pem"
    private_key_path.write_text("test private key", encoding="utf-8")
    configuration = Settings(
        GITHUB_APP_ID=123,
        GITHUB_APP_PRIVATE_KEY_PATH=str(private_key_path),
    )

    with (
        patch("app.ingestion.github_client.Auth.AppAuth"),
        patch("app.ingestion.github_client.GithubIntegration") as integration_class,
        patch("app.ingestion.github_client.Github") as github_class,
    ):
        integration = integration_class.return_value
        installation = integration.get_repo_installation.return_value
        installation.id = 456
        integration.get_access_token.return_value.token = "installation-token"
        repository = github_class.return_value.get_repo.return_value
        repository.get_collaborator_permission.return_value = "write"

        permission = GitHubClient(configuration).get_collaborator_permission(
            "owner/repo", "octocat"
        )

    assert permission == "write"
    integration.get_repo_installation.assert_called_once_with("owner", "repo")
    github_class.return_value.get_repo.assert_called_once_with("owner/repo")
    repository.get_collaborator_permission.assert_called_once_with("octocat")
