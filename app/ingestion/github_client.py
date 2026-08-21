"""Small GitHub App-authenticated client for collaborator permission lookups."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import time
from pathlib import Path
from threading import Lock

from github import Auth, Github, GithubIntegration
from github.Repository import Repository

from app.config import Settings, get_settings


class GitHubClientConfigurationError(RuntimeError):
    """Raised when a collaborator lookup is attempted without GitHub App settings."""


_token_cache: dict[int, tuple[str, float]] = {}
_token_lock = Lock()


class GitHubClient:
    """Authenticate as a GitHub App installation and query repository permissions."""

    def __init__(self, configuration: Settings | None = None) -> None:
        self._settings = configuration or get_settings()

    @property
    def is_configured(self) -> bool:
        """Whether the minimum GitHub App settings are available for a lookup."""

        return bool(
            self._settings.github_app_id > 0
            and self._settings.github_app_private_key_path
        )

    @contextmanager
    def _repository(self, repo_full_name: str) -> Iterator[Repository]:
        """Yield a repository handle authenticated as the app installation."""

        if not self.is_configured:
            raise GitHubClientConfigurationError(
                "GitHub App ID and private key path must be configured"
            )

        owner, repo = repo_full_name.split("/", maxsplit=1)
        private_key = Path(self._settings.github_app_private_key_path).read_text(
            encoding="utf-8"
        )
        app_auth = Auth.AppAuth(self._settings.github_app_id, private_key)
        integration = GithubIntegration(auth=app_auth)

        try:
            installation = integration.get_repo_installation(owner, repo)
            with _token_lock:
                cached_token, expires_at = _token_cache.get(installation.id, (None, 0.0))
                if not cached_token or time.time() > expires_at:
                    installation_auth = integration.get_access_token(installation.id)
                    cached_token = installation_auth.token
                    _token_cache[installation.id] = (cached_token, time.time() + 3000)
                    if len(_token_cache) > 1000:
                        _token_cache.pop(next(iter(_token_cache)))

            github = Github(auth=Auth.Token(cached_token))
            try:
                yield github.get_repo(repo_full_name)
            finally:
                github.close()
        finally:
            integration.close()

    def get_collaborator_permission(self, repo_full_name: str, username: str) -> str:
        """Return GitHub's permission string for ``username`` in ``repo_full_name``.

        PyGithub raises its native exception for API failures, including a 404 for a
        non-collaborator. The resolver deliberately converts those failures into the
        fail-closed external tier.
        """

        with self._repository(repo_full_name) as repository:
            return repository.get_collaborator_permission(username)

    def post_issue_comment(self, repo_full_name: str, issue_number: int, body: str) -> None:
        """Post a comment on an issue or pull request thread using app installation auth."""

        with self._repository(repo_full_name) as repository:
            repository.get_issue(number=issue_number).create_comment(body)
