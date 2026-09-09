import uuid
import os
import pytest

# Alternatively, setting them immediately on import might be safer if modules are imported before fixtures run.
os.environ.setdefault("SIGNING_METHOD", "ed25519")
os.environ.setdefault("ED25519_PRIVATE_KEY_PATH", "data/ed25519.key")
os.environ.setdefault("GITHUB_ACTIONS_IDENTITY", "https://github.com/my-org/my-repo/.github/workflows/deploy.yml@refs/heads/main")
os.environ.setdefault("GITHUB_ACTIONS_ISSUER", "https://token.actions.githubusercontent.com")
os.environ.setdefault("GITHUB_APP_ID", "12345")
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "test-secret")
os.environ.setdefault("ADMIN_API_TOKEN", "test-token")
os.environ.setdefault("WATSONX_PROJECT_ID", "test-project-id")
os.environ.setdefault("LLM_API_KEY", "test-api-key")
