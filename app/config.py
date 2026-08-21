"""Application configuration loaded from environment variables."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the FastAPI service and governance pipeline."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", frozen=True)

    github_app_id: int = Field(default=0, validation_alias="GITHUB_APP_ID")
    github_app_private_key_path: str = Field(
        default="", validation_alias="GITHUB_APP_PRIVATE_KEY_PATH"
    )
    github_webhook_secret: str = Field(default="", validation_alias="GITHUB_WEBHOOK_SECRET")
    llm_api_key: str = Field(default="", validation_alias="LLM_API_KEY")
    llm_model: str = Field(
        default="ibm/granite-3-3-8b-instruct", validation_alias="LLM_MODEL"
    )
    llm_provider: str = Field(
        default="watsonx",
        pattern=r"^(openai|watsonx)$",
        validation_alias="LLM_PROVIDER",
    )
    watsonx_project_id: str = Field(
        default="",
        validation_alias="WATSONX_PROJECT_ID",
        description="watsonx.ai project ID",
    )
    watsonx_url: str = Field(
        default="https://us-south.ml.cloud.ibm.com",
        validation_alias="WATSONX_URL",
        description="watsonx.ai API endpoint URL",
    )
    admin_api_token: str = Field(
        default="",
        validation_alias="ADMIN_API_TOKEN",
        description="Bearer token for admin endpoints (approve/audit)",
    )
    workspace_root: str = Field(
        default=".",
        validation_alias="WORKSPACE_ROOT",
        description="Filesystem root the governed MCP tool handler may read/write within",
    )
    signing_method: str = Field(
        default="sigstore",
        pattern=r"^(sigstore|ed25519)$",
        validation_alias="SIGNING_METHOD",
    )
    ed25519_private_key_path: str | None = Field(
        default=None, validation_alias="ED25519_PRIVATE_KEY_PATH"
    )
    database_path: str = Field(default="data/audit.db", validation_alias="DATABASE_PATH")
    capsule_expiry_hours: int = Field(default=1, validation_alias="CAPSULE_EXPIRY_HOURS")
    pending_approval_ttl_hours: int = Field(
        default=24,
        validation_alias="PENDING_APPROVAL_TTL_HOURS",
        description="Hours an unresolved pending approval may remain before it is auto-expired",
    )
    pending_approval_retention_days: int = Field(
        default=30,
        validation_alias="PENDING_APPROVAL_RETENTION_DAYS",
        description="Days a resolved pending-approval/capsule record is kept before permanent deletion",
    )
    pending_cleanup_interval_minutes: int = Field(
        default=60,
        validation_alias="PENDING_CLEANUP_INTERVAL_MINUTES",
        description="How often the background sweep checks for expired/stale pending approvals",
    )
    host: str = Field(default="0.0.0.0", validation_alias="HOST")
    port: int = Field(default=8000, validation_alias="PORT")
    github_actions_identity: str = Field(
        default="https://github.com/example/repo/.github/workflows/main.yml@refs/heads/main",
        validation_alias="GITHUB_ACTIONS_IDENTITY"
    )
    github_actions_issuer: str = Field(
        default="https://token.actions.githubusercontent.com",
        validation_alias="GITHUB_ACTIONS_ISSUER"
    )


@lru_cache
def get_settings() -> Settings:
    """Return one immutable settings object for the running process."""

    return Settings()


settings = get_settings()
