"""Shared, immutable data contracts for Signed Task Capsules."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


GITHUB_USERNAME_PATTERN = r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\[bot\])?$"
REPOSITORY_FULL_NAME_PATTERN = r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
SHA256_PATTERN = r"^[0-9a-f]{64}$"
UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
SEMVER_PATTERN = r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
UTC_TIMESTAMP_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)$"
THREAD_ID_PATTERN = r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#(delivery-[0-9a-fA-F-]+|\d+)$"

PathPattern = Annotated[str, Field(min_length=1, max_length=200)]


class TrustTier(str, Enum):
    """Trust level derived from a GitHub collaborator permission."""

    EXTERNAL = "external"
    CONTRIBUTOR = "contributor"
    MAINTAINER = "maintainer"


class KnownTools(str, Enum):
    """The exhaustive set of tools that policy may grant to a capsule."""

    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    RUN_TESTS = "run_tests"
    EXECUTE_CMD = "execute_cmd"
    NET_REQUEST = "net_request"


class AuditEventType(str, Enum):
    """The exhaustive set of auditable governance events."""

    CAPSULE_ISSUED = "capsule_issued"
    CAPSULE_DENIED = "capsule_denied"
    CAPSULE_PENDING = "capsule_pending"
    CAPSULE_APPROVED = "capsule_approved"
    CAPSULE_EXPIRED = "capsule_expired"
    TOOL_ALLOWED = "tool_allowed"
    TOOL_BLOCKED = "tool_blocked"


class FrozenModel(BaseModel):
    """Base model for data that must not change after a trust boundary."""

    model_config = ConfigDict(frozen=True, extra="forbid")


def _validate_utc_timestamp(value: str) -> str:
    """Accept only parseable ISO 8601 timestamps expressed in UTC."""

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("must be an ISO 8601 UTC timestamp") from exc

    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("must be an ISO 8601 UTC timestamp")
    return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class WebhookEvent(FrozenModel):
    """Validated, untrusted material extracted from an incoming GitHub webhook."""

    event_type: str = Field(description="GitHub webhook event type from the X-GitHub-Event header")
    raw_text: str = Field(
        max_length=65_536,
        description="The untrusted text body from the issue, pull request, or comment",
    )
    author: str = Field(
        min_length=1,
        max_length=39,
        pattern=GITHUB_USERNAME_PATTERN,
        description="The sender.login from the webhook payload",
    )
    repo_full_name: str = Field(
        pattern=REPOSITORY_FULL_NAME_PATTERN,
        description="The repository.full_name from the webhook payload",
    )
    source_url: str = Field(
        min_length=1,
        pattern=r"^https://github\.com/.+",
        description="URL of the originating issue, pull request, or comment",
    )
    raw_payload_hash: str = Field(
        pattern=SHA256_PATTERN,
        description="SHA-256 hash of the raw webhook body bytes, computed before JSON parsing",
    )

    @field_validator("source_url")
    @classmethod
    def source_url_must_be_a_github_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or parsed.hostname != "github.com" or not parsed.path:
            raise ValueError("must be a valid https://github.com URL")
        return value


class TrustTierResult(FrozenModel):
    """The deterministic GitHub permission lookup result."""

    author: str = Field(
        min_length=1,
        max_length=39,
        pattern=GITHUB_USERNAME_PATTERN,
        description="GitHub username that was looked up",
    )
    repo_full_name: str = Field(
        pattern=REPOSITORY_FULL_NAME_PATTERN,
        description="Repository the lookup was performed against",
    )
    trust_tier: TrustTier = Field(
        description="Resolved trust tier based on GitHub permission level"
    )
    github_permission: Literal["admin", "maintain", "write", "triage", "read", "none"] = Field(
        description="Raw permission level returned by the GitHub API"
    )
    resolved_at: str = Field(
        pattern=UTC_TIMESTAMP_PATTERN,
        description="When the permission lookup was performed",
    )

    @field_validator("resolved_at")
    @classmethod
    def resolved_at_must_be_utc(cls, value: str) -> str:
        return _validate_utc_timestamp(value)


class CompilerOutput(FrozenModel):
    """Schema-constrained intent compiled from untrusted request text."""

    intent: str = Field(
        min_length=1,
        max_length=500,
        description="Extracted task summary from the raw text",
    )
    requested_tools: list[KnownTools] = Field(
        max_length=5,
        description="Tools the compiler thinks the task needs",
    )
    target_paths: list[PathPattern] = Field(
        max_length=20,
        description="File paths or glob patterns the task targets",
    )
    compiler_model: str = Field(
        min_length=1,
        description="Identifier of the LLM model used for compilation",
    )
    compiler_version: str = Field(
        pattern=SEMVER_PATTERN,
        description="Version of the compiler logic",
    )
    allowed_hosts: list[str] = Field(
        default_factory=list,
        description="List of allowed hostnames for network requests",
    )


class PolicyDecision(FrozenModel):
    """Deterministic policy evaluation output supplied to the signer."""

    allow: bool = Field(description="Whether the request passed policy evaluation")
    final_tools: list[KnownTools] = Field(
        description="Requested tools that survived trust-tier intersection"
    )
    final_paths: list[PathPattern] = Field(
        description="Paths that survived denied-path filtering"
    )
    trust_tier: TrustTier = Field(description="The trust tier that was applied")
    require_human_approval: bool = Field(
        description="Whether human approval is required before issuance"
    )
    denial_reason: str | None = Field(
        default=None,
        max_length=500,
        description="Explanation of why the request was denied",
    )
    intent: str = Field(
        min_length=1,
        max_length=500,
        description="Pass-through of the compiler's extracted intent",
    )
    source_hash: str = Field(
        pattern=SHA256_PATTERN,
        description="SHA-256 hash of the original raw text",
    )
    compiler_version: str = Field(
        pattern=SEMVER_PATTERN,
        description="Pass-through of the compiler version",
    )
    allowed_hosts: list[str] = Field(
        default_factory=list,
        description="Allowed hostnames for network requests",
    )


class SignedCapsule(FrozenModel):
    """A policy-approved task scope and its cryptographic signature."""

    capsule_id: str = Field(
        pattern=UUID_PATTERN,
        description="Unique identifier for this capsule",
    )
    intent: str = Field(
        min_length=1,
        max_length=500,
        description="Task summary from the compiler",
    )
    allowed_tools: list[KnownTools] = Field(
        description="Sorted tools permitted for this task"
    )
    target_paths: list[PathPattern] = Field(
        description="Sorted file paths or glob patterns permitted for this task"
    )
    trust_tier: TrustTier = Field(
        description="Trust tier under which this capsule was issued"
    )
    expiry: str = Field(
        pattern=UTC_TIMESTAMP_PATTERN,
        description="When this capsule expires",
    )
    source_hash: str = Field(
        pattern=SHA256_PATTERN,
        description="SHA-256 hash of the source text that generated this capsule",
    )
    compiler_version: str = Field(
        pattern=SEMVER_PATTERN,
        description="Version of the compiler that produced the intent",
    )
    signature: dict[str, Any] | str = Field(
        description="Sigstore bundle JSON or base64-encoded Ed25519 signature"
    )
    allowed_hosts: list[str] = Field(
        default_factory=list,
        description="Sorted hostnames permitted for network requests",
    )

    @field_validator("expiry")
    @classmethod
    def expiry_must_be_utc(cls, value: str) -> str:
        return _validate_utc_timestamp(value)

    @model_validator(mode="after")
    def scopes_must_be_sorted(self) -> SignedCapsule:
        if self.allowed_tools != sorted(self.allowed_tools, key=lambda tool: tool.value):
            raise ValueError("allowed_tools must be sorted")
        if self.target_paths != sorted(self.target_paths):
            raise ValueError("target_paths must be sorted")
        if self.allowed_hosts != sorted(self.allowed_hosts):
            raise ValueError("allowed_hosts must be sorted")
        return self

    def is_expired(self, *, now: datetime | None = None) -> bool:
        """Return whether this capsule's expiry time has passed."""

        reference = now or datetime.now(timezone.utc)
        parsed_expiry = datetime.fromisoformat(self.expiry.replace("Z", "+00:00"))
        return parsed_expiry <= reference


class AuditEvent(FrozenModel):
    """An append-only record of a governance or enforcement event."""

    timestamp: str = Field(
        default_factory=_utc_now,
        pattern=UTC_TIMESTAMP_PATTERN,
        description="When the event occurred",
    )
    capsule_id: str | None = Field(
        default=None,
        pattern=UUID_PATTERN,
        description="The capsule this event relates to, or null for pre-issuance denials",
    )
    event_type: AuditEventType = Field(description="Category of the event")
    trust_tier: TrustTier | None = Field(
        default=None,
        description="Trust tier at the time of the event",
    )
    tool_name: str | None = Field(
        default=None,
        description="The tool involved, if applicable",
    )
    target_path: str | None = Field(
        default=None,
        description="The file path involved, if applicable",
    )
    detail: str | None = Field(
        default=None,
        max_length=1_000,
        description="Additional context such as a denial or block reason",
    )

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_utc(cls, value: str) -> str:
        return _validate_utc_timestamp(value)


class CapsuleSummary(FrozenModel):
    """A compact issued-capsule record retained in a session history."""

    capsule_id: str = Field(
        pattern=UUID_PATTERN,
        description="Reference to the issued capsule",
    )
    issued_at: str = Field(
        pattern=UTC_TIMESTAMP_PATTERN,
        description="When this capsule was issued",
    )
    trust_tier: TrustTier = Field(description="Trust tier of the capsule")
    tools_count: int = Field(ge=0, description="Number of tools in the capsule")
    paths_count: int = Field(ge=0, description="Number of paths in the capsule")

    @field_validator("issued_at")
    @classmethod
    def issued_at_must_be_utc(cls, value: str) -> str:
        return _validate_utc_timestamp(value)


class SessionHistory(BaseModel):
    """Mutable per-thread state used by session-aware policy rules."""

    model_config = ConfigDict(frozen=False, extra="forbid")

    thread_id: str = Field(
        pattern=THREAD_ID_PATTERN,
        description="Issue or pull request identifier, for example owner/repo#42",
    )
    recent_capsules: list[CapsuleSummary] = Field(
        default_factory=list,
        description="Capsules issued in this thread within the last 60 minutes",
    )
    consecutive_high_scope: int = Field(
        default=0,
        ge=0,
        description="Count of consecutive capsules requesting more than two tools or ten paths",
    )
    cumulative_unique_tools: int = Field(
        default=0,
        ge=0,
        description="Total unique tools requested across this thread",
    )
    last_human_approval_at: str | None = Field(
        default=None,
        pattern=UTC_TIMESTAMP_PATTERN,
        description="When a human last approved a capsule in this thread",
    )

    @field_validator("last_human_approval_at")
    @classmethod
    def approval_time_must_be_utc(cls, value: str | None) -> str | None:
        return _validate_utc_timestamp(value) if value is not None else value


class ToolCallParams(FrozenModel):
    """The tool name and arbitrary arguments embedded in an MCP call."""

    name: str = Field(
        min_length=1,
        description="Name of the tool being invoked",
    )
    arguments: dict[str, Any] = Field(
        description="Arbitrary tool-specific key-value arguments"
    )


class ToolCallRequest(FrozenModel):
    """MCP JSON-RPC tools/call request received by the enforcement proxy."""

    jsonrpc: Literal["2.0"] = Field(description="JSON-RPC version")
    id: str | int = Field(description="JSON-RPC request ID")
    method: Literal["tools/call"] = Field(description="MCP method being called")
    params: ToolCallParams = Field(description="Tool name and arguments")


class ToolCallDecision(FrozenModel):
    """The enforcement proxy's decision for one intercepted tool call."""

    capsule_id: str = Field(
        pattern=UUID_PATTERN,
        description="The capsule this decision was evaluated against",
    )
    tool_name: str = Field(min_length=1, description="The tool that was requested")
    allowed: bool = Field(description="Whether the call was permitted")
    block_reason: str | None = Field(
        default=None,
        description="Why the call was blocked",
    )
    matched_paths: list[str] = Field(
        default_factory=list,
        description="Path arguments extracted and checked from the request",
    )


class GovernancePipelineInput(FrozenModel):
    """Inputs assembled by webhook ingestion before policy evaluation."""

    event: WebhookEvent = Field(description="Parsed and validated webhook event")
    trust_tier_result: TrustTierResult = Field(
        description="Resolved trust tier for the event author"
    )
    compiler_output: CompilerOutput = Field(
        description="LLM compiler's structured extraction"
    )
    session_history: SessionHistory = Field(description="Current thread session state")


class GovernancePipelineOutput(FrozenModel):
    """The client-facing outcome of processing a GitHub webhook."""

    capsule_id: str | None = Field(
        default=None,
        pattern=UUID_PATTERN,
        description="Issued capsule ID, or null if no capsule was issued",
    )
    status: Literal["issued", "denied", "pending_approval"] = Field(
        description="Outcome of the governance pipeline"
    )
    denial_reason: str | None = Field(
        default=None,
        max_length=500,
        description="Why the pipeline denied the request",
    )
    capsule: SignedCapsule | None = Field(
        default=None,
        description="The full signed capsule when the status is issued",
    )
