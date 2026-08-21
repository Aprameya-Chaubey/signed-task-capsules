"""
Runtime policy engine — mirrors the declarative specification in policies/capsule.rego.

capsule.rego is the canonical, auditable policy specification.
This Python implementation is the runtime engine that executes the same logic.
Any policy change MUST be reflected in both files.

The Python implementation exists because:
- No production-ready OPA-in-Python runtime exists (opa-wasmtime is unmaintained)
- Pure Python is easier to unit-test under pytest
- The logic is simple set intersection, not complex rule chaining
"""

from __future__ import annotations

from app.enforcement.path_utils import match_pattern
import logging
import re
from typing import ClassVar, TypedDict

from app.models import (
    CompilerOutput,
    KnownTools,
    PolicyDecision,
    SessionHistory,
    TrustTier,
)


logger = logging.getLogger(__name__)


class TierCaps(TypedDict):
    """Hard scope limits that cannot be raised by compiler output."""

    tools: frozenset[KnownTools]
    denied_paths: frozenset[str]
    max_files: int
    network: bool
    secrets: bool


class PolicyEngine:
    """Intersect untrusted compiler scope with immutable, tier-specific limits."""

    SENSITIVE_PATH_PATTERNS: ClassVar[frozenset[str]] = frozenset(
        {"**/.env", "**/.env.*", "**/secrets/**", "**/*.key", "**/*.pem"}
    )

    TIER_CAPS: ClassVar[dict[TrustTier, TierCaps]] = {
        TrustTier.EXTERNAL: {
            "tools": frozenset({KnownTools.READ_FILE}),
            "denied_paths": frozenset(
                {"**/.env", "**/.env.*", "**/secrets/**", "**/.git/**", "**/*.key", "**/*.pem"}
            ),
            "max_files": 5,
            "network": False,
            "secrets": False,
        },
        TrustTier.CONTRIBUTOR: {
            "tools": frozenset(
                {KnownTools.READ_FILE, KnownTools.WRITE_FILE, KnownTools.RUN_TESTS}
            ),
            "denied_paths": frozenset(
                {"**/.env", "**/.env.*", "**/secrets/**", "**/.git/**", "**/*.key", "**/*.pem"}
            ),
            "max_files": 50,
            "network": False,
            "secrets": False,
        },
        TrustTier.MAINTAINER: {
            "tools": frozenset(KnownTools),
            "denied_paths": frozenset(),
            "max_files": -1,
            "network": True,
            "secrets": True,
        },
    }

    def evaluate(
        self,
        compiler_output: CompilerOutput,
        trust_tier: TrustTier,
        session_history: SessionHistory,
        source_hash: str,
    ) -> PolicyDecision:
        """Apply fixed tier caps and basic session escalation to one request."""

        caps = self.TIER_CAPS[trust_tier]
        final_tools = [
            tool for tool in compiler_output.requested_tools if tool in caps["tools"]
        ]

        allowed_paths = [
            path
            for path in compiler_output.target_paths
            if not self._path_matches_denied(path, caps["denied_paths"])
        ]

        final_paths: list[str] = []
        for path in allowed_paths:
            if self._validate_target_path(path):
                final_paths.append(path)
            else:
                logger.info(
                    "Removed overly broad target path without a directory anchor: %s",
                    path,
                )

        final_hosts: list[str] = []
        if KnownTools.NET_REQUEST in final_tools:
            hosts_set = set()
            for h in compiler_output.allowed_hosts:
                h_clean = h.strip().lower()
                if not h_clean or "://" in h_clean or "/" in h_clean or "@" in h_clean or ":" in h_clean:
                    continue
                hosts_set.add(h_clean)
            final_hosts = sorted(list(hosts_set))

        all_paths_overly_broad = bool(allowed_paths) and not final_paths

        max_files = caps["max_files"]
        file_count_within_limit = max_files == -1 or len(final_paths) <= max_files
        require_human_approval = self._requires_human_approval(
            final_tools, final_paths, trust_tier, session_history
        )

        denial_reason: str | None = None
        if not final_tools:
            denial_reason = (
                f"No requested tools are permitted for the {trust_tier.value} trust tier."
            )
        elif all_paths_overly_broad:
            denial_reason = (
                "All target paths are overly broad (must include at least one "
                "directory anchor)."
            )
        elif not file_count_within_limit:
            denial_reason = (
                f"The {trust_tier.value} trust tier permits at most {max_files} target "
                f"paths; {len(final_paths)} permitted paths were requested."
            )

        return PolicyDecision(
            allow=denial_reason is None,
            final_tools=final_tools,
            final_paths=final_paths,
            trust_tier=trust_tier,
            require_human_approval=require_human_approval,
            denial_reason=denial_reason,
            intent=compiler_output.intent,
            source_hash=source_hash,
            compiler_version=compiler_output.compiler_version,
            allowed_hosts=final_hosts,
        )

    @staticmethod
    def _validate_target_path(pattern: str) -> bool:
        """Reject broad/malicious patterns."""
        if "\0" in pattern:
            return False
        
        normalized = pattern.replace("\\", "/").strip()
        
        # Absolute paths (POSIX/Windows/UNC)
        if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized) or normalized.startswith("//"):
            return False
            
        # Traversal/Injection
        if "/../" in f"/{normalized}/" or normalized == ".." or normalized.startswith("../"):
            return False

        # Anchor check: Require at least one non-wildcard path segment before any glob wildcard.
        parts = normalized.split("/")
        for part in parts:
            if "*" in part or "?" in part:
                return False
            if part and part != ".":
                return True
        return False

    @staticmethod
    def _path_matches_denied(path: str, denied_patterns: set[str] | frozenset[str]) -> bool:
        """Return whether a path matches any denied glob, including at repo root."""

        normalized_path = path.replace("\\", "/").removeprefix("./")
        return any(
            match_pattern(normalized_path, pattern)
            for pattern in denied_patterns
        )

    @classmethod
    def _requires_human_approval(
        cls,
        final_tools: list[KnownTools],
        final_paths: list[str],
        trust_tier: TrustTier,
        session_history: SessionHistory,
    ) -> bool:
        """Apply the stage-one approval triggers without changing a policy denial."""

        maintainer_sensitive_tool = trust_tier is TrustTier.MAINTAINER and bool(
            {KnownTools.NET_REQUEST, KnownTools.EXECUTE_CMD}.intersection(final_tools)
        )
        if maintainer_sensitive_tool:
            return True

        # Maintainer access to secrets/keys requires the same human gate as network tools.
        if trust_tier is TrustTier.MAINTAINER:
            for path in final_paths:
                normalized = path.replace("\\", "/").removeprefix("./")
                for pattern in cls.SENSITIVE_PATH_PATTERNS:
                    if match_pattern(normalized, pattern):
                        return True

        return (
            len(session_history.recent_capsules) >= 3
            or session_history.consecutive_high_scope >= 1
            or session_history.cumulative_unique_tools > 4
        )
