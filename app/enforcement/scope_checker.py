"""Path extraction and scope-matching helpers for MCP enforcement."""

from __future__ import annotations

from app.enforcement.path_utils import match_pattern, canonicalize_path
import re
from typing import Any


_COMMON_FILE_EXTENSION = re.compile(r"\.[A-Za-z0-9]{1,8}$")

# Extensionless filenames that are almost always real files and must be
# visible to path enforcement even without a "/" or extension.
KNOWN_EXTENSIONLESS = {
    "makefile", "dockerfile", "license", "licence", "readme",
    "rakefile", "gemfile", "procfile", "vagrantfile",
    ".gitignore", ".dockerignore", ".gitattributes", ".editorconfig",
    ".env", ".htaccess", ".npmrc", ".nvmrc", ".bobignore",
}

_NON_PATH_LITERALS = {"true", "false", "null", "none", "nan"}


def _looks_like_path(value: str) -> bool:
    # If the value contains newlines or other control characters, strip them
    # before evaluation.  This closes the newline-injection bypass where an
    # attacker appends "\n" to a path (e.g. "/etc/passwd\n") to make the proxy
    # skip the allowlist check.
    #
    # However, multiline strings (e.g. file content like "# comment\ncode")
    # should NOT be extracted as paths.  Heuristic: if the original contained
    # a newline AND the stripped result has no path separator, treat the
    # original as non-path content (likely code/text).
    had_newline = "\n" in value
    candidate = re.sub(r"[\x00-\x1f\x7f]", "", value).strip()
    if not candidate:
        return False
    if candidate.startswith(("http://", "https://")):
        return False
    if "/" in candidate or "\\" in candidate:
        return True
    if candidate.lower() in KNOWN_EXTENSIONLESS:
        return True
    # Dotfiles are almost always config or secrets; extract them even when a
    # newline was appended (e.g. ".env\n" must still reach the allowlist check).
    if candidate.startswith("."):
        return True
    # If the original had embedded newlines but the stripped result has no
    # path-separator or obvious file marker, it's likely multi-line text (code,
    # prose) rather than a path — skip it to avoid false positives.
    if had_newline and "/" not in candidate and "\\" not in candidate:
        return False
    if _COMMON_FILE_EXTENSION.search(candidate):
        return True
    # Flip the default: treat a short bare token as a possible path unless it
    # is obviously a number, boolean/null, or JSON fragment.
    if len(candidate) >= 256:
        return False
    if candidate.lower() in _NON_PATH_LITERALS:
        return False
    if candidate.startswith(("{", "[")) and candidate.endswith(("}", "]")):
        return False
    try:
        float(candidate)
        return False
    except ValueError:
        pass
    return True


def extract_paths(
    arguments: dict[str, Any], _depth: int = 0, max_depth: int = 10
) -> list[str]:
    """Walk nested argument values and return path-like strings."""

    found_paths: list[str] = []
    seen: set[str] = set()

    def walk(value: Any, depth: int) -> None:
        if depth >= max_depth:
            return

        if isinstance(value, dict):
            for nested in value.values():
                walk(nested, depth + 1)
            return

        if isinstance(value, (list, tuple, set)):
            for nested in value:
                walk(nested, depth + 1)
            return

        if isinstance(value, str) and _looks_like_path(value):
            if value not in seen:
                seen.add(value)
                found_paths.append(value)

    walk(arguments, _depth)
    return found_paths


def path_allowed(canonical_path: str, allowed_patterns: list[str]) -> bool:
    """Return whether a canonical path matches any allowed glob pattern."""
    
    if canonical_path == "" or ".." in canonical_path.split("/"):
        return False

    for pattern in allowed_patterns:
        if match_pattern(canonical_path, pattern):
            return True
    return False
