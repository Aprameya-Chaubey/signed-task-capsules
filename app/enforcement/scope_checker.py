"""Path extraction and scope-matching helpers for MCP enforcement."""

from __future__ import annotations

from app.enforcement.path_utils import match_pattern
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
    candidate = value.strip()
    if not candidate:
        return False
    if candidate.startswith(("http://", "https://")):
        return False
    if "/" in candidate or "\\" in candidate:
        return True
    if candidate.lower() in KNOWN_EXTENSIONLESS:
        return True
    # Dotfiles are almost always config or secrets.
    if candidate.startswith("."):
        return True
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
    if " " in candidate:
        return False
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


def canonicalize_path(path: str) -> str:
    """Normalize path separators and collapse dot segments safely."""

    normalized = path.replace("\\", "/").strip()
    if not normalized:
        return "."

    is_absolute = normalized.startswith("/")
    parts: list[str] = []

    for raw_part in normalized.split("/"):
        part = raw_part.strip()
        if not part or part == ".":
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)

    canonical = "/".join(parts)
    if is_absolute:
        return f"/{canonical}" if canonical else "/"
    return canonical or "."


def path_allowed(canonical_path: str, allowed_patterns: list[str]) -> bool:
    """Return whether a canonical path matches any allowed glob pattern."""

    normalized = canonical_path.replace("\\", "/")
    relative = normalized.lstrip("/")

    for pattern in allowed_patterns:
        if match_pattern(canonical_path, pattern):
            return True
    return False
