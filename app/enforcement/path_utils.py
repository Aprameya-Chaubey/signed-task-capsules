from __future__ import annotations
import fnmatch

def canonicalize_path(path: str) -> str:
    """Normalize path separators and collapse dot segments safely."""
    normalized = path.replace("\\", "/").strip()
    if not normalized:
        return "."

    is_absolute = normalized.startswith("/")
    parts = []

    for raw_part in normalized.split("/"):
        part = raw_part.strip()
        if not part or part == ".":
            continue
        if part == "..":
            if parts and parts[-1] != "..":
                parts.pop()
            else:
                parts.append("..")
            continue
        parts.append(part)

    canonical = "/".join(parts)
    if is_absolute:
        return f"/{canonical}" if canonical else "/"
    return canonical or "."

def _normalize_parts(value: str) -> list[str]:
    """Normalize a path or pattern into segments, skipping empty and '.' parts."""
    canonical = canonicalize_path(value)
    if canonical in (".", "/", ""):
        return []
    return [p for p in canonical.split("/") if p]

def match_pattern(path: str, pattern: str) -> bool:
    """
    Segment-aware glob matcher.
    '**' matches zero or more complete segments.
    Both path and pattern are normalized consistently (backslashes, '.', empty segments).
    """
    # If path escaped root, it's immediately invalid
    if canonicalize_path(path) == "":
        return False
        
    path_parts = _normalize_parts(path)
    pattern_parts = _normalize_parts(pattern)
    
    # Use memoized matching to prevent exponential backtracking (ReDoS).
    memo: dict[tuple[int, int], bool] = {}
    return _match_memoized(tuple(path_parts), tuple(pattern_parts), 0, 0, memo)




def _match_memoized(
    path_parts: tuple[str, ...],
    pattern_parts: tuple[str, ...],
    pi: int,
    qi: int,
    memo: dict[tuple[int, int], bool],
) -> bool:
    """Memoized segment-level glob matching.

    ``pi`` and ``qi`` are indexes into *path_parts* and *pattern_parts*
    respectively.  The memo dictionary caches ``(pi, qi)`` states so that
    patterns with multiple ``**`` wildcards cannot trigger exponential
    backtracking.
    """
    key = (pi, qi)
    if key in memo:
        return memo[key]

    result = _match_inner(path_parts, pattern_parts, pi, qi, memo)
    memo[key] = result
    return result


def _match_inner(
    path_parts: tuple[str, ...],
    pattern_parts: tuple[str, ...],
    pi: int,
    qi: int,
    memo: dict[tuple[int, int], bool],
) -> bool:
    if qi == len(pattern_parts):
        return pi == len(path_parts)

    if pattern_parts[qi] == "**":
        # Match zero segments
        if _match_memoized(path_parts, pattern_parts, pi, qi + 1, memo):
            return True
        # Match one or more segments
        for i in range(pi, len(path_parts)):
            if _match_memoized(path_parts, pattern_parts, i + 1, qi + 1, memo):
                return True
        return False

    if pi == len(path_parts):
        # Only trailing ** can match empty path
        return all(p == "**" for p in pattern_parts[qi:])

    if not fnmatch.fnmatch(path_parts[pi], pattern_parts[qi]):
        return False

    return _match_memoized(path_parts, pattern_parts, pi + 1, qi + 1, memo)
