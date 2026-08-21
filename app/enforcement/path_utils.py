from __future__ import annotations
import fnmatch

def _normalize_parts(value: str) -> list[str]:
    """Normalize a path or pattern into segments, skipping empty and '.' parts."""
    parts = []
    for part in value.replace("\\", "/").split("/"):
        if part == "..":
            if not parts:  # Escape attempt
                return []
            parts.pop()
        elif part and part != ".":
            parts.append(part)
    return parts

def match_pattern(path: str, pattern: str) -> bool:
    """
    Segment-aware glob matcher.
    '**' matches zero or more complete segments.
    Both path and pattern are normalized consistently (backslashes, '.', empty segments).
    """
    path_parts = _normalize_parts(path)
    pattern_parts = _normalize_parts(pattern)
    
    return _match_recursive(path_parts, pattern_parts)

def _match_recursive(path_parts: list[str], pattern_parts: list[str]) -> bool:
    if not pattern_parts:
        return not path_parts
    
    if pattern_parts[0] == "**":
        # Match zero segments
        if _match_recursive(path_parts, pattern_parts[1:]):
            return True
        # Match one or more segments
        for i in range(len(path_parts)):
            if _match_recursive(path_parts[i+1:], pattern_parts[1:]):
                return True
        return False

    if not path_parts:
        return False
        
    # Standard segment match (supports ? and *)
    if fnmatch.fnmatch(path_parts[0], pattern_parts[0]):
        return _match_recursive(path_parts[1:], pattern_parts[1:])
        
    return False
