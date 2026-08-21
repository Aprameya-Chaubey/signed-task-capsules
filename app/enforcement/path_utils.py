from __future__ import annotations
import fnmatch

def match_pattern(path: str, pattern: str) -> bool:
    """
    Segment-aware glob matcher.
    '**' matches zero or more complete segments.
    """
    path_parts = []
    for part in path.replace("\\", "/").split("/"):
        if part == "..":
            if not path_parts: # Escape attempt
                return False
            path_parts.pop()
        elif part and part != ".":
            path_parts.append(part)
            
    pattern_parts = pattern.replace("\\", "/").split("/")
    
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
