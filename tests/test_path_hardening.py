import uuid
import pytest
from app.enforcement.path_utils import match_pattern
from app.governance.policy import PolicyEngine

def test_path_matcher():
    # Test cases from Section 2.1
    cases = [
        ("secrets/key.txt", "**/secrets/**", True),
        ("src/secrets/key.txt", "**/secrets/**", True),
        ("a/b/secrets/key.txt", "**/secrets/**", True),
        (".env", "**/.env", True),
        ("src/.env", "**/.env", True),
        ("src/main.py", "src/**/*.py", True),
        ("src/utils/helper.py", "src/**/*.py", True),
        ("src/secretsafe/key.txt", "**/secrets/**", False),
        ("src/secret/key.txt", "**/secrets/**", False),
        ("src/main.txt", "src/**/*.py", False),
    ]
    for path, pattern, expected in cases:
        assert match_pattern(path, pattern) == expected, f"Failed: {path} vs {pattern}"

def test_validate_target_path_negative():
    # Test cases from Section 2.7
    cases = [
        ("/etc/passwd", False),
        ("../secret.txt", False),
        ("../../secret.txt", False),
        ("src/../../secret.txt", False),
        ("foo/../secret.txt", False),
        ("C:\\Windows\\System32", False),
        ("C:/Windows/System32", False),
        ("\\\\server\\share", False),
        ("src/main.py\0.txt", False),
    ]
    for path, expected in cases:
        assert PolicyEngine._validate_target_path(path) == expected, f"Failed validation: {path}"

from app.enforcement.scope_checker import path_allowed

def test_integration_path_hardening():
    # Valid paths according to policy
    assert PolicyEngine._validate_target_path("src/main.py") is True
    # Should be allowed by valid pattern
    assert path_allowed("src/main.py", ["src/**/*.py"]) is True
    
    # Malicious paths according to policy
    assert PolicyEngine._validate_target_path("../secret.txt") is False
    # Even if pattern allows it, path_allowed will reject malicious patterns by canonicalizing
    assert path_allowed("../secret.txt", ["**/*"]) is False
