package signed_task_capsules.capsule

# Canonical policy specification. The runtime engine in app/governance/policy.py
# mirrors this logic. Any policy change MUST be reflected in both files.

default allow := false

tier_caps := {
    "external": {
        "tools": {"read_file"},
        "denied_paths": {"**/.env", "**/.env.*", "**/secrets/**", "**/.git/**", "**/*.key", "**/*.pem"},
        "max_files": 5,
        "network": false,
        "secrets": false,
    },
    "contributor": {
        "tools": {"read_file", "write_file", "run_tests"},
        "denied_paths": {"**/.env", "**/.env.*", "**/secrets/**", "**/.git/**", "**/*.key", "**/*.pem"},
        "max_files": 50,
        "network": false,
        "secrets": false,
    },
    "maintainer": {
        "tools": {"read_file", "write_file", "run_tests", "execute_cmd", "net_request"},
        "denied_paths": {},
        "max_files": -1,
        "network": true,
        "secrets": true,
    },
}

# Maintainer access to these paths requires the same human gate as network tools.
sensitive_path_patterns := {"**/.env", "**/.env.*", "**/secrets/**", "**/*.key", "**/*.pem"}

final_tools contains tool if {
    tool := input.compiler_output.requested_tools[_]
    tier_caps[input.trust_tier].tools[tool]
}

denied_path contains path if {
    path := input.compiler_output.target_paths[_]
    pattern := tier_caps[input.trust_tier].denied_paths[_]
    normalized_path := trim_prefix(replace(path, "\\", "/"), "./")
    glob.match(pattern, ["/"], normalized_path)
}

denied_path contains path if {
    path := input.compiler_output.target_paths[_]
    pattern := tier_caps[input.trust_tier].denied_paths[_]
    normalized_path := trim_prefix(replace(path, "\\", "/"), "./")
    glob.match(pattern, ["/"], sprintf("./%s", [normalized_path]))
}

# A path is anchored if at least one segment is a literal (no glob wildcard)
# and is not just "." (which is overly broad).
# "src/**/*.py" is anchored (src/); "**/*.py" and "*.py" and "." are not.
anchored_path(path) if {
    segment := split(replace(path, "\\", "/"), "/")[_]
    segment != ""
    segment != "."
    not contains(segment, "*")
    not contains(segment, "?")
}

# Reject paths containing null bytes.
invalid_path(path) if {
    contains(path, "\u0000")
}

# Reject absolute paths (POSIX, Windows drive-letter, UNC).
invalid_path(path) if {
    normalized := replace(path, "\\", "/")
    startswith(normalized, "/")
}

invalid_path(path) if {
    re_match(`^[A-Za-z]:`, path)
}

invalid_path(path) if {
    normalized := replace(path, "\\", "/")
    startswith(normalized, "//")
}

# Reject directory traversal.
invalid_path(path) if {
    normalized := replace(path, "\\", "/")
    contains(sprintf("/%s/", [normalized]), "/../")
}

invalid_path(path) if {
    path == ".."
}

invalid_path(path) if {
    normalized := replace(path, "\\", "/")
    startswith(normalized, "../")
}

allowed_path contains path if {
    path := input.compiler_output.target_paths[_]
    not denied_path[path]
    not invalid_path(path)
}

final_paths contains path if {
    allowed_path[path]
    anchored_path(path)
}

all_paths_overly_broad if {
    count(allowed_path) > 0
    count(final_paths) == 0
}

within_file_limit if {
    tier_caps[input.trust_tier].max_files == -1
}

within_file_limit if {
    count(final_paths) <= tier_caps[input.trust_tier].max_files
}

maintainer_sensitive_tool if {
    input.trust_tier == "maintainer"
    final_tools["net_request"]
}

maintainer_sensitive_tool if {
    input.trust_tier == "maintainer"
    final_tools["execute_cmd"]
}

maintainer_sensitive_path if {
    input.trust_tier == "maintainer"
    path := final_paths[_]
    pattern := sensitive_path_patterns[_]
    normalized_path := trim_prefix(replace(path, "\\", "/"), "./")
    glob.match(pattern, ["/"], normalized_path)
}

require_human_approval if {
    maintainer_sensitive_tool
}

require_human_approval if {
    maintainer_sensitive_path
}

require_human_approval if {
    count(input.session_history.recent_capsules) >= 3
}

require_human_approval if {
    input.session_history.consecutive_high_scope >= 1
}

require_human_approval if {
    input.session_history.cumulative_unique_tools > 4
}

allow if {
    count(final_tools) > 0
    not all_paths_overly_broad
    within_file_limit
}
