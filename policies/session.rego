package signed_task_capsules.session

approval_required if {
    count(input.recent_capsules) >= 3
}

approval_required if {
    input.consecutive_high_scope >= 1
}

approval_required if {
    input.cumulative_unique_tools > 4
}
