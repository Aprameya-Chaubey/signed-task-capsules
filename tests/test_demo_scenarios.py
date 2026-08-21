"""Automated assertions for final demo scenarios A, B, C, and D."""

from scripts.demo_scenario_a import run_scenario as run_scenario_a
from scripts.demo_scenario_b import run_scenario as run_scenario_b
from scripts.demo_scenario_c import run_scenario as run_scenario_c
from scripts.demo_scenario_d import run_scenario as run_scenario_d


def test_demo_scenario_a_removes_env_from_final_capsule_scope() -> None:
    result = run_scenario_a()

    assert ".env" in result["compiler_target_paths"]
    assert ".env" not in result["final_target_paths"]
    assert result["status"] == "issued"


def test_demo_scenario_b_compiler_can_be_fooled_but_policy_filters_env() -> None:
    result = run_scenario_b()

    assert ".env" in result["compiler_target_paths"]
    assert ".env" not in result["final_target_paths"]
    assert result["status"] == "issued"


def test_demo_scenario_c_requires_approval_on_fourth_capsule() -> None:
    result = run_scenario_c()

    assert result["statuses"][0:3] == ["issued", "issued", "issued"]
    assert result["statuses"][3] == "pending_approval"


def test_demo_scenario_d_governed_runtime_executes_in_scope_and_blocks_out_of_scope() -> None:
    result = run_scenario_d()

    assert result["status"] == "issued"
    assert result["capsule_loaded_from_store"] is True
    assert result["governed_read_ok"] is True
    assert result["governed_write_ok"] is True
    assert result["patch_written"] is True
    assert result["blocked_env_read"] is True
