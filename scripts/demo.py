"""Run all demo scenarios with readable sectioned output."""

from __future__ import annotations

from scripts.demo_scenario_a import run_scenario as run_scenario_a
from scripts.demo_scenario_b import run_scenario as run_scenario_b
from scripts.demo_scenario_c import run_scenario as run_scenario_c
from scripts.demo_scenario_d import run_scenario as run_scenario_d


RESET = "\033[0m"
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"


def _print_header(title: str, color: str) -> None:
    print(f"{color}{'=' * 72}{RESET}")
    print(f"{color}{title}{RESET}")
    print(f"{color}{'=' * 72}{RESET}")


def main() -> None:
    _print_header("Signed Task Capsules Demo Runner", BLUE)
    print(
        "PRECONDITION: Bob must run in the 'stc-governed' custom mode "
        "(.bob/custom_modes.yaml).\n"
        "That mode disables Bob's native edit/write/command tools so 100% of "
        "actions route\nthrough the capsule enforcement proxy. Without it, native "
        "tools bypass MCP."
    )

    _print_header("Scenario A - Direct Injection Attack", GREEN)
    result_a = run_scenario_a()
    print(f"Requested paths: {result_a['compiler_target_paths']}")
    print(f"Allowed paths:   {result_a['final_target_paths']}")
    print(f".env blocked by enforcement: {result_a['blocked_env_read']}")

    _print_header("Scenario B - Compiler-Fooling Attack", GREEN)
    result_b = run_scenario_b()
    print(f"Compiler paths: {result_b['compiler_target_paths']}")
    print(f"Policy paths:   {result_b['final_target_paths']}")

    _print_header("Scenario C - Slow Escalation Attack", YELLOW)
    result_c = run_scenario_c()
    print(f"Capsule statuses: {result_c['statuses']}")
    print(f"Audit events: {result_c['audit_event_types']}")

    _print_header("Scenario D - Governed MCP Runtime", GREEN)
    result_d = run_scenario_d()
    print(f"Webhook status: {result_d['status']}")
    print(f"Capsule retrievable by MCP server: {result_d['capsule_loaded_from_store']}")
    print(f"Governed read executed in scope: {result_d['governed_read_ok']}")
    print(f"Governed write executed in scope: {result_d['governed_write_ok']}")
    print(f"Out-of-scope .env read blocked: {result_d['blocked_env_read']}")

    _print_header("Demo Complete", BLUE)


if __name__ == "__main__":
    main()
