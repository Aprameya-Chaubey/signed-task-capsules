"""Scenario C demo: slow escalation across one thread triggers approval hold."""

from __future__ import annotations

import json
from typing import Any

from fastapi.testclient import TestClient

from app.models import CompilerOutput, GovernancePipelineOutput, KnownTools
from scripts.demo_common import build_demo_app, issue_payload, post_webhook


SCENARIO_INPUTS = [
    "Read README.md",
    "Read src/main.py",
    "Read tests/test_main.py",
    "Read src/config.py",
]


def run_scenario() -> dict[str, Any]:
    compiler_outputs = [
        CompilerOutput(
            intent=text,
            requested_tools=[KnownTools.READ_FILE],
            target_paths=[path],
            compiler_model="demo-compiler",
            compiler_version="1.0.0",
        )
        for text, path in zip(
            SCENARIO_INPUTS,
            ["README.md", "src/main.py", "tests/test_main.py", "src/config.py"],
            strict=True,
        )
    ]

    context = build_demo_app(compiler_outputs)
    statuses: list[str] = []
    issued_capsule_ids: list[str] = []

    with TestClient(context.app) as client:
        for body in SCENARIO_INPUTS:
            payload = issue_payload(body, issue_number=303)
            response = post_webhook(
                client,
                payload=payload,
                event_type="issues",
                secret=context.secret,
            )
            parsed = GovernancePipelineOutput.model_validate(response.json())
            statuses.append(parsed.status)
            if parsed.capsule_id is not None:
                issued_capsule_ids.append(parsed.capsule_id)

    return {
        "scenario": "C",
        "statuses": statuses,
        "issued_capsule_ids": issued_capsule_ids,
        "audit_event_types": [event.event_type.value for event in context.audit_logger.events],
    }


def main() -> None:
    result = run_scenario()
    print("Scenario C: Slow Escalation Attack")
    print(f"Statuses: {result['statuses']}")
    print(f"Audit timeline: {result['audit_event_types']}")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
