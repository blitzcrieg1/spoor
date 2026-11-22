"""Fixture-check the lab's small Sigma subset without a Sigma backend.

This evaluator intentionally supports only the simple conjunctions and field
modifiers used by the lab-specific process rule. It is not a general Sigma
engine; use the Sigma CLI/backend for production rule compilation.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
RULE_PATH = ROOT / "detections" / "sigma" / "artex_agent_shell_spawns_attack_tool.yml"
FIXTURE_PATH = ROOT / "detections" / "sigma" / "tests" / "fixtures" / "agent_shell_spawns_attack_tool.jsonl"


def field_value(event: dict, field: str):
    value = event
    for part in field.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def matches_selector(event: dict, selector: dict) -> bool:
    for expression, expected in selector.items():
        if "|" in expression:
            field, modifier = expression.rsplit("|", 1)
        else:
            field, modifier = expression, "exact"
        actual = field_value(event, field)
        values = expected if isinstance(expected, list) else [expected]
        if modifier == "exact":
            matched = any(actual == candidate for candidate in values)
        elif modifier == "contains":
            matched = isinstance(actual, str) and any(str(candidate) in actual for candidate in values)
        elif modifier == "re":
            matched = isinstance(actual, str) and any(re.search(str(candidate), actual) for candidate in values)
        else:
            raise ValueError(f"unsupported Sigma modifier: {modifier}")
        if not matched:
            return False
    return True


def matches_rule(event: dict, detection: dict) -> bool:
    selections = {
        name: matches_selector(event, selector)
        for name, selector in detection.items()
        if name != "condition"
    }
    names = [name.strip() for name in detection["condition"].split(" and ")]
    if not names or any(name not in selections for name in names):
        raise ValueError("fixture evaluator only supports known selector conjunctions")
    return all(selections[name] for name in names)


def main() -> int:
    rule = yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))
    detection = rule["detection"]
    checked = 0
    for line_no, line in enumerate(FIXTURE_PATH.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        fixture = json.loads(line)
        actual = matches_rule(fixture["event"], detection)
        expected = fixture["expected"]
        result = "PASS" if actual == expected else "FAIL"
        print(f"{fixture['name']}: expected={expected} matched={actual} {result}")
        checked += 1
        if actual != expected:
            return 1
    if checked == 0:
        raise RuntimeError("no Sigma fixtures were evaluated")
    print(f"Sigma process fixtures passed: {checked}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
