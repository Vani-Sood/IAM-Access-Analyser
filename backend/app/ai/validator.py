from __future__ import annotations

import json


def _normalize_to_list(action: str | list[str]) -> list[str]:
    return [action] if isinstance(action, str) else list(action)


def _filter_actions(actions: list[str], valid: set[str]) -> list[str]:
    return [a for a in actions if a in valid]


def _strip_code_fences(raw: str) -> str:
    stripped = raw.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("\n", 1)[-1]
        if stripped.endswith("```"):
            stripped = stripped[: stripped.rfind("```")]
    return stripped.strip()


def validate_llm_output(raw: str, valid_actions: set[str]) -> dict:
    """Parse LLM JSON; strip any Action not in valid_actions. Return error dict on failure."""
    if not raw or not raw.strip():
        return {"error": "empty_response", "least_privilege_policy": None, "changes": []}

    cleaned = _strip_code_fences(raw)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        return {"error": f"parse_failed: {exc}", "least_privilege_policy": None, "changes": []}

    if "least_privilege_policy" not in data:
        return {"error": "missing_least_privilege_policy", "least_privilege_policy": None, "changes": []}

    policy = data["least_privilege_policy"]
    for stmt in policy.get("Statement", []):
        if "Action" not in stmt:
            continue
        normalized = _normalize_to_list(stmt["Action"])
        stmt["Action"] = _filter_actions(normalized, valid_actions)

    data["least_privilege_policy"] = policy
    data.setdefault("changes", [])
    return data
