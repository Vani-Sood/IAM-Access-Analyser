from __future__ import annotations

from app.ingestion.catalog import get_actions_for_service, get_all_actions
from app.ingestion.parser import PolicyDoc, Statement


def _expand_single(action: str) -> list[str]:
    if action == "*":
        return get_all_actions()

    if ":" not in action:
        return [action]

    service, remainder = action.split(":", 1)

    if remainder == "*":
        return get_actions_for_service(service)

    if "*" in remainder:
        prefix = f"{service}:{remainder[: remainder.index('*')]}"
        return [a for a in get_actions_for_service(service) if a.startswith(prefix)]

    return [action]


def _expand_list(actions: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for action in actions:
        for expanded in _expand_single(action):
            if expanded not in seen:
                seen.add(expanded)
                result.append(expanded)
    return result


def expand_wildcards(policy: PolicyDoc) -> PolicyDoc:
    """Return new PolicyDoc with wildcard actions expanded. Original unchanged."""
    new_statements: list[Statement] = []

    for stmt in policy.statement:
        data = stmt.model_dump(by_alias=True, exclude_none=True)

        if stmt.action is not None:
            data["Action"] = _expand_list(stmt.actions)

        if stmt.not_action is not None:
            data["NotAction"] = _expand_list(stmt.not_actions)

        new_statements.append(Statement.model_validate(data))

    doc_data = policy.model_dump(by_alias=True, exclude_none=True)
    doc_data["Statement"] = [
        s.model_dump(by_alias=True, exclude_none=True) for s in new_statements
    ]
    return PolicyDoc.model_validate(doc_data)
