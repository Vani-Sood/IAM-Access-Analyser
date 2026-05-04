"""Azure IAM role definition → PolicyDoc normalizer."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from app.ingestion.parser import PolicyDoc, PolicyValidationError

_CATALOG_PATH = Path(__file__).parent.parent.parent.parent / "data" / "azure_actions_catalog.json"


@lru_cache(maxsize=1)
def _load_catalog() -> dict[str, list[str]]:
    with open(_CATALOG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def get_azure_actions() -> list[str]:
    """Return flat list of all known Azure actions."""
    catalog = _load_catalog()
    seen: set[str] = set()
    result: list[str] = []
    for actions in catalog.values():
        for action in actions:
            if action not in seen:
                seen.add(action)
                result.append(action)
    return result


class AzureNormalizer:
    """Normalize an Azure role definition dict to a PolicyDoc.

    Supports:
    - Single role definition with Actions / NotActions / DataActions
    - AssignableScopes → Resource
    """

    def normalize(self, raw: dict) -> PolicyDoc:
        if not isinstance(raw, dict):
            raise PolicyValidationError("Azure policy must be a JSON object")

        actions = list(raw.get("Actions") or [])
        data_actions = list(raw.get("DataActions") or [])
        not_actions = list(raw.get("NotActions") or [])
        not_data_actions = list(raw.get("NotDataActions") or [])
        scopes = list(raw.get("AssignableScopes") or [])

        combined_actions = actions + data_actions
        combined_not_actions = not_actions + not_data_actions

        if not combined_actions and not combined_not_actions:
            raise PolicyValidationError(
                "Azure role definition must have at least one action in 'Actions', "
                "'DataActions', 'NotActions', or 'NotDataActions'"
            )

        # Normalise root scope "/" → "*" (AWS wildcard convention)
        resources = [("*" if s == "/" else s) for s in scopes] or ["*"]
        resource_value = resources[0] if len(resources) == 1 else resources

        statements: list[dict] = []

        if combined_actions:
            statements.append({
                "Effect": "Allow",
                "Action": combined_actions,
                "Resource": resource_value,
            })

        if combined_not_actions:
            statements.append({
                "Effect": "Allow",
                "NotAction": combined_not_actions,
                "Resource": resource_value,
            })

        return PolicyDoc.model_validate({"Version": "2012-10-17", "Statement": statements})
