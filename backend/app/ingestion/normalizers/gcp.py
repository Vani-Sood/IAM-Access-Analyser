"""GCP IAM policy / custom role → PolicyDoc normalizer."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from app.ingestion.parser import PolicyDoc, PolicyValidationError

_CATALOG_PATH = Path(__file__).parent.parent.parent.parent / "data" / "gcp_actions_catalog.json"


@lru_cache(maxsize=1)
def _load_catalog() -> dict[str, list[str]]:
    with open(_CATALOG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def get_gcp_actions() -> list[str]:
    """Return flat list of all known GCP actions and roles."""
    catalog = _load_catalog()
    seen: set[str] = set()
    result: list[str] = []
    for actions in catalog.values():
        for action in actions:
            if action not in seen:
                seen.add(action)
                result.append(action)
    return result


class GCPNormalizer:
    """Normalize a GCP IAM policy or custom role definition to a PolicyDoc.

    Supports two formats:
    1. Policy bindings: {"bindings": [{"role": "roles/X", "members": [...]}]}
    2. Custom role:     {"name": "...", "includedPermissions": [...]}
    """

    def normalize(self, raw: dict) -> PolicyDoc:
        if not isinstance(raw, dict):
            raise PolicyValidationError("GCP policy must be a JSON object")

        if "bindings" in raw:
            return self._normalize_bindings(raw["bindings"])
        if "includedPermissions" in raw:
            return self._normalize_custom_role(raw)
        raise PolicyValidationError(
            "GCP policy must have 'bindings' (IAM policy) or 'includedPermissions' (custom role)"
        )

    def _normalize_bindings(self, bindings: list) -> PolicyDoc:
        if not bindings:
            raise PolicyValidationError("GCP IAM policy must have at least one binding")

        statements: list[dict] = []
        for binding in bindings:
            role = binding.get("role", "")
            members = binding.get("members") or []
            if not role:
                continue
            # Represent each binding as an Allow statement: role → action, members → principal
            principal = members[0] if len(members) == 1 else (members or None)
            stmt: dict = {
                "Effect": "Allow",
                "Action": [role],
                "Resource": "*",
            }
            if principal:
                stmt["Principal"] = principal
            statements.append(stmt)

        if not statements:
            raise PolicyValidationError("GCP IAM policy produced no valid statements from bindings")

        return PolicyDoc.model_validate({"Version": "2012-10-17", "Statement": statements})

    def _normalize_custom_role(self, raw: dict) -> PolicyDoc:
        permissions = list(raw.get("includedPermissions") or [])
        if not permissions:
            raise PolicyValidationError(
                "GCP custom role must have at least one permission in 'includedPermissions'"
            )

        return PolicyDoc.model_validate({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": permissions,
                    "Resource": "*",
                }
            ],
        })
