"""Alibaba Cloud RAM policy → PolicyDoc normalizer.

RAM policies are structurally similar to AWS but use:
  - Version "1" instead of "2012-10-17"
  - "acs:" ARN prefix instead of "arn:aws:"
"""
from __future__ import annotations

from app.ingestion.parser import PolicyDoc, PolicyValidationError


class AlibabaNormalizer:
    """Normalize an Alibaba Cloud RAM policy dict to PolicyDoc."""

    def normalize(self, raw: object) -> PolicyDoc:
        if not isinstance(raw, dict):
            raise PolicyValidationError("Alibaba RAM policy must be a JSON object")

        stmts_raw = raw.get("Statement")
        if not isinstance(stmts_raw, list) or not stmts_raw:
            raise PolicyValidationError(
                "Alibaba RAM policy must have a non-empty 'Statement' list"
            )

        statements: list[dict] = []
        for stmt in stmts_raw:
            if not isinstance(stmt, dict):
                continue
            effect = stmt.get("Effect", "Allow")
            action = stmt.get("Action", "*")
            resource = stmt.get("Resource", "*")
            condition = stmt.get("Condition")

            entry: dict = {
                "Effect": effect,
                "Action": action if isinstance(action, list) else [action],
                "Resource": resource if isinstance(resource, list) else [resource],
            }
            if condition:
                entry["Condition"] = condition
            statements.append(entry)

        if not statements:
            raise PolicyValidationError("Alibaba RAM policy produced no valid statements")

        return PolicyDoc.model_validate({
            "Version": "2012-10-17",
            "Statement": statements,
        })
