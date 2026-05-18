"""OCI IAM policy → PolicyDoc normalizer.

OCI uses human-readable string statements:
  "Allow group Admins to manage all-resources in tenancy"
  "Deny group ReadOnly to use instances in compartment Prod"
"""
from __future__ import annotations

import re

from app.ingestion.parser import PolicyDoc, PolicyValidationError

_STMT_RE = re.compile(
    r"^(Allow|Deny)\s+"           # effect
    r"(.+?)\s+"                    # subject (group X / service Y / any-user)
    r"to\s+(\S+)\s+"              # verb (manage/use/read/inspect)
    r"(\S+)\s+"                   # resource-type
    r"in\s+(.+)$",                # location (tenancy / compartment X)
    re.IGNORECASE,
)


def _parse_oci_statement(raw: str) -> dict:
    """Parse one OCI policy string into a PolicyDoc Statement dict."""
    m = _STMT_RE.match(raw.strip())
    if not m:
        # Fallback: treat entire string as a single allow action on wildcard
        return {
            "Effect": "Allow",
            "Action": [f"oci:{raw[:80]}"],
            "Resource": "*",
        }

    effect_str, subject, verb, resource_type, location = m.groups()
    effect = "Allow" if effect_str.lower() == "allow" else "Deny"
    action = f"oci:{verb.lower()}:{resource_type.lower()}"

    location = location.strip()
    if location.lower() == "tenancy":
        resource = "*"
    else:
        # "compartment X" → keep compartment path as resource
        resource = re.sub(r"^compartment\s+", "compartment/", location, flags=re.IGNORECASE)

    stmt: dict = {
        "Effect": effect,
        "Action": [action],
        "Resource": resource,
    }

    # Map subject to Principal where meaningful
    subject = subject.strip()
    if not subject.lower().startswith("any-user"):
        stmt["Principal"] = subject

    return stmt


class OCINormalizer:
    """Normalize an OCI IAM policy (string statement list) to PolicyDoc."""

    def normalize(self, raw: object) -> PolicyDoc:
        if not isinstance(raw, dict):
            raise PolicyValidationError("OCI policy must be a JSON object")

        statements_raw = raw.get("statements")
        if not isinstance(statements_raw, list) or not statements_raw:
            raise PolicyValidationError(
                "OCI policy must have a non-empty 'statements' list"
            )

        statements = [_parse_oci_statement(s) for s in statements_raw if isinstance(s, str)]
        if not statements:
            raise PolicyValidationError("OCI policy produced no valid statements")

        return PolicyDoc.model_validate({
            "Version": "2012-10-17",
            "Statement": statements,
        })
