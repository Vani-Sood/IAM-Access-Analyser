"""Auto-detect cloud provider from raw policy JSON shape."""
from __future__ import annotations


def _has_acs_resource(raw: dict) -> bool:
    """Return True if any Resource value starts with 'acs:'."""
    stmts = raw.get("Statement")
    if not isinstance(stmts, list):
        return False
    for stmt in stmts:
        if not isinstance(stmt, dict):
            continue
        res = stmt.get("Resource", "")
        if isinstance(res, str) and res.startswith("acs:"):
            return True
        if isinstance(res, list) and any(
            isinstance(r, str) and r.startswith("acs:") for r in res
        ):
            return True
    return False


def detect_cloud(raw: object) -> str | None:
    """Return detected cloud provider string or None if unrecognised.

    Supported: 'aws', 'gcp', 'azure', 'oci', 'alibaba'
    """
    if not isinstance(raw, dict):
        return None

    # OCI: string-statement list
    if "statements" in raw and isinstance(raw["statements"], list):
        stmts = raw["statements"]
        if stmts and isinstance(stmts[0], str):
            return "oci"

    # GCP: IAM policy bindings or custom role
    if "bindings" in raw or "includedPermissions" in raw:
        return "gcp"

    # Azure: role definition keys
    azure_keys = {"Actions", "DataActions", "NotActions", "NotDataActions"}
    if azure_keys & raw.keys():
        return "azure"

    # Alibaba: Statement + (Version "1" OR acs: resource prefix)
    if "Statement" in raw:
        if raw.get("Version") == "1" or _has_acs_resource(raw):
            return "alibaba"
        return "aws"

    return None
