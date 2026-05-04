"""Azure RBAC live scanner — enumerates role assignments via azure-mgmt-authorization."""
from __future__ import annotations

import logging
import os

from app.ingestion.live_scanners._types import ScanTarget
from app.ingestion.parser import PolicyDoc, Statement

logger = logging.getLogger(__name__)

_REQUIRED_ENV = (
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_SUBSCRIPTION_ID",
)


def _read_env() -> tuple[str, str, str, str]:
    """Read and validate Azure env vars. Raises ValueError (no secret in message)."""
    missing = [k for k in _REQUIRED_ENV if not os.environ.get(k)]
    if missing:
        raise ValueError(f"Missing required env vars: {', '.join(missing)}")
    return (
        os.environ["AZURE_TENANT_ID"],
        os.environ["AZURE_CLIENT_ID"],
        os.environ["AZURE_CLIENT_SECRET"],
        os.environ["AZURE_SUBSCRIPTION_ID"],
    )


def _build_role_def_dict(role_def) -> dict:
    """Convert SDK RoleDefinition to AzureNormalizer-compatible dict."""
    perms = role_def.properties.permissions or []
    actions: list[str] = []
    not_actions: list[str] = []
    data_actions: list[str] = []
    not_data_actions: list[str] = []
    for p in perms:
        actions.extend(p.actions or [])
        not_actions.extend(p.not_actions or [])
        data_actions.extend(p.data_actions or [])
        not_data_actions.extend(p.not_data_actions or [])
    return {
        "Actions": actions,
        "NotActions": not_actions,
        "DataActions": data_actions,
        "NotDataActions": not_data_actions,
        "AssignableScopes": [],
    }


class AzureScanner:
    """Implements the Scanner protocol for Azure RBAC via service-principal auth."""

    def scan(self, target: ScanTarget) -> PolicyDoc:
        tenant_id, client_id, client_secret, subscription_id = _read_env()

        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.authorization import AuthorizationManagementClient

            credential = ClientSecretCredential(tenant_id, client_id, client_secret)
            client = AuthorizationManagementClient(credential, subscription_id)

            # Collect unique role definition IDs referenced by assignments
            seen_def_ids: set[str] = set()
            for assignment in client.role_assignments.list_for_subscription():
                def_id = assignment.properties.role_definition_id
                if def_id:
                    seen_def_ids.add(def_id)

            raw_statements: list[dict] = []
            for def_id in seen_def_ids:
                role_def = client.role_definitions.get_by_id(def_id)
                role_dict = _build_role_def_dict(role_def)
                if role_dict["Actions"] or role_dict["DataActions"] or \
                        role_dict["NotActions"] or role_dict["NotDataActions"]:
                    from app.ingestion.normalizers.azure import AzureNormalizer
                    try:
                        doc = AzureNormalizer().normalize(role_dict)
                        for stmt in doc.statement:
                            raw_statements.append(stmt.model_dump(by_alias=True))
                    except Exception:
                        logger.debug("Skipping unparseable role definition %s", def_id)

        except ValueError:
            raise
        except Exception as exc:
            raise RuntimeError(f"Azure scan failed: {exc}") from exc

        if not raw_statements:
            return PolicyDoc(
                statement=[Statement(effect="Deny", action=["*"], resource="*")]
            )
        return PolicyDoc(
            statement=[Statement.model_validate(s) for s in raw_statements]
        )
