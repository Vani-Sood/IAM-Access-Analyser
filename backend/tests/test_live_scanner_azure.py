"""Azure live scanner tests — Batch 6.

All Azure SDK calls are mocked; no real Azure credentials needed.
"""
from __future__ import annotations

import os
from dataclasses import FrozenInstanceError
from unittest.mock import MagicMock, patch

import pytest

from app.ingestion.parser import PolicyDoc

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_client(actions: list[str] | None = None) -> MagicMock:
    """Return a mock AuthorizationManagementClient with one role assignment."""
    mock_permission = MagicMock()
    mock_permission.actions = actions or ["Microsoft.Compute/virtualMachines/read"]
    mock_permission.not_actions = []
    mock_permission.data_actions = []
    mock_permission.not_data_actions = []

    mock_role_def = MagicMock()
    mock_role_def.properties.permissions = [mock_permission]

    mock_assignment = MagicMock()
    mock_assignment.properties.role_definition_id = (
        "/subscriptions/sub-1/providers/Microsoft.Authorization"
        "/roleDefinitions/def-abc"
    )

    mock_client = MagicMock()
    mock_client.role_assignments.list_for_subscription.return_value = [mock_assignment]
    mock_client.role_definitions.get_by_id.return_value = mock_role_def
    return mock_client


# ---------------------------------------------------------------------------
# 1. AzureCredentials — frozen + masked repr
# ---------------------------------------------------------------------------

def test_azure_credentials_frozen():
    from app.ingestion.live_scanners._types import AzureCredentials
    creds = AzureCredentials(
        tenant_id="t1", client_id="c1",
        client_secret="super-secret", subscription_id="s1",
    )
    with pytest.raises(FrozenInstanceError):
        creds.client_secret = "other"  # type: ignore[misc]


def test_azure_credentials_repr_masks_secret():
    from app.ingestion.live_scanners._types import AzureCredentials
    creds = AzureCredentials(
        tenant_id="tenant-1", client_id="client-1",
        client_secret="my-very-secret-value", subscription_id="sub-1",
    )
    r = repr(creds)
    assert "my-very-secret-value" not in r
    assert "***" in r
    assert "tenant-1" in r
    assert "client-1" in r


# ---------------------------------------------------------------------------
# 2. Dispatcher now resolves azure
# ---------------------------------------------------------------------------

def test_get_scanner_azure_returns_azure_scanner():
    from app.ingestion.live_scanners import get_scanner
    from app.ingestion.live_scanners.azure import AzureScanner
    scanner = get_scanner("azure")
    assert isinstance(scanner, AzureScanner)


# ---------------------------------------------------------------------------
# 3. Missing env vars → ValueError before SDK call
# ---------------------------------------------------------------------------

def test_azure_scanner_raises_on_missing_env(monkeypatch):
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)

    from app.ingestion.live_scanners.azure import AzureScanner
    from app.ingestion.live_scanners._types import ScanTarget

    scanner = AzureScanner()
    with pytest.raises(ValueError, match="AZURE_"):
        scanner.scan(ScanTarget(cloud="azure"))


def test_azure_scanner_error_does_not_leak_secret(monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", "t")
    monkeypatch.setenv("AZURE_CLIENT_ID", "c")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "ultra-secret-value", )
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)

    from app.ingestion.live_scanners.azure import AzureScanner
    from app.ingestion.live_scanners._types import ScanTarget

    scanner = AzureScanner()
    with pytest.raises(ValueError) as exc_info:
        scanner.scan(ScanTarget(cloud="azure"))
    assert "ultra-secret-value" not in str(exc_info.value)


# ---------------------------------------------------------------------------
# 4. Happy path — returns PolicyDoc with correct actions
# ---------------------------------------------------------------------------

def test_azure_scanner_happy_path(monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-1")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-1")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret-1")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")

    mock_client = _make_mock_client(["Microsoft.Compute/virtualMachines/read"])

    with (
        patch("azure.identity.ClientSecretCredential") as mock_cred_cls,
        patch(
            "azure.mgmt.authorization.AuthorizationManagementClient",
            return_value=mock_client,
        ),
    ):
        mock_cred_cls.return_value = MagicMock()
        from app.ingestion.live_scanners.azure import AzureScanner
        from app.ingestion.live_scanners._types import ScanTarget

        result = AzureScanner().scan(ScanTarget(cloud="azure"))

    assert isinstance(result, PolicyDoc)
    all_actions = [a for stmt in result.statement for a in stmt.actions]
    assert "Microsoft.Compute/virtualMachines/read" in all_actions


# ---------------------------------------------------------------------------
# 5. SDK exception wrapped in RuntimeError
# ---------------------------------------------------------------------------

def test_azure_scanner_wraps_sdk_exception(monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", "t")
    monkeypatch.setenv("AZURE_CLIENT_ID", "c")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "s")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")

    mock_client = MagicMock()
    mock_client.role_assignments.list_for_subscription.side_effect = Exception(
        "Azure API unreachable"
    )

    with (
        patch("azure.identity.ClientSecretCredential"),
        patch(
            "azure.mgmt.authorization.AuthorizationManagementClient",
            return_value=mock_client,
        ),
    ):
        from app.ingestion.live_scanners.azure import AzureScanner
        from app.ingestion.live_scanners._types import ScanTarget

        with pytest.raises(RuntimeError, match="Azure scan failed"):
            AzureScanner().scan(ScanTarget(cloud="azure"))


# ---------------------------------------------------------------------------
# 6. Empty subscription → deny-all fallback
# ---------------------------------------------------------------------------

def test_azure_scanner_empty_subscription_returns_deny_all(monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", "t")
    monkeypatch.setenv("AZURE_CLIENT_ID", "c")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "s")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")

    mock_client = MagicMock()
    mock_client.role_assignments.list_for_subscription.return_value = []

    with (
        patch("azure.identity.ClientSecretCredential"),
        patch(
            "azure.mgmt.authorization.AuthorizationManagementClient",
            return_value=mock_client,
        ),
    ):
        from app.ingestion.live_scanners.azure import AzureScanner
        from app.ingestion.live_scanners._types import ScanTarget

        result = AzureScanner().scan(ScanTarget(cloud="azure"))

    assert isinstance(result, PolicyDoc)
    assert len(result.statement) == 1
    assert result.statement[0].effect.value == "Deny"
