"""Unit tests for AzureNormalizer — Batch 18."""
from __future__ import annotations

import pytest

from app.ingestion.parser import PolicyDoc


# ── Fixtures ──────────────────────────────────────────────────────────────────

ROLE_DEF_SIMPLE = {
    "Name": "Custom Reader",
    "IsCustom": True,
    "Description": "Read-only custom role",
    "Actions": [
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.Compute/virtualMachines/read",
    ],
    "NotActions": [],
    "DataActions": [],
    "NotDataActions": [],
    "AssignableScopes": ["/subscriptions/00000000-0000-0000-0000-000000000000"],
}

ROLE_DEF_NOT_ACTIONS = {
    "Name": "Almost Admin",
    "Actions": ["*"],
    "NotActions": ["Microsoft.Authorization/*/Delete"],
    "DataActions": [],
    "NotDataActions": [],
    "AssignableScopes": ["/"],
}

ROLE_DEF_WILDCARD = {
    "Name": "Full Admin",
    "Actions": ["*"],
    "NotActions": [],
    "DataActions": [],
    "NotDataActions": [],
    "AssignableScopes": ["/"],
}

ROLE_DEF_MULTIPLE_SCOPES = {
    "Name": "Multi-scope Reader",
    "Actions": ["Microsoft.Storage/storageAccounts/read"],
    "NotActions": [],
    "DataActions": [],
    "NotDataActions": [],
    "AssignableScopes": [
        "/subscriptions/aaa",
        "/subscriptions/bbb",
    ],
}

ROLE_DEF_DATA_ACTIONS = {
    "Name": "Data Reader",
    "Actions": ["Microsoft.Storage/storageAccounts/read"],
    "NotActions": [],
    "DataActions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
    "NotDataActions": [],
    "AssignableScopes": ["/"],
}


# ── Import smoke ──────────────────────────────────────────────────────────────

def test_import_azure_normalizer():
    from app.ingestion.normalizers.azure import AzureNormalizer
    assert AzureNormalizer is not None


def test_azure_normalizer_instantiation():
    from app.ingestion.normalizers.azure import AzureNormalizer
    n = AzureNormalizer()
    assert n is not None


# ── normalize() return type ───────────────────────────────────────────────────

def test_normalize_returns_policy_doc():
    from app.ingestion.normalizers.azure import AzureNormalizer
    result = AzureNormalizer().normalize(ROLE_DEF_SIMPLE)
    assert isinstance(result, PolicyDoc)


def test_normalize_has_statements():
    from app.ingestion.normalizers.azure import AzureNormalizer
    result = AzureNormalizer().normalize(ROLE_DEF_SIMPLE)
    assert len(result.statement) >= 1


# ── Actions mapping ───────────────────────────────────────────────────────────

def test_normalize_actions_mapped_to_allow_statement():
    from app.ingestion.normalizers.azure import AzureNormalizer
    result = AzureNormalizer().normalize(ROLE_DEF_SIMPLE)
    allow_stmts = [s for s in result.statement if s.effect.value == "Allow"]
    assert len(allow_stmts) >= 1


def test_normalize_all_actions_present():
    from app.ingestion.normalizers.azure import AzureNormalizer
    result = AzureNormalizer().normalize(ROLE_DEF_SIMPLE)
    all_actions = [a for s in result.statement for a in s.actions]
    assert "Microsoft.Storage/storageAccounts/read" in all_actions
    assert "Microsoft.Compute/virtualMachines/read" in all_actions


def test_normalize_wildcard_action_preserved():
    from app.ingestion.normalizers.azure import AzureNormalizer
    result = AzureNormalizer().normalize(ROLE_DEF_WILDCARD)
    all_actions = [a for s in result.statement for a in s.actions]
    assert "*" in all_actions


# ── NotActions mapping ────────────────────────────────────────────────────────

def test_normalize_not_actions_produce_not_action_statement():
    from app.ingestion.normalizers.azure import AzureNormalizer
    result = AzureNormalizer().normalize(ROLE_DEF_NOT_ACTIONS)
    not_action_stmts = [s for s in result.statement if s.not_action is not None]
    assert len(not_action_stmts) >= 1


def test_normalize_not_actions_content():
    from app.ingestion.normalizers.azure import AzureNormalizer
    result = AzureNormalizer().normalize(ROLE_DEF_NOT_ACTIONS)
    not_actions_flat = [a for s in result.statement for a in s.not_actions]
    assert "Microsoft.Authorization/*/Delete" in not_actions_flat


# ── Resource / AssignableScopes mapping ──────────────────────────────────────

def test_normalize_scope_becomes_resource():
    from app.ingestion.normalizers.azure import AzureNormalizer
    result = AzureNormalizer().normalize(ROLE_DEF_SIMPLE)
    all_resources = [r for s in result.statement for r in s.resources]
    assert "/subscriptions/00000000-0000-0000-0000-000000000000" in all_resources


def test_normalize_root_scope_becomes_wildcard_or_slash():
    from app.ingestion.normalizers.azure import AzureNormalizer
    result = AzureNormalizer().normalize(ROLE_DEF_WILDCARD)
    all_resources = [r for s in result.statement for r in s.resources]
    # "/" or "*" both acceptable for root scope
    assert any(r in ("*", "/") for r in all_resources)


def test_normalize_multiple_scopes_produces_resources():
    from app.ingestion.normalizers.azure import AzureNormalizer
    result = AzureNormalizer().normalize(ROLE_DEF_MULTIPLE_SCOPES)
    all_resources = [r for s in result.statement for r in s.resources]
    assert "/subscriptions/aaa" in all_resources or "/subscriptions/bbb" in all_resources


# ── DataActions ───────────────────────────────────────────────────────────────

def test_normalize_data_actions_included():
    from app.ingestion.normalizers.azure import AzureNormalizer
    result = AzureNormalizer().normalize(ROLE_DEF_DATA_ACTIONS)
    all_actions = [a for s in result.statement for a in s.actions]
    assert "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read" in all_actions


# ── Empty/minimal inputs ──────────────────────────────────────────────────────

def test_normalize_empty_actions_list():
    from app.ingestion.normalizers.azure import AzureNormalizer
    # Should raise or return something valid
    with pytest.raises(Exception):
        AzureNormalizer().normalize({
            "Name": "Empty",
            "Actions": [],
            "NotActions": [],
            "DataActions": [],
            "NotDataActions": [],
            "AssignableScopes": ["/"],
        })


def test_normalize_missing_required_key_raises():
    from app.ingestion.normalizers.azure import AzureNormalizer
    with pytest.raises(Exception):
        AzureNormalizer().normalize({"Name": "Broken"})


# ── Azure catalog ─────────────────────────────────────────────────────────────

def test_azure_catalog_loads():
    from app.ingestion.normalizers.azure import get_azure_actions
    actions = get_azure_actions()
    assert isinstance(actions, list)
    assert len(actions) > 0


def test_azure_catalog_has_authorization_actions():
    from app.ingestion.normalizers.azure import get_azure_actions
    actions = get_azure_actions()
    assert any("Microsoft.Authorization" in a for a in actions)


def test_azure_catalog_has_storage_actions():
    from app.ingestion.normalizers.azure import get_azure_actions
    actions = get_azure_actions()
    assert any("Microsoft.Storage" in a for a in actions)
