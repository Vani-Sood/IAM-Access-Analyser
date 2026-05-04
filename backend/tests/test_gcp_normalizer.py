"""Unit tests for GCPNormalizer — Batch 18."""
from __future__ import annotations

import pytest

from app.ingestion.parser import PolicyDoc


# ── Fixtures ──────────────────────────────────────────────────────────────────

GCP_BINDING_POLICY = {
    "bindings": [
        {
            "role": "roles/storage.admin",
            "members": ["user:alice@example.com", "serviceAccount:sa@project.iam.gserviceaccount.com"],
        },
        {
            "role": "roles/viewer",
            "members": ["group:team@example.com"],
        },
    ]
}

GCP_CUSTOM_ROLE = {
    "name": "projects/my-project/roles/myCustomRole",
    "title": "My Custom Role",
    "description": "A custom role for testing",
    "includedPermissions": [
        "storage.objects.get",
        "storage.objects.list",
        "iam.roles.create",
        "iam.serviceAccounts.actAs",
    ],
    "stage": "GA",
}

GCP_BINDING_SINGLE = {
    "bindings": [
        {
            "role": "roles/owner",
            "members": ["user:admin@example.com"],
        }
    ]
}

GCP_BINDING_EMPTY_MEMBERS = {
    "bindings": [
        {
            "role": "roles/viewer",
            "members": [],
        }
    ]
}


# ── Import smoke ──────────────────────────────────────────────────────────────

def test_import_gcp_normalizer():
    from app.ingestion.normalizers.gcp import GCPNormalizer
    assert GCPNormalizer is not None


def test_gcp_normalizer_instantiation():
    from app.ingestion.normalizers.gcp import GCPNormalizer
    n = GCPNormalizer()
    assert n is not None


# ── normalize() return type ───────────────────────────────────────────────────

def test_normalize_bindings_returns_policy_doc():
    from app.ingestion.normalizers.gcp import GCPNormalizer
    result = GCPNormalizer().normalize(GCP_BINDING_POLICY)
    assert isinstance(result, PolicyDoc)


def test_normalize_custom_role_returns_policy_doc():
    from app.ingestion.normalizers.gcp import GCPNormalizer
    result = GCPNormalizer().normalize(GCP_CUSTOM_ROLE)
    assert isinstance(result, PolicyDoc)


def test_normalize_has_statements():
    from app.ingestion.normalizers.gcp import GCPNormalizer
    result = GCPNormalizer().normalize(GCP_BINDING_POLICY)
    assert len(result.statement) >= 1


# ── Bindings format ───────────────────────────────────────────────────────────

def test_bindings_each_role_produces_statement():
    from app.ingestion.normalizers.gcp import GCPNormalizer
    result = GCPNormalizer().normalize(GCP_BINDING_POLICY)
    # 2 bindings → at least 2 statements (or one merged)
    assert len(result.statement) >= 1


def test_bindings_role_becomes_action():
    from app.ingestion.normalizers.gcp import GCPNormalizer
    result = GCPNormalizer().normalize(GCP_BINDING_SINGLE)
    all_actions = [a for s in result.statement for a in s.actions]
    assert "roles/owner" in all_actions


def test_bindings_all_roles_present():
    from app.ingestion.normalizers.gcp import GCPNormalizer
    result = GCPNormalizer().normalize(GCP_BINDING_POLICY)
    all_actions = [a for s in result.statement for a in s.actions]
    assert "roles/storage.admin" in all_actions
    assert "roles/viewer" in all_actions


def test_bindings_statements_are_allow():
    from app.ingestion.normalizers.gcp import GCPNormalizer
    result = GCPNormalizer().normalize(GCP_BINDING_POLICY)
    for stmt in result.statement:
        assert stmt.effect.value == "Allow"


def test_bindings_resources_are_wildcard():
    from app.ingestion.normalizers.gcp import GCPNormalizer
    result = GCPNormalizer().normalize(GCP_BINDING_POLICY)
    for stmt in result.statement:
        assert stmt.resources  # non-empty
        assert all(r == "*" for r in stmt.resources)


# ── Custom role format ────────────────────────────────────────────────────────

def test_custom_role_permissions_become_actions():
    from app.ingestion.normalizers.gcp import GCPNormalizer
    result = GCPNormalizer().normalize(GCP_CUSTOM_ROLE)
    all_actions = [a for s in result.statement for a in s.actions]
    assert "storage.objects.get" in all_actions
    assert "storage.objects.list" in all_actions
    assert "iam.roles.create" in all_actions
    assert "iam.serviceAccounts.actAs" in all_actions


def test_custom_role_effect_is_allow():
    from app.ingestion.normalizers.gcp import GCPNormalizer
    result = GCPNormalizer().normalize(GCP_CUSTOM_ROLE)
    for stmt in result.statement:
        assert stmt.effect.value == "Allow"


def test_custom_role_resource_is_wildcard():
    from app.ingestion.normalizers.gcp import GCPNormalizer
    result = GCPNormalizer().normalize(GCP_CUSTOM_ROLE)
    for stmt in result.statement:
        assert stmt.resources
        assert all(r == "*" for r in stmt.resources)


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_empty_bindings_raises():
    from app.ingestion.normalizers.gcp import GCPNormalizer
    with pytest.raises(Exception):
        GCPNormalizer().normalize({"bindings": []})


def test_invalid_format_raises():
    from app.ingestion.normalizers.gcp import GCPNormalizer
    with pytest.raises(Exception):
        GCPNormalizer().normalize({"unknown_key": "value"})


def test_empty_permissions_custom_role_raises():
    from app.ingestion.normalizers.gcp import GCPNormalizer
    with pytest.raises(Exception):
        GCPNormalizer().normalize({
            "name": "projects/p/roles/r",
            "includedPermissions": [],
        })


# ── GCP catalog ───────────────────────────────────────────────────────────────

def test_gcp_catalog_loads():
    from app.ingestion.normalizers.gcp import get_gcp_actions
    actions = get_gcp_actions()
    assert isinstance(actions, list)
    assert len(actions) > 0


def test_gcp_catalog_has_iam_actions():
    from app.ingestion.normalizers.gcp import get_gcp_actions
    actions = get_gcp_actions()
    assert any("iam" in a for a in actions)


def test_gcp_catalog_has_storage_actions():
    from app.ingestion.normalizers.gcp import get_gcp_actions
    actions = get_gcp_actions()
    assert any("storage" in a for a in actions)


def test_gcp_catalog_has_roles():
    from app.ingestion.normalizers.gcp import get_gcp_actions
    actions = get_gcp_actions()
    assert any(a.startswith("roles/") for a in actions)
