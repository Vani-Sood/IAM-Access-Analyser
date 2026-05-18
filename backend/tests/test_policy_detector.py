"""Tests for policy auto-detection normalizer."""
from __future__ import annotations

import pytest

AWS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
}
GCP_BINDINGS = {
    "bindings": [{"role": "roles/viewer", "members": ["user:a@b.com"]}]
}
GCP_CUSTOM = {
    "name": "projects/p/roles/r",
    "includedPermissions": ["storage.objects.get"],
}
AZURE_ROLE = {
    "Name": "Reader",
    "Actions": ["Microsoft.Storage/storageAccounts/read"],
    "NotActions": [],
    "DataActions": [],
    "NotDataActions": [],
    "AssignableScopes": ["/"],
}
AZURE_DATA_ONLY = {
    "DataActions": ["Microsoft.Storage/storageAccounts/blobServices/read"],
    "NotDataActions": [],
    "AssignableScopes": ["/"],
}


# ── Tracer bullet ─────────────────────────────────────────────────────────────

def test_detect_aws_policy():
    from app.ingestion.normalizers.detect import detect_cloud
    assert detect_cloud(AWS_POLICY) == "aws"


# ── GCP ───────────────────────────────────────────────────────────────────────

def test_detect_gcp_bindings():
    from app.ingestion.normalizers.detect import detect_cloud
    assert detect_cloud(GCP_BINDINGS) == "gcp"


def test_detect_gcp_custom_role():
    from app.ingestion.normalizers.detect import detect_cloud
    assert detect_cloud(GCP_CUSTOM) == "gcp"


# ── Azure ─────────────────────────────────────────────────────────────────────

def test_detect_azure_role():
    from app.ingestion.normalizers.detect import detect_cloud
    assert detect_cloud(AZURE_ROLE) == "azure"


def test_detect_azure_data_actions_only():
    from app.ingestion.normalizers.detect import detect_cloud
    assert detect_cloud(AZURE_DATA_ONLY) == "azure"


# ── Unknown ───────────────────────────────────────────────────────────────────

def test_detect_unknown_returns_none():
    from app.ingestion.normalizers.detect import detect_cloud
    assert detect_cloud({"foo": "bar"}) is None


def test_detect_empty_dict_returns_none():
    from app.ingestion.normalizers.detect import detect_cloud
    assert detect_cloud({}) is None


def test_detect_non_dict_returns_none():
    from app.ingestion.normalizers.detect import detect_cloud
    assert detect_cloud([]) is None  # type: ignore[arg-type]


# ── Auto routing via _normalize_policy ───────────────────────────────────────

def test_auto_routes_aws():
    from app.api.v1.analyze import _normalize_policy
    result = _normalize_policy("auto", AWS_POLICY)
    assert "Statement" in result


def test_auto_routes_gcp():
    from app.api.v1.analyze import _normalize_policy
    result = _normalize_policy("auto", GCP_BINDINGS)
    assert "Statement" in result


def test_auto_routes_azure():
    from app.api.v1.analyze import _normalize_policy
    result = _normalize_policy("auto", AZURE_ROLE)
    assert "Statement" in result


def test_auto_unknown_raises_422():
    from fastapi import HTTPException
    from app.api.v1.analyze import _normalize_policy
    with pytest.raises(HTTPException) as exc_info:
        _normalize_policy("auto", {"totally": "unknown"})
    assert exc_info.value.status_code == 422
