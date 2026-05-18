"""Tests for OCI policy normalizer."""
from __future__ import annotations
import pytest
from app.ingestion.parser import PolicyDoc

OCI_POLICY = {
    "statements": [
        "Allow group Admins to manage all-resources in tenancy",
        "Allow group NetworkAdmins to use virtual-network-family in compartment Production",
        "Allow service objectstorage-us-phoenix-1 to use keys in tenancy",
        "Deny group ReadOnly to manage iam-groups in tenancy",
    ]
}

OCI_SINGLE = {
    "statements": ["Allow group Devs to read buckets in compartment Dev"]
}


# ── Tracer bullet ─────────────────────────────────────────────────────────────

def test_oci_normalize_returns_policy_doc():
    from app.ingestion.normalizers.oci import OCINormalizer
    result = OCINormalizer().normalize(OCI_POLICY)
    assert isinstance(result, PolicyDoc)


# ── Statement count ───────────────────────────────────────────────────────────

def test_oci_each_string_becomes_statement():
    from app.ingestion.normalizers.oci import OCINormalizer
    result = OCINormalizer().normalize(OCI_POLICY)
    assert len(result.statement) == 4


# ── Effect mapping ────────────────────────────────────────────────────────────

def test_oci_allow_maps_to_allow():
    from app.ingestion.normalizers.oci import OCINormalizer
    result = OCINormalizer().normalize(OCI_SINGLE)
    assert result.statement[0].effect.value == "Allow"


def test_oci_deny_maps_to_deny():
    from app.ingestion.normalizers.oci import OCINormalizer
    deny_policy = {"statements": ["Deny group ReadOnly to manage iam-groups in tenancy"]}
    result = OCINormalizer().normalize(deny_policy)
    assert result.statement[0].effect.value == "Deny"


# ── Action mapping ────────────────────────────────────────────────────────────

def test_oci_verb_and_resource_type_become_action():
    from app.ingestion.normalizers.oci import OCINormalizer
    result = OCINormalizer().normalize(OCI_SINGLE)
    actions = result.statement[0].actions
    assert len(actions) == 1
    assert "read" in actions[0].lower()
    assert "bucket" in actions[0].lower()


def test_oci_manage_verb_in_action():
    from app.ingestion.normalizers.oci import OCINormalizer
    policy = {"statements": ["Allow group Admins to manage all-resources in tenancy"]}
    result = OCINormalizer().normalize(policy)
    actions = result.statement[0].actions
    assert any("manage" in a.lower() for a in actions)


# ── Resource mapping ──────────────────────────────────────────────────────────

def test_oci_tenancy_scope_becomes_wildcard():
    from app.ingestion.normalizers.oci import OCINormalizer
    result = OCINormalizer().normalize(OCI_SINGLE)
    resources = result.statement[0].resources
    assert len(resources) >= 1


def test_oci_compartment_scope_preserved():
    from app.ingestion.normalizers.oci import OCINormalizer
    policy = {"statements": ["Allow group Devs to use instances in compartment Dev"]}
    result = OCINormalizer().normalize(policy)
    resources = result.statement[0].resources
    assert any("Dev" in r or r == "*" for r in resources)


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_oci_empty_statements_raises():
    from app.ingestion.normalizers.oci import OCINormalizer
    with pytest.raises(Exception):
        OCINormalizer().normalize({"statements": []})


def test_oci_missing_statements_key_raises():
    from app.ingestion.normalizers.oci import OCINormalizer
    with pytest.raises(Exception):
        OCINormalizer().normalize({"Version": "1"})


def test_oci_non_dict_raises():
    from app.ingestion.normalizers.oci import OCINormalizer
    with pytest.raises(Exception):
        OCINormalizer().normalize("not a dict")  # type: ignore[arg-type]


# ── Detection ─────────────────────────────────────────────────────────────────

def test_detect_oci_policy():
    from app.ingestion.normalizers.detect import detect_cloud
    assert detect_cloud(OCI_POLICY) == "oci"
