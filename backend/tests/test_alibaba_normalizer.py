"""Tests for Alibaba Cloud RAM policy normalizer."""
from __future__ import annotations
import pytest
from app.ingestion.parser import PolicyDoc

ALI_POLICY = {
    "Version": "1",
    "Statement": [
        {"Effect": "Allow", "Action": ["oss:GetObject", "oss:PutObject"], "Resource": ["acs:oss:*:*:mybucket/*"]},
        {"Effect": "Deny",  "Action": ["ram:DeleteUser"],                 "Resource": ["acs:ram:*:*:*"]},
    ],
}

ALI_WILDCARD = {
    "Version": "1",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}

ALI_SINGLE_STRINGS = {
    "Version": "1",
    "Statement": [{"Effect": "Allow", "Action": "ecs:DescribeInstances", "Resource": "acs:ecs:*:*:*"}],
}


# ── Tracer bullet ─────────────────────────────────────────────────────────────

def test_alibaba_normalize_returns_policy_doc():
    from app.ingestion.normalizers.alibaba import AlibabaNormalizer
    result = AlibabaNormalizer().normalize(ALI_POLICY)
    assert isinstance(result, PolicyDoc)


# ── Statement count ───────────────────────────────────────────────────────────

def test_alibaba_statement_count():
    from app.ingestion.normalizers.alibaba import AlibabaNormalizer
    result = AlibabaNormalizer().normalize(ALI_POLICY)
    assert len(result.statement) == 2


# ── Effect mapping ────────────────────────────────────────────────────────────

def test_alibaba_allow_effect():
    from app.ingestion.normalizers.alibaba import AlibabaNormalizer
    result = AlibabaNormalizer().normalize(ALI_POLICY)
    assert result.statement[0].effect.value == "Allow"


def test_alibaba_deny_effect():
    from app.ingestion.normalizers.alibaba import AlibabaNormalizer
    result = AlibabaNormalizer().normalize(ALI_POLICY)
    assert result.statement[1].effect.value == "Deny"


# ── Action mapping ────────────────────────────────────────────────────────────

def test_alibaba_actions_preserved():
    from app.ingestion.normalizers.alibaba import AlibabaNormalizer
    result = AlibabaNormalizer().normalize(ALI_POLICY)
    actions = result.statement[0].actions
    assert "oss:GetObject" in actions
    assert "oss:PutObject" in actions


def test_alibaba_string_action_normalised():
    from app.ingestion.normalizers.alibaba import AlibabaNormalizer
    result = AlibabaNormalizer().normalize(ALI_SINGLE_STRINGS)
    assert "ecs:DescribeInstances" in result.statement[0].actions


def test_alibaba_wildcard_action_preserved():
    from app.ingestion.normalizers.alibaba import AlibabaNormalizer
    result = AlibabaNormalizer().normalize(ALI_WILDCARD)
    assert "*" in result.statement[0].actions


# ── Resource mapping ──────────────────────────────────────────────────────────

def test_alibaba_acs_resource_preserved():
    from app.ingestion.normalizers.alibaba import AlibabaNormalizer
    result = AlibabaNormalizer().normalize(ALI_POLICY)
    resources = result.statement[0].resources
    assert any("acs:" in r for r in resources)


def test_alibaba_string_resource_normalised():
    from app.ingestion.normalizers.alibaba import AlibabaNormalizer
    result = AlibabaNormalizer().normalize(ALI_SINGLE_STRINGS)
    assert result.statement[0].resources


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_alibaba_empty_statement_raises():
    from app.ingestion.normalizers.alibaba import AlibabaNormalizer
    with pytest.raises(Exception):
        AlibabaNormalizer().normalize({"Version": "1", "Statement": []})


def test_alibaba_missing_statement_raises():
    from app.ingestion.normalizers.alibaba import AlibabaNormalizer
    with pytest.raises(Exception):
        AlibabaNormalizer().normalize({"Version": "1"})


def test_alibaba_non_dict_raises():
    from app.ingestion.normalizers.alibaba import AlibabaNormalizer
    with pytest.raises(Exception):
        AlibabaNormalizer().normalize("not a dict")  # type: ignore[arg-type]


# ── Detection ─────────────────────────────────────────────────────────────────

def test_detect_alibaba_by_version_and_acs():
    from app.ingestion.normalizers.detect import detect_cloud
    assert detect_cloud(ALI_POLICY) == "alibaba"


def test_detect_alibaba_acs_resource_no_version():
    from app.ingestion.normalizers.detect import detect_cloud
    policy = {"Statement": [{"Effect": "Allow", "Action": ["oss:Get"], "Resource": ["acs:oss:*:*:*"]}]}
    assert detect_cloud(policy) == "alibaba"
