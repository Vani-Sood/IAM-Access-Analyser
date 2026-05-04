import pytest
from app.ingestion.catalog import get_actions_for_service, get_all_actions, service_exists


def test_s3_returns_list():
    actions = get_actions_for_service("s3")
    assert isinstance(actions, list)
    assert len(actions) > 0


def test_s3_actions_prefixed_correctly():
    actions = get_actions_for_service("s3")
    assert all(a.startswith("s3:") for a in actions)


def test_iam_contains_passrole():
    actions = get_actions_for_service("iam")
    assert "iam:PassRole" in actions


def test_iam_contains_createpolicyversion():
    actions = get_actions_for_service("iam")
    assert "iam:CreatePolicyVersion" in actions


def test_sts_contains_assumerole():
    actions = get_actions_for_service("sts")
    assert "sts:AssumeRole" in actions


def test_secretsmanager_returns_actions():
    actions = get_actions_for_service("secretsmanager")
    assert "secretsmanager:GetSecretValue" in actions


def test_kms_returns_actions():
    actions = get_actions_for_service("kms")
    assert "kms:Decrypt" in actions


def test_unknown_service_returns_empty():
    actions = get_actions_for_service("nonexistentservice")
    assert actions == []


def test_service_exists_true():
    assert service_exists("s3") is True
    assert service_exists("iam") is True


def test_service_exists_false():
    assert service_exists("fakesvc") is False


def test_get_all_actions_is_flat_list():
    all_actions = get_all_actions()
    assert isinstance(all_actions, list)
    assert len(all_actions) > 50


def test_get_all_actions_no_duplicates():
    all_actions = get_all_actions()
    assert len(all_actions) == len(set(all_actions))


def test_service_lookup_case_insensitive():
    lower = get_actions_for_service("s3")
    upper = get_actions_for_service("S3")
    assert lower == upper
