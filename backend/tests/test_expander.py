import pytest
from app.ingestion.parser import PolicyDoc
from app.ingestion.expander import expand_wildcards

# ── helpers ───────────────────────────────────────────────────────────────────

def make_policy(statements: list[dict]) -> PolicyDoc:
    return PolicyDoc.model_validate(
        {"Version": "2012-10-17", "Statement": statements}
    )


def actions_of(policy: PolicyDoc, idx: int = 0) -> list[str]:
    return policy.statement[idx].actions


# ── exact actions (no wildcard) ───────────────────────────────────────────────

def test_exact_action_passthrough():
    p = make_policy([{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}])
    result = expand_wildcards(p)
    assert actions_of(result) == ["s3:GetObject"]


def test_exact_action_list_passthrough():
    p = make_policy([
        {"Effect": "Allow", "Action": ["s3:GetObject", "iam:PassRole"], "Resource": "*"}
    ])
    result = expand_wildcards(p)
    assert "s3:GetObject" in actions_of(result)
    assert "iam:PassRole" in actions_of(result)


# ── service wildcard (service:*) ──────────────────────────────────────────────

def test_s3_service_wildcard_expands():
    p = make_policy([{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}])
    result = expand_wildcards(p)
    expanded = actions_of(result)
    assert "s3:GetObject" in expanded
    assert "s3:PutObject" in expanded
    assert "s3:DeleteObject" in expanded
    assert "s3:*" not in expanded


def test_iam_service_wildcard_expands():
    p = make_policy([{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}])
    result = expand_wildcards(p)
    expanded = actions_of(result)
    assert "iam:PassRole" in expanded
    assert "iam:CreatePolicyVersion" in expanded
    assert "iam:*" not in expanded


def test_service_wildcard_all_prefixed_correctly():
    p = make_policy([{"Effect": "Allow", "Action": "kms:*", "Resource": "*"}])
    result = expand_wildcards(p)
    assert all(a.startswith("kms:") for a in actions_of(result))


# ── prefix wildcard (service:Prefix*) ─────────────────────────────────────────

def test_prefix_wildcard_s3_get():
    p = make_policy([{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}])
    result = expand_wildcards(p)
    expanded = actions_of(result)
    assert "s3:GetObject" in expanded
    assert "s3:GetBucketPolicy" in expanded
    assert "s3:PutObject" not in expanded
    assert "s3:Get*" not in expanded


def test_prefix_wildcard_iam_list():
    p = make_policy([{"Effect": "Allow", "Action": "iam:List*", "Resource": "*"}])
    result = expand_wildcards(p)
    expanded = actions_of(result)
    assert all(a.startswith("iam:List") for a in expanded)
    assert "iam:PassRole" not in expanded


def test_prefix_wildcard_no_match_returns_empty_for_that_action():
    p = make_policy([{"Effect": "Allow", "Action": "s3:Nonexistent*", "Resource": "*"}])
    result = expand_wildcards(p)
    assert actions_of(result) == []


# ── full wildcard (*) ─────────────────────────────────────────────────────────

def test_full_wildcard_expands_to_all_catalog():
    p = make_policy([{"Effect": "Allow", "Action": "*", "Resource": "*"}])
    result = expand_wildcards(p)
    expanded = actions_of(result)
    assert len(expanded) > 50
    assert "*" not in expanded
    assert "s3:GetObject" in expanded
    assert "iam:PassRole" in expanded


# ── mixed list ────────────────────────────────────────────────────────────────

def test_mixed_wildcard_and_exact():
    p = make_policy([
        {"Effect": "Allow", "Action": ["s3:*", "iam:PassRole"], "Resource": "*"}
    ])
    result = expand_wildcards(p)
    expanded = actions_of(result)
    assert "s3:GetObject" in expanded
    assert "iam:PassRole" in expanded
    assert "s3:*" not in expanded


def test_no_duplicates_in_output():
    p = make_policy([
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObject"], "Resource": "*"}
    ])
    result = expand_wildcards(p)
    expanded = actions_of(result)
    assert len(expanded) == len(set(expanded))


# ── no wildcards in output guarantee ─────────────────────────────────────────

def test_no_wildcards_remain_in_output():
    p = make_policy([
        {"Effect": "Allow", "Action": ["s3:*", "iam:*", "kms:*"], "Resource": "*"}
    ])
    result = expand_wildcards(p)
    assert not any("*" in a for a in actions_of(result))


# ── Deny + NotAction ─────────────────────────────────────────────────────────

def test_deny_statement_expanded():
    p = make_policy([{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}])
    result = expand_wildcards(p)
    expanded = actions_of(result)
    assert "s3:DeleteObject" in expanded
    assert result.statement[0].effect.value == "Deny"


def test_not_action_expanded():
    p = make_policy([{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}])
    result = expand_wildcards(p)
    not_actions = result.statement[0].not_actions
    assert "iam:PassRole" in not_actions
    assert "iam:*" not in not_actions


# ── immutability ──────────────────────────────────────────────────────────────

def test_original_policy_not_mutated():
    p = make_policy([{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}])
    original_action = p.statement[0].action
    expand_wildcards(p)
    assert p.statement[0].action == original_action


# ── multi-statement ───────────────────────────────────────────────────────────

def test_multiple_statements_all_expanded():
    p = make_policy([
        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
    ])
    result = expand_wildcards(p)
    assert "s3:GetObject" in actions_of(result, 0)
    assert actions_of(result, 1) == ["iam:PassRole"]


# ── unknown service ───────────────────────────────────────────────────────────

def test_unknown_service_wildcard_empty():
    p = make_policy([{"Effect": "Allow", "Action": "fakesvc:*", "Resource": "*"}])
    result = expand_wildcards(p)
    assert actions_of(result) == []
