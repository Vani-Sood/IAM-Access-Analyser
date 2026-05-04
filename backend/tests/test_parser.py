import pytest
from pydantic import ValidationError
from app.ingestion.parser import Effect, PolicyDoc, PolicyValidationError, Statement

# ── helpers ──────────────────────────────────────────────────────────────────

def make_stmt(**kwargs) -> dict:
    base = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
    base.update(kwargs)
    return base


def make_policy(statements: list[dict]) -> dict:
    return {"Version": "2012-10-17", "Statement": statements}


# ── PolicyDoc ─────────────────────────────────────────────────────────────────

def test_valid_policy_parses():
    doc = PolicyDoc.model_validate(
        make_policy([make_stmt(Action=["s3:GetObject", "s3:PutObject"])])
    )
    assert len(doc.statement) == 1


def test_version_defaults_to_2012():
    doc = PolicyDoc.model_validate({"Statement": [make_stmt()]})
    assert doc.version == "2012-10-17"


def test_version_custom():
    doc = PolicyDoc.model_validate(
        {"Version": "2008-10-17", "Statement": [make_stmt()]}
    )
    assert doc.version == "2008-10-17"


def test_empty_statement_list_raises():
    with pytest.raises(ValidationError):
        PolicyDoc.model_validate({"Version": "2012-10-17", "Statement": []})


def test_missing_statement_key_raises():
    with pytest.raises(ValidationError):
        PolicyDoc.model_validate({"Version": "2012-10-17"})


def test_multiple_statements():
    doc = PolicyDoc.model_validate(
        make_policy([make_stmt(), make_stmt(Effect="Deny", Action="s3:DeleteObject")])
    )
    assert len(doc.statement) == 2


# ── Effect ────────────────────────────────────────────────────────────────────

def test_effect_allow():
    stmt = Statement.model_validate(make_stmt(Effect="Allow"))
    assert stmt.effect == Effect.ALLOW


def test_effect_deny():
    stmt = Statement.model_validate(make_stmt(Effect="Deny"))
    assert stmt.effect == Effect.DENY


def test_invalid_effect_raises():
    with pytest.raises(ValidationError):
        Statement.model_validate(make_stmt(Effect="grant"))


# ── Action normalisation ──────────────────────────────────────────────────────

def test_action_string_normalised_to_list():
    stmt = Statement.model_validate(make_stmt(Action="s3:GetObject"))
    assert stmt.actions == ["s3:GetObject"]


def test_action_list_preserved():
    stmt = Statement.model_validate(
        make_stmt(Action=["s3:GetObject", "s3:PutObject"])
    )
    assert stmt.actions == ["s3:GetObject", "s3:PutObject"]


def test_action_wildcard_allowed():
    stmt = Statement.model_validate(make_stmt(Action="*"))
    assert stmt.actions == ["*"]


def test_action_service_wildcard_allowed():
    stmt = Statement.model_validate(make_stmt(Action="s3:*"))
    assert stmt.actions == ["s3:*"]


# ── NotAction ─────────────────────────────────────────────────────────────────

def test_not_action_parsed():
    data = {"Effect": "Allow", "NotAction": "iam:CreateUser", "Resource": "*"}
    stmt = Statement.model_validate(data)
    assert stmt.not_actions == ["iam:CreateUser"]
    assert stmt.actions == []


def test_action_and_not_action_together_raises():
    data = {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "NotAction": "iam:CreateUser",
        "Resource": "*",
    }
    with pytest.raises((ValidationError, PolicyValidationError)):
        Statement.model_validate(data)


def test_neither_action_nor_not_action_raises():
    data = {"Effect": "Allow", "Resource": "*"}
    with pytest.raises((ValidationError, PolicyValidationError)):
        Statement.model_validate(data)


# ── Resource ──────────────────────────────────────────────────────────────────

def test_resource_string_normalised():
    stmt = Statement.model_validate(make_stmt(Resource="arn:aws:s3:::bucket/*"))
    assert stmt.resources == ["arn:aws:s3:::bucket/*"]


def test_resource_list_normalised():
    stmt = Statement.model_validate(
        make_stmt(Resource=["arn:aws:s3:::bucket/*", "arn:aws:s3:::other/*"])
    )
    assert len(stmt.resources) == 2


def test_resource_wildcard():
    stmt = Statement.model_validate(make_stmt(Resource="*"))
    assert stmt.resources == ["*"]


# ── Optional fields ───────────────────────────────────────────────────────────

def test_sid_optional():
    stmt = Statement.model_validate(make_stmt(Sid="AllowRead"))
    assert stmt.sid == "AllowRead"


def test_condition_optional():
    stmt = Statement.model_validate(
        make_stmt(
            Condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
        )
    )
    assert stmt.condition is not None
    assert "StringEquals" in stmt.condition


def test_condition_absent_is_none():
    stmt = Statement.model_validate(make_stmt())
    assert stmt.condition is None


# ── Principal ─────────────────────────────────────────────────────────────────

def test_principal_string():
    data = {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "*",
        "Principal": "arn:aws:iam::123456789012:root",
    }
    stmt = Statement.model_validate(data)
    assert stmt.principal == "arn:aws:iam::123456789012:root"


def test_principal_dict():
    data = {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "*",
        "Principal": {"Service": "lambda.amazonaws.com"},
    }
    stmt = Statement.model_validate(data)
    assert stmt.principal == {"Service": "lambda.amazonaws.com"}
