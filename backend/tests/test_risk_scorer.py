import pytest
from app.ingestion.parser import PolicyDoc
from app.analysis.risk_scorer import score_policy, get_severity
from app.analysis.findings import Severity

# ── helpers ───────────────────────────────────────────────────────────────────

def make_policy(statements: list[dict]) -> PolicyDoc:
    return PolicyDoc.model_validate(
        {"Version": "2012-10-17", "Statement": statements}
    )


def allow(actions, resource="arn:aws:s3:::bucket/*", condition=None) -> dict:
    stmt = {"Effect": "Allow", "Action": actions, "Resource": resource}
    if condition:
        stmt["Condition"] = condition
    return stmt


def deny(actions, resource="*") -> dict:
    return {"Effect": "Deny", "Action": actions, "Resource": resource}


# ── safe policies ─────────────────────────────────────────────────────────────

def test_safe_readonly_s3_low_score():
    p = make_policy([allow(["s3:GetObject", "s3:ListBucket"])])
    assert score_policy(p) < 4.0


def test_safe_policy_severity_low():
    p = make_policy([allow(["s3:GetObject"])])
    assert get_severity(score_policy(p)) == Severity.LOW


# ── dangerous actions ─────────────────────────────────────────────────────────

def test_iam_passrole_critical_score():
    p = make_policy([allow("iam:PassRole", resource="*")])
    assert score_policy(p) >= 8.0


def test_iam_wildcard_max_score():
    p = make_policy([allow("iam:*", resource="*")])
    assert score_policy(p) == 10.0


def test_sts_assumerole_high():
    p = make_policy([allow("sts:AssumeRole", resource="*")])
    assert score_policy(p) >= 8.0


def test_secrets_manager_high():
    p = make_policy([allow("secretsmanager:GetSecretValue", resource="*")])
    assert score_policy(p) >= 6.0


def test_kms_decrypt_high():
    p = make_policy([allow("kms:Decrypt", resource="*")])
    assert score_policy(p) >= 6.0


# ── Deny not scored ───────────────────────────────────────────────────────────

def test_deny_only_policy_score_zero():
    p = make_policy([deny("iam:PassRole")])
    assert score_policy(p) == 0.0


def test_deny_not_added_to_allow_score():
    p = make_policy([
        allow("s3:GetObject"),
        deny("iam:PassRole"),
    ])
    # Only s3:GetObject counted (1.0)
    assert score_policy(p) < 4.0


# ── wildcard resource multiplier ──────────────────────────────────────────────

def test_wildcard_resource_multiplies_score():
    p_specific = make_policy([allow("s3:GetObject", resource="arn:aws:s3:::bucket/*")])
    p_wildcard = make_policy([allow("s3:GetObject", resource="*")])
    assert score_policy(p_wildcard) > score_policy(p_specific)


def test_wildcard_resource_applies_1_5x():
    p = make_policy([allow("s3:GetObject", resource="*")])
    # s3:GetObject weight = 1.0, * 1.5 = 1.5
    assert score_policy(p) == pytest.approx(1.5, rel=1e-3)


# ── NotAction penalty ─────────────────────────────────────────────────────────

def test_notaction_adds_penalty():
    p_action = make_policy([allow("s3:GetObject")])
    p_notaction = make_policy([{"Effect": "Allow", "NotAction": "s3:DeleteObject", "Resource": "*"}])
    assert score_policy(p_notaction) > score_policy(p_action)


# ── score cap ─────────────────────────────────────────────────────────────────

def test_score_capped_at_10():
    p = make_policy([
        allow(["iam:*", "iam:PassRole", "sts:AssumeRole", "secretsmanager:GetSecretValue"], resource="*")
    ])
    assert score_policy(p) == 10.0


# ── severity mapping ──────────────────────────────────────────────────────────

def test_severity_critical_at_8():
    assert get_severity(8.0) == Severity.CRITICAL


def test_severity_critical_above_8():
    assert get_severity(9.5) == Severity.CRITICAL


def test_severity_high_at_6():
    assert get_severity(6.0) == Severity.HIGH


def test_severity_high_below_8():
    assert get_severity(7.9) == Severity.HIGH


def test_severity_medium_at_4():
    assert get_severity(4.0) == Severity.MEDIUM


def test_severity_medium_below_6():
    assert get_severity(5.9) == Severity.MEDIUM


def test_severity_low_below_4():
    assert get_severity(3.9) == Severity.LOW


def test_severity_low_at_zero():
    assert get_severity(0.0) == Severity.LOW


# ── multiple statements ───────────────────────────────────────────────────────

def test_multiple_allow_statements_accumulate():
    p = make_policy([
        allow("iam:PassRole", resource="*"),
        allow("secretsmanager:GetSecretValue", resource="*"),
    ])
    assert score_policy(p) == 10.0
