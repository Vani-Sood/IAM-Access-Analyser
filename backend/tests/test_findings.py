import pytest
from app.ingestion.parser import PolicyDoc
from app.analysis.findings import Finding, Severity, generate_findings

# ── helpers ───────────────────────────────────────────────────────────────────

def make_policy(statements: list[dict]) -> PolicyDoc:
    return PolicyDoc.model_validate(
        {"Version": "2012-10-17", "Statement": statements}
    )


def allow(actions, resource="*", condition=None) -> dict:
    stmt = {"Effect": "Allow", "Action": actions, "Resource": resource}
    if condition:
        stmt["Condition"] = condition
    return stmt


def deny(actions) -> dict:
    return {"Effect": "Deny", "Action": actions, "Resource": "*"}


def rule_ids(findings: list[Finding]) -> set[str]:
    return {f.rule_id for f in findings}


# ── safe policy ───────────────────────────────────────────────────────────────

def test_safe_policy_no_findings():
    p = make_policy([allow("s3:GetObject", resource="arn:aws:s3:::bucket/*")])
    assert generate_findings(p) == []


# ── critical action findings ──────────────────────────────────────────────────

def test_iam_wildcard_finding():
    p = make_policy([allow("iam:*")])
    findings = generate_findings(p)
    assert "IAM_WILDCARD" in rule_ids(findings)


def test_iam_wildcard_is_critical():
    p = make_policy([allow("iam:*")])
    f = next(f for f in generate_findings(p) if f.rule_id == "IAM_WILDCARD")
    assert f.severity == Severity.CRITICAL


def test_full_wildcard_action_finding():
    p = make_policy([allow("*")])
    assert "FULL_WILDCARD_ACTION" in rule_ids(generate_findings(p))


def test_full_wildcard_is_critical():
    p = make_policy([allow("*")])
    f = next(f for f in generate_findings(p) if f.rule_id == "FULL_WILDCARD_ACTION")
    assert f.severity == Severity.CRITICAL


# ── high severity action findings ─────────────────────────────────────────────

def test_passrole_finding():
    p = make_policy([allow("iam:PassRole")])
    assert "IAM_PASS_ROLE" in rule_ids(generate_findings(p))


def test_passrole_is_high():
    p = make_policy([allow("iam:PassRole")])
    f = next(f for f in generate_findings(p) if f.rule_id == "IAM_PASS_ROLE")
    assert f.severity == Severity.HIGH


def test_create_policy_version_finding():
    p = make_policy([allow("iam:CreatePolicyVersion")])
    assert "IAM_CREATE_POLICY_VERSION" in rule_ids(generate_findings(p))


def test_secrets_manager_finding():
    p = make_policy([allow("secretsmanager:GetSecretValue")])
    assert "SECRETS_MANAGER_READ" in rule_ids(generate_findings(p))


def test_kms_decrypt_finding():
    p = make_policy([allow("kms:Decrypt")])
    assert "KMS_DECRYPT" in rule_ids(generate_findings(p))


def test_sts_assumerole_finding():
    p = make_policy([allow("sts:AssumeRole")])
    assert "STS_ASSUME_ROLE" in rule_ids(generate_findings(p))


# ── wildcard resource ─────────────────────────────────────────────────────────

def test_wildcard_resource_finding():
    p = make_policy([allow("s3:GetObject", resource="*")])
    assert "WILDCARD_RESOURCE" in rule_ids(generate_findings(p))


def test_specific_resource_no_wildcard_finding():
    p = make_policy([allow("s3:GetObject", resource="arn:aws:s3:::bucket/*")])
    assert "WILDCARD_RESOURCE" not in rule_ids(generate_findings(p))


# ── NotAction ─────────────────────────────────────────────────────────────────

def test_not_action_finding():
    p = make_policy([{"Effect": "Allow", "NotAction": "iam:CreateUser", "Resource": "*"}])
    assert "NOT_ACTION_USAGE" in rule_ids(generate_findings(p))


def test_not_action_is_medium():
    p = make_policy([{"Effect": "Allow", "NotAction": "iam:CreateUser", "Resource": "*"}])
    f = next(f for f in generate_findings(p) if f.rule_id == "NOT_ACTION_USAGE")
    assert f.severity == Severity.MEDIUM


# ── MFA condition ─────────────────────────────────────────────────────────────

def test_missing_mfa_condition_for_passrole():
    p = make_policy([allow("iam:PassRole")])
    assert "MISSING_MFA_CONDITION" in rule_ids(generate_findings(p))


def test_mfa_condition_present_suppresses_finding():
    mfa_condition = {
        "Bool": {"aws:MultiFactorAuthPresent": "true"}
    }
    p = make_policy([allow("iam:PassRole", condition=mfa_condition)])
    assert "MISSING_MFA_CONDITION" not in rule_ids(generate_findings(p))


def test_safe_action_no_mfa_finding():
    p = make_policy([allow("s3:GetObject")])
    assert "MISSING_MFA_CONDITION" not in rule_ids(generate_findings(p))


# ── Deny statements ───────────────────────────────────────────────────────────

def test_deny_action_no_action_finding():
    p = make_policy([deny("iam:PassRole")])
    assert "IAM_PASS_ROLE" not in rule_ids(generate_findings(p))


def test_deny_with_notaction_still_flagged():
    p = make_policy([{"Effect": "Deny", "NotAction": "s3:GetObject", "Resource": "*"}])
    assert "NOT_ACTION_USAGE" in rule_ids(generate_findings(p))


# ── statement index ───────────────────────────────────────────────────────────

def test_finding_references_correct_statement_idx():
    p = make_policy([
        allow("s3:GetObject", resource="arn:aws:s3:::bucket/*"),
        allow("iam:PassRole"),
    ])
    findings = generate_findings(p)
    passrole_f = next(f for f in findings if f.rule_id == "IAM_PASS_ROLE")
    assert passrole_f.statement_idx == 1


# ── multiple findings ─────────────────────────────────────────────────────────

def test_multiple_findings_same_statement():
    p = make_policy([allow(["iam:PassRole", "secretsmanager:GetSecretValue"])])
    rids = rule_ids(generate_findings(p))
    assert "IAM_PASS_ROLE" in rids
    assert "SECRETS_MANAGER_READ" in rids


def test_finding_has_message():
    p = make_policy([allow("iam:PassRole")])
    f = next(f for f in generate_findings(p) if f.rule_id == "IAM_PASS_ROLE")
    assert len(f.message) > 10
