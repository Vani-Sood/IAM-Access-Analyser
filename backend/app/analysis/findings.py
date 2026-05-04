from __future__ import annotations

from enum import Enum

from pydantic import BaseModel

from app.ingestion.parser import Effect, PolicyDoc


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    message: str
    statement_idx: int


_DANGEROUS_ACTIONS: dict[str, tuple[str, Severity, str]] = {
    "iam:*": (
        "IAM_WILDCARD",
        Severity.CRITICAL,
        "Full IAM wildcard grants complete privilege escalation capability",
    ),
    "*": (
        "FULL_WILDCARD_ACTION",
        Severity.CRITICAL,
        "Wildcard action (*) grants every permission across all services",
    ),
    "iam:PassRole": (
        "IAM_PASS_ROLE",
        Severity.HIGH,
        "iam:PassRole enables privilege escalation by assigning roles to services",
    ),
    "iam:CreatePolicyVersion": (
        "IAM_CREATE_POLICY_VERSION",
        Severity.HIGH,
        "iam:CreatePolicyVersion enables replacing policy content for escalation",
    ),
    "iam:AttachRolePolicy": (
        "IAM_ATTACH_ROLE_POLICY",
        Severity.HIGH,
        "iam:AttachRolePolicy enables attaching arbitrary managed policies to roles",
    ),
    "iam:PutRolePolicy": (
        "IAM_PUT_ROLE_POLICY",
        Severity.HIGH,
        "iam:PutRolePolicy enables injecting inline policies into roles",
    ),
    "sts:AssumeRole": (
        "STS_ASSUME_ROLE",
        Severity.HIGH,
        "sts:AssumeRole without conditions enables unrestricted role assumption",
    ),
    "secretsmanager:GetSecretValue": (
        "SECRETS_MANAGER_READ",
        Severity.HIGH,
        "secretsmanager:GetSecretValue exposes stored secrets and credentials",
    ),
    "kms:Decrypt": (
        "KMS_DECRYPT",
        Severity.HIGH,
        "kms:Decrypt enables decryption of KMS-protected data at rest",
    ),
    "ec2:*": (
        "EC2_WILDCARD",
        Severity.HIGH,
        "EC2 wildcard grants full compute control including instance metadata access",
    ),
    "cloudformation:*": (
        "CF_WILDCARD",
        Severity.HIGH,
        "CloudFormation wildcard enables infrastructure-level privilege escalation",
    ),
    "s3:*": (
        "S3_WILDCARD",
        Severity.MEDIUM,
        "S3 wildcard grants full bucket control including data exfiltration",
    ),
    "lambda:InvokeFunction": (
        "LAMBDA_INVOKE",
        Severity.MEDIUM,
        "lambda:InvokeFunction enables arbitrary code execution",
    ),
}

_MFA_SENSITIVE: frozenset[str] = frozenset({
    "iam:*",
    "iam:PassRole",
    "iam:CreatePolicyVersion",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "sts:AssumeRole",
    "secretsmanager:GetSecretValue",
})


def _has_mfa_condition(condition: dict | None) -> bool:
    if condition is None:
        return False
    return "aws:MultiFactorAuthPresent" in condition.get("Bool", {})


def generate_findings(policy: PolicyDoc) -> list[Finding]:
    findings: list[Finding] = []

    for idx, stmt in enumerate(policy.statement):
        if stmt.not_action is not None:
            findings.append(Finding(
                rule_id="NOT_ACTION_USAGE",
                severity=Severity.MEDIUM,
                message="NotAction inverts permission logic; grants all actions except listed ones",
                statement_idx=idx,
            ))

        if stmt.effect != Effect.ALLOW:
            continue

        seen_rule_ids: set[str] = set()
        for action in stmt.actions:
            if action not in _DANGEROUS_ACTIONS:
                continue
            rule_id, severity, message = _DANGEROUS_ACTIONS[action]
            if rule_id in seen_rule_ids:
                continue
            seen_rule_ids.add(rule_id)
            findings.append(Finding(
                rule_id=rule_id,
                severity=severity,
                message=message,
                statement_idx=idx,
            ))

        if "*" in stmt.resources:
            findings.append(Finding(
                rule_id="WILDCARD_RESOURCE",
                severity=Severity.MEDIUM,
                message="Resource wildcard (*) grants access to every resource of the specified type",
                statement_idx=idx,
            ))

        has_sensitive = any(a in _MFA_SENSITIVE for a in stmt.actions)
        if has_sensitive and not _has_mfa_condition(stmt.condition):
            findings.append(Finding(
                rule_id="MISSING_MFA_CONDITION",
                severity=Severity.MEDIUM,
                message="Sensitive actions lack aws:MultiFactorAuthPresent condition",
                statement_idx=idx,
            ))

    return findings
