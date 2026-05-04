from __future__ import annotations

from app.analysis.findings import Severity
from app.ingestion.parser import Effect, PolicyDoc

_RISK_WEIGHTS: dict[str, float] = {
    "iam:*":                           10.0,
    "*":                               10.0,
    "iam:PassRole":                     9.5,
    "iam:CreatePolicyVersion":          9.0,
    "iam:AttachRolePolicy":             9.0,
    "iam:PutRolePolicy":                9.0,
    "sts:AssumeRole":                   8.5,
    "secretsmanager:GetSecretValue":    8.0,
    "kms:Decrypt":                      7.5,
    "ec2:*":                            7.0,
    "cloudformation:*":                 7.0,
    "s3:*":                             6.5,
    "lambda:InvokeFunction":            6.0,
}

_WILDCARD_RESOURCE_MULTIPLIER: float = 1.5
_NOTACTION_PENALTY: float = 2.0
_DEFAULT_ACTION_WEIGHT: float = 1.0


def score_policy(policy: PolicyDoc) -> float:
    base: float = 0.0
    has_wildcard_resource = False
    has_notaction = False

    for stmt in policy.statement:
        if stmt.not_action is not None:
            has_notaction = True

        if stmt.effect != Effect.ALLOW:
            continue

        for action in stmt.actions:
            base += _RISK_WEIGHTS.get(action, _DEFAULT_ACTION_WEIGHT)

        if "*" in stmt.resources:
            has_wildcard_resource = True

    if has_wildcard_resource:
        base *= _WILDCARD_RESOURCE_MULTIPLIER

    if has_notaction:
        base += _NOTACTION_PENALTY

    return min(round(base, 10), 10.0)


def get_severity(score: float) -> Severity:
    if score >= 8.0:
        return Severity.CRITICAL
    if score >= 6.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW
