"""Tests for live boto3 scanning via moto — Batch 12."""
from __future__ import annotations

import json

import boto3
import pytest
from moto import mock_aws

from app.ingestion.live_scanners.aws import scan_live
from app.ingestion.parser import PolicyDoc

TEST_ROLE_ARN = "arn:aws:iam::123456789012:role/AnalyzerRole"

INLINE_POLICY_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::my-bucket/*",
            }
        ],
    }
)


# ---------------------------------------------------------------------------
# autouse fixture: fake AWS credentials
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


# ---------------------------------------------------------------------------
# 1. Import / basic contract
# ---------------------------------------------------------------------------

def test_scan_live_importable():
    from app.ingestion.live_scanners.aws import scan_live  # noqa: F401
    assert scan_live is not None


@mock_aws
def test_scan_live_returns_policy_doc():
    """scan_live must return a PolicyDoc instance."""
    iam = boto3.client("iam", region_name="us-east-1")
    sts = boto3.client("sts", region_name="us-east-1")

    # Create a role so assume_role works
    iam.create_role(
        RoleName="AnalyzerRole",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )

    result = scan_live(TEST_ROLE_ARN)
    assert isinstance(result, PolicyDoc)


# ---------------------------------------------------------------------------
# 2. Inline user policy harvesting
# ---------------------------------------------------------------------------

@mock_aws
def test_inline_user_policy_included():
    """Inline policies on IAM users must appear in the result."""
    iam = boto3.client("iam", region_name="us-east-1")

    iam.create_role(
        RoleName="AnalyzerRole",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )
    iam.create_user(UserName="alice")
    iam.put_user_policy(
        UserName="alice",
        PolicyName="AliceInlinePolicy",
        PolicyDocument=INLINE_POLICY_DOC,
    )

    result = scan_live(TEST_ROLE_ARN)
    all_actions = [a for stmt in result.statement for a in stmt.actions]
    assert "s3:GetObject" in all_actions


# ---------------------------------------------------------------------------
# 3. Managed user policy harvesting
# ---------------------------------------------------------------------------

@mock_aws
def test_managed_user_policy_included():
    """Managed policies attached to IAM users must appear in the result."""
    iam = boto3.client("iam", region_name="us-east-1")

    iam.create_role(
        RoleName="AnalyzerRole",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )
    iam.create_user(UserName="bob")
    managed_policy = iam.create_policy(
        PolicyName="BobManagedPolicy",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["ec2:DescribeInstances"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    iam.attach_user_policy(
        UserName="bob",
        PolicyArn=managed_policy["Policy"]["Arn"],
    )

    result = scan_live(TEST_ROLE_ARN)
    all_actions = [a for stmt in result.statement for a in stmt.actions]
    assert "ec2:DescribeInstances" in all_actions


# ---------------------------------------------------------------------------
# 4. Inline role policy harvesting
# ---------------------------------------------------------------------------

@mock_aws
def test_inline_role_policy_included():
    """Inline policies on IAM roles must appear in the result."""
    iam = boto3.client("iam", region_name="us-east-1")

    iam.create_role(
        RoleName="AnalyzerRole",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )
    iam.put_role_policy(
        RoleName="AnalyzerRole",
        PolicyName="RoleInlinePolicy",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["iam:ListRoles"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )

    result = scan_live(TEST_ROLE_ARN)
    all_actions = [a for stmt in result.statement for a in stmt.actions]
    assert "iam:ListRoles" in all_actions


# ---------------------------------------------------------------------------
# 5. Managed role policy harvesting
# ---------------------------------------------------------------------------

@mock_aws
def test_managed_role_policy_included():
    """Managed policies attached to IAM roles must appear in the result."""
    iam = boto3.client("iam", region_name="us-east-1")

    role = iam.create_role(
        RoleName="AnalyzerRole",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )
    managed_policy = iam.create_policy(
        PolicyName="RoleManagedPolicy",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["lambda:InvokeFunction"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    iam.attach_role_policy(
        RoleName="AnalyzerRole",
        PolicyArn=managed_policy["Policy"]["Arn"],
    )

    result = scan_live(TEST_ROLE_ARN)
    all_actions = [a for stmt in result.statement for a in stmt.actions]
    assert "lambda:InvokeFunction" in all_actions


# ---------------------------------------------------------------------------
# 6. Empty account — deny-all fallback
# ---------------------------------------------------------------------------

@mock_aws
def test_empty_account_returns_deny_all_fallback():
    """When no statements found, return deny-all PolicyDoc."""
    iam = boto3.client("iam", region_name="us-east-1")

    iam.create_role(
        RoleName="AnalyzerRole",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )

    result = scan_live(TEST_ROLE_ARN)
    assert len(result.statement) == 1
    stmt = result.statement[0]
    assert stmt.effect.value == "Deny"
    assert stmt.action == ["*"] or stmt.action == "*"
    assert stmt.resource == "*"


# ---------------------------------------------------------------------------
# 7. Mixed users and roles
# ---------------------------------------------------------------------------

@mock_aws
def test_multiple_entities_statements_combined():
    """Statements from multiple users and roles are all included."""
    iam = boto3.client("iam", region_name="us-east-1")

    iam.create_role(
        RoleName="AnalyzerRole",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )

    # User with inline policy
    iam.create_user(UserName="carol")
    iam.put_user_policy(
        UserName="carol",
        PolicyName="CarolPolicy",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": "*"}
                ],
            }
        ),
    )

    # Role with inline policy (not the scanner role, a different one)
    iam.create_role(
        RoleName="WorkerRole",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )
    iam.put_role_policy(
        RoleName="WorkerRole",
        PolicyName="WorkerPolicy",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["sns:Publish"], "Resource": "*"}
                ],
            }
        ),
    )

    result = scan_live(TEST_ROLE_ARN)
    all_actions = [a for stmt in result.statement for a in stmt.actions]
    assert "sqs:SendMessage" in all_actions
    assert "sns:Publish" in all_actions


# ---------------------------------------------------------------------------
# 8. Analyze endpoint — mode=live integration
# ---------------------------------------------------------------------------

def test_analyze_endpoint_live_mode_importable():
    """AnalyzeRequest model supports mode='live'."""
    from app.api.v1.analyze import AnalyzeRequest
    req = AnalyzeRequest(mode="live", role_arn=TEST_ROLE_ARN)
    assert req.mode == "live"
    assert req.role_arn == TEST_ROLE_ARN


def test_analyze_request_json_mode_requires_policy():
    from pydantic import ValidationError
    from app.api.v1.analyze import AnalyzeRequest
    with pytest.raises(ValidationError):
        AnalyzeRequest(mode="json", policy=None)


def test_analyze_request_live_mode_role_arn_optional():
    """role_arn is optional: omitted → direct single-account scan via env-var creds."""
    from app.api.v1.analyze import AnalyzeRequest
    req = AnalyzeRequest(mode="live", cloud="aws", role_arn=None)
    assert req.role_arn is None
    assert req.mode == "live"
    assert req.cloud == "aws"
