"""AWS live IAM scanner — wraps boto3 STS assume-role logic."""
from __future__ import annotations

import json

import boto3

from app.ingestion.live_scanners._types import ScanTarget
from app.ingestion.parser import PolicyDoc, Statement


def _parse_policy_document(policy_doc_str: str) -> list[dict]:
    try:
        doc = json.loads(policy_doc_str)
    except (json.JSONDecodeError, TypeError):
        return []
    return doc.get("Statement", [])


def _get_managed_policy_statements(iam, policy_arn: str) -> list[dict]:
    try:
        policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
        version_id = policy["DefaultVersionId"]
        version = iam.get_policy_version(
            PolicyArn=policy_arn, VersionId=version_id
        )
        doc = version["PolicyVersion"]["Document"]
        if isinstance(doc, str):
            doc = json.loads(doc)
        return doc.get("Statement", [])
    except Exception:
        return []


def _scan_role_arn(role_arn: str) -> PolicyDoc:
    sts = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="iam-analyzer-scan",
        DurationSeconds=3600,
    )["Credentials"]

    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    iam = session.client("iam")
    raw_statements: list[dict] = []

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            for ip in iam.get_paginator("list_user_policies").paginate(UserName=username):
                for policy_name in ip["PolicyNames"]:
                    doc = iam.get_user_policy(
                        UserName=username, PolicyName=policy_name
                    )["PolicyDocument"]
                    if isinstance(doc, str):
                        raw_statements.extend(_parse_policy_document(doc))
                    else:
                        raw_statements.extend(doc.get("Statement", []))
            for mp in iam.get_paginator("list_attached_user_policies").paginate(UserName=username):
                for policy in mp["AttachedPolicies"]:
                    raw_statements.extend(
                        _get_managed_policy_statements(iam, policy["PolicyArn"])
                    )

    for page in iam.get_paginator("list_roles").paginate():
        for role in page["Roles"]:
            rolename = role["RoleName"]
            for ip in iam.get_paginator("list_role_policies").paginate(RoleName=rolename):
                for policy_name in ip["PolicyNames"]:
                    doc = iam.get_role_policy(
                        RoleName=rolename, PolicyName=policy_name
                    )["PolicyDocument"]
                    if isinstance(doc, str):
                        raw_statements.extend(_parse_policy_document(doc))
                    else:
                        raw_statements.extend(doc.get("Statement", []))
            for mp in iam.get_paginator("list_attached_role_policies").paginate(RoleName=rolename):
                for policy in mp["AttachedPolicies"]:
                    raw_statements.extend(
                        _get_managed_policy_statements(iam, policy["PolicyArn"])
                    )

    if not raw_statements:
        return PolicyDoc(
            statement=[Statement(effect="Deny", action=["*"], resource="*")]
        )
    return PolicyDoc(statement=[Statement.model_validate(s) for s in raw_statements])


class AwsScanner:
    """Implements the Scanner protocol for AWS IAM via STS assume-role."""

    def scan(self, target: ScanTarget) -> PolicyDoc:
        if not target.role_arn:
            raise ValueError("AwsScanner requires target.role_arn")
        return _scan_role_arn(target.role_arn)


def scan_live(role_arn: str) -> PolicyDoc:
    """Convenience wrapper — preserves existing call-site API."""
    return AwsScanner().scan(ScanTarget(cloud="aws", role_arn=role_arn))
