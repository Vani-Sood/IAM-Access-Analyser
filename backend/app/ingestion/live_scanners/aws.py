"""AWS live IAM scanner — wraps boto3 STS assume-role logic."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3

from app.ingestion.live_scanners._types import ScanTarget
from app.ingestion.parser import PolicyDoc, Statement

# AWS-managed policies (arn:aws:iam::aws:policy/*) are not customer-configured
# — skip them. Fetching SecurityAudit alone is 350KB+ and takes minutes.
_AWS_MANAGED_PREFIX = "arn:aws:iam::aws:policy/"

# Service-linked roles are auto-managed by AWS — not relevant for audit.
_SERVICE_LINKED_PATH = "/aws-service-role/"


def _is_aws_managed(policy_arn: str) -> bool:
    return policy_arn.startswith(_AWS_MANAGED_PREFIX)


def _parse_policy_document(policy_doc_str: str) -> list[dict]:
    try:
        doc = json.loads(policy_doc_str)
    except (json.JSONDecodeError, TypeError):
        return []
    return doc.get("Statement", [])


def _get_customer_managed_policy_statements(iam, policy_arn: str) -> list[dict]:
    if _is_aws_managed(policy_arn):
        return []
    try:
        policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
        version_id = policy["DefaultVersionId"]
        version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        doc = version["PolicyVersion"]["Document"]
        if isinstance(doc, str):
            doc = json.loads(doc)
        return doc.get("Statement", [])
    except Exception:
        return []


def _collect_user_statements(iam, username: str) -> list[dict]:
    """Users: include ALL attached policies (AWS-managed too — SecurityAudit etc. matter for audit)."""
    stmts: list[dict] = []
    for ip in iam.get_paginator("list_user_policies").paginate(UserName=username):
        for policy_name in ip["PolicyNames"]:
            doc = iam.get_user_policy(UserName=username, PolicyName=policy_name)[
                "PolicyDocument"
            ]
            stmts.extend(
                _parse_policy_document(doc) if isinstance(doc, str)
                else doc.get("Statement", [])
            )
    for mp in iam.get_paginator("list_attached_user_policies").paginate(UserName=username):
        for policy in mp["AttachedPolicies"]:
            # Users: fetch ALL managed policies (AWS-managed too).
            # SecurityAudit/ReadOnlyAccess etc. define real permissions the user holds.
            stmts.extend(_get_all_managed_policy_statements(iam, policy["PolicyArn"]))
    return stmts


def _get_all_managed_policy_statements(iam, policy_arn: str) -> list[dict]:
    """Fetch managed policy document regardless of whether it is AWS-managed."""
    try:
        policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
        version_id = policy["DefaultVersionId"]
        version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        doc = version["PolicyVersion"]["Document"]
        if isinstance(doc, str):
            doc = json.loads(doc)
        return doc.get("Statement", [])
    except Exception:
        return []


def _collect_role_statements(iam, role: dict) -> list[dict]:
    """Roles: skip service-linked (AWS-managed) and skip AWS-managed policy docs.

    Service-linked roles are auto-managed by AWS — not user-defined.
    AWS-managed policies on roles (e.g. AmazonEC2ReadOnlyAccess on a lambda role)
    are not user-configured; skipping them keeps scan fast without losing signal.
    """
    if role.get("Path", "").startswith(_SERVICE_LINKED_PATH):
        return []
    rolename = role["RoleName"]
    stmts: list[dict] = []
    for ip in iam.get_paginator("list_role_policies").paginate(RoleName=rolename):
        for policy_name in ip["PolicyNames"]:
            doc = iam.get_role_policy(RoleName=rolename, PolicyName=policy_name)[
                "PolicyDocument"
            ]
            stmts.extend(
                _parse_policy_document(doc) if isinstance(doc, str)
                else doc.get("Statement", [])
            )
    for mp in iam.get_paginator("list_attached_role_policies").paginate(RoleName=rolename):
        for policy in mp["AttachedPolicies"]:
            stmts.extend(
                _get_customer_managed_policy_statements(iam, policy["PolicyArn"])
            )
    return stmts


def _scan_with_iam(iam) -> PolicyDoc:
    users = [
        u
        for page in iam.get_paginator("list_users").paginate()
        for u in page["Users"]
    ]
    roles = [
        r
        for page in iam.get_paginator("list_roles").paginate()
        for r in page["Roles"]
    ]

    raw_statements: list[dict] = []
    futures = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        for u in users:
            futures.append(pool.submit(_collect_user_statements, iam, u["UserName"]))
        for r in roles:
            futures.append(pool.submit(_collect_role_statements, iam, r))
        for f in as_completed(futures):
            try:
                raw_statements.extend(f.result())
            except Exception:
                pass

    if not raw_statements:
        return PolicyDoc(
            statement=[Statement(effect="Deny", action=["*"], resource="*")]
        )
    return PolicyDoc(statement=[Statement.model_validate(s) for s in raw_statements])


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
    return _scan_with_iam(session.client("iam"))


def _scan_direct() -> PolicyDoc:
    """Scan using the default boto3 credential chain (env vars / instance role).

    Used when no role_arn is supplied — the IAM user whose keys are configured
    must have SecurityAudit (or equivalent read-only IAM) attached.
    """
    return _scan_with_iam(boto3.client("iam"))


class AwsScanner:
    """Implements the Scanner protocol for AWS IAM.

    Two modes:
      * role_arn set  → sts:AssumeRole into target role, scan with temp creds
      * role_arn None → scan directly with configured IAM user (SecurityAudit)
    """

    def scan(self, target: ScanTarget) -> PolicyDoc:
        if target.role_arn:
            return _scan_role_arn(target.role_arn)
        return _scan_direct()


def scan_live(role_arn: str | None = None) -> PolicyDoc:
    """Convenience wrapper — preserves existing call-site API."""
    return AwsScanner().scan(ScanTarget(cloud="aws", role_arn=role_arn))
