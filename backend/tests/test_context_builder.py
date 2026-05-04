import json
import pytest
from app.ingestion.parser import PolicyDoc
from app.analysis.findings import generate_findings
from app.ai.context_builder import build_suggestion_prompt

# ── helpers ───────────────────────────────────────────────────────────────────

def make_policy(actions, resource="*") -> PolicyDoc:
    return PolicyDoc.model_validate({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resource}],
    })


# ── return type ───────────────────────────────────────────────────────────────

def test_returns_tuple_of_two_strings():
    p = make_policy("s3:GetObject")
    findings = generate_findings(p)
    result = build_suggestion_prompt(p, findings, ["s3:GetObject"])
    assert isinstance(result, tuple)
    assert len(result) == 2
    assert all(isinstance(s, str) for s in result)


# ── system prompt ─────────────────────────────────────────────────────────────

def test_system_prompt_has_anti_hallucination_rule():
    p = make_policy("s3:GetObject")
    system, _ = build_suggestion_prompt(p, [], ["s3:GetObject"])
    assert "VALID_ACTIONS" in system or "valid" in system.lower()


def test_system_prompt_forbids_invented_actions():
    p = make_policy("s3:GetObject")
    system, _ = build_suggestion_prompt(p, [], ["s3:GetObject"])
    lower = system.lower()
    assert "never" in lower or "only" in lower or "do not" in lower


# ── user prompt ───────────────────────────────────────────────────────────────

def test_user_prompt_contains_valid_actions():
    valid = ["s3:GetObject", "s3:PutObject"]
    p = make_policy("s3:*")
    _, user = build_suggestion_prompt(p, [], valid)
    assert "s3:GetObject" in user
    assert "s3:PutObject" in user


def test_user_prompt_contains_policy_json():
    p = make_policy("iam:PassRole")
    _, user = build_suggestion_prompt(p, [], ["iam:PassRole"])
    assert "iam:PassRole" in user


def test_user_prompt_contains_findings():
    p = make_policy("iam:PassRole")
    findings = generate_findings(p)
    _, user = build_suggestion_prompt(p, findings, ["iam:PassRole"])
    assert any(f.rule_id in user for f in findings)


def test_user_prompt_requests_json_output():
    p = make_policy("s3:GetObject")
    _, user = build_suggestion_prompt(p, [], ["s3:GetObject"])
    lower = user.lower()
    assert "json" in lower


def test_user_prompt_scoped_actions_for_policy_services():
    p = make_policy(["s3:GetObject", "iam:PassRole"])
    _, user = build_suggestion_prompt(p, [], ["s3:GetObject", "iam:PassRole"])
    assert "s3:GetObject" in user
    assert "iam:PassRole" in user


def test_empty_findings_still_builds_prompt():
    p = make_policy("s3:GetObject")
    system, user = build_suggestion_prompt(p, [], ["s3:GetObject"])
    assert len(system) > 50
    assert len(user) > 50
