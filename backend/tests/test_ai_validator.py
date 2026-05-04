import json
import pytest
from app.ai.validator import validate_llm_output

VALID_ACTIONS = {"s3:GetObject", "s3:PutObject", "s3:ListBucket", "iam:PassRole"}

# ── helpers ───────────────────────────────────────────────────────────────────

def make_raw(statements: list[dict], changes: list[dict] | None = None) -> str:
    return json.dumps({
        "least_privilege_policy": {
            "Version": "2012-10-17",
            "Statement": statements,
        },
        "changes": changes or [],
    })


# ── happy path ────────────────────────────────────────────────────────────────

def test_valid_actions_pass_through():
    raw = make_raw([{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}])
    result = validate_llm_output(raw, VALID_ACTIONS)
    stmts = result["least_privilege_policy"]["Statement"]
    assert stmts[0]["Action"] == ["s3:GetObject"]


def test_multiple_valid_actions_preserved():
    raw = make_raw([{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*"}])
    result = validate_llm_output(raw, VALID_ACTIONS)
    actions = result["least_privilege_policy"]["Statement"][0]["Action"]
    assert "s3:GetObject" in actions
    assert "s3:PutObject" in actions


# ── hallucination stripping ───────────────────────────────────────────────────

def test_hallucinated_action_stripped():
    raw = make_raw([{"Effect": "Allow", "Action": ["s3:GetObject", "s3:FakeAction"], "Resource": "*"}])
    result = validate_llm_output(raw, VALID_ACTIONS)
    actions = result["least_privilege_policy"]["Statement"][0]["Action"]
    assert "s3:FakeAction" not in actions
    assert "s3:GetObject" in actions


def test_all_invalid_actions_produces_empty_list():
    raw = make_raw([{"Effect": "Allow", "Action": ["s3:FakeAction", "iam:Nonexistent"], "Resource": "*"}])
    result = validate_llm_output(raw, VALID_ACTIONS)
    actions = result["least_privilege_policy"]["Statement"][0]["Action"]
    assert actions == []


def test_mixed_valid_invalid_keeps_only_valid():
    raw = make_raw([
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:HackedAction", "iam:PassRole"], "Resource": "*"}
    ])
    result = validate_llm_output(raw, VALID_ACTIONS)
    actions = result["least_privilege_policy"]["Statement"][0]["Action"]
    assert set(actions) == {"s3:GetObject", "iam:PassRole"}


def test_multiple_statements_all_validated():
    raw = make_raw([
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"},
        {"Effect": "Allow", "Action": ["s3:FakeAction", "s3:PutObject"], "Resource": "*"},
    ])
    result = validate_llm_output(raw, VALID_ACTIONS)
    stmts = result["least_privilege_policy"]["Statement"]
    assert stmts[0]["Action"] == ["s3:GetObject"]
    assert stmts[1]["Action"] == ["s3:PutObject"]


# ── action as string (not list) ───────────────────────────────────────────────

def test_action_as_string_validated():
    raw = make_raw([{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}])
    result = validate_llm_output(raw, VALID_ACTIONS)
    actions = result["least_privilege_policy"]["Statement"][0]["Action"]
    assert "s3:GetObject" in actions


def test_action_string_invalid_stripped():
    raw = make_raw([{"Effect": "Allow", "Action": "s3:FakeAction", "Resource": "*"}])
    result = validate_llm_output(raw, VALID_ACTIONS)
    actions = result["least_privilege_policy"]["Statement"][0]["Action"]
    assert actions == []


# ── error cases ───────────────────────────────────────────────────────────────

def test_malformed_json_returns_error():
    result = validate_llm_output("not valid json", VALID_ACTIONS)
    assert result.get("error") is not None


def test_empty_string_returns_error():
    result = validate_llm_output("", VALID_ACTIONS)
    assert result.get("error") is not None


def test_missing_least_privilege_key_returns_error():
    result = validate_llm_output('{"other": "field"}', VALID_ACTIONS)
    assert result.get("error") is not None


# ── changes preserved ─────────────────────────────────────────────────────────

def test_changes_list_preserved():
    raw = make_raw(
        [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
        changes=[{"original": "s3:*", "replacement": ["s3:GetObject"], "reason": "Least privilege"}],
    )
    result = validate_llm_output(raw, VALID_ACTIONS)
    assert len(result["changes"]) == 1
    assert result["changes"][0]["reason"] == "Least privilege"


def test_no_statement_action_key_passes_through():
    raw = json.dumps({
        "least_privilege_policy": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": ["s3:DeleteObject"], "Resource": "*"}],
        },
        "changes": [],
    })
    result = validate_llm_output(raw, VALID_ACTIONS)
    assert result.get("error") is None


def test_markdown_json_fence_stripped():
    inner = make_raw([{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}])
    fenced = f"```json\n{inner}\n```"
    result = validate_llm_output(fenced, VALID_ACTIONS)
    assert result.get("error") is None
    assert result["least_privilege_policy"] is not None


def test_plain_backtick_fence_stripped():
    inner = make_raw([{"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": "*"}])
    fenced = f"```\n{inner}\n```"
    result = validate_llm_output(fenced, VALID_ACTIONS)
    assert result.get("error") is None


def test_whitespace_only_returns_empty_error():
    result = validate_llm_output("   \n\t  ", VALID_ACTIONS)
    assert result.get("error") == "empty_response"
