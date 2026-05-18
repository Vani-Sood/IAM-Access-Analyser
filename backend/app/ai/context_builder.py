from __future__ import annotations

import json

from app.analysis.findings import Finding
from app.ingestion.parser import PolicyDoc, Statement

_MAX_STATEMENTS = 30   # free-tier Gemini times out on prompts > ~5KB
_MAX_ACTIONS_PER_STMT = 20  # long action lists (SecurityAudit has 200+) bloat prompt

SYSTEM_PROMPT = """You are a cloud IAM security expert specializing in least-privilege access.

STRICT RULES:
1. ONLY suggest real, documented IAM actions — never invent action names.
2. Output ONLY valid JSON — no explanation text outside the JSON structure.
3. Use the exact action format: service:ActionName (e.g. s3:GetObject, iam:ListUsers).
4. If the policy is GCP or Azure, adapt the schema to that cloud's IAM model."""


def _truncate_statements(statements: list[Statement], limit: int) -> list[Statement]:
    """Return the most security-relevant statements up to limit.

    Priority: Deny > Allow with conditions > Allow with specific actions > Allow *.
    Large managed policies (SecurityAudit etc.) can have 300+ statements;
    keeping all of them blows the free-tier Gemini token budget.
    """
    if len(statements) <= limit:
        return statements

    def _rank(s: Statement) -> int:
        is_deny = getattr(s.effect, "value", str(s.effect)).lower() == "deny"
        has_condition = bool(s.condition)
        actions = s.action or []
        is_wildcard = actions == ["*"] or actions == "*"
        if is_deny:
            return 0
        if has_condition:
            return 1
        if not is_wildcard:
            return 2
        return 3

    ranked = sorted(statements, key=_rank)
    return ranked[:limit]


def build_suggestion_prompt(
    policy: PolicyDoc,
    findings: list[Finding],
    valid_actions: list[str],  # kept for signature compat; used only for post-hoc validation
) -> tuple[str, str]:
    findings_summary = "\n".join(
        f"- [{f.severity.value}] {f.rule_id}: {f.message}" for f in findings
    ) or "No critical findings — still apply least-privilege."

    truncated = _truncate_statements(policy.statement, _MAX_STATEMENTS)
    total = len(policy.statement)
    truncation_note = (
        f"  // ... {total - len(truncated)} lower-priority statements omitted\n"
        if len(truncated) < total
        else ""
    )

    def _serialise(s: Statement) -> dict:
        d = s.model_dump(by_alias=True, exclude_none=True)
        actions = d.get("Action") or d.get("action") or []
        if isinstance(actions, list) and len(actions) > _MAX_ACTIONS_PER_STMT:
            shown = actions[:_MAX_ACTIONS_PER_STMT]
            d["Action"] = shown + [f"... +{len(actions) - _MAX_ACTIONS_PER_STMT} more actions omitted"]
            d.pop("action", None)
        return d

    stmts_json = json.dumps([_serialise(s) for s in truncated], indent=2)

    user_prompt = f"""CURRENT POLICY — {total} statements total, showing {len(truncated)} most relevant:
{stmts_json}
{truncation_note}
RISK FINDINGS:
{findings_summary}

TASK:
1. Identify the minimum set of real IAM actions needed for the stated purpose.
2. Replace wildcard resources with specific ARN patterns where possible.
3. Add Condition blocks where appropriate (MFA, IP CIDR, source ARN).
4. Output ONLY valid JSON matching this exact schema:

{{
  "least_privilege_policy": {{
    "Version": "2012-10-17",
    "Statement": [...]
  }},
  "changes": [
    {{"original": "<old action>", "replacement": ["<new action>"], "reason": "<one sentence>"}}
  ]
}}"""

    return SYSTEM_PROMPT, user_prompt
