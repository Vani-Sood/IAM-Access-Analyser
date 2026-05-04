from __future__ import annotations

import json

from app.analysis.findings import Finding
from app.ingestion.parser import PolicyDoc

SYSTEM_PROMPT = """You are an AWS IAM security expert specializing in least-privilege access.

STRICT RULES:
1. ONLY suggest actions from the VALID_ACTIONS list provided. NEVER invent action names.
2. If unsure whether an action exists, OMIT it entirely.
3. Output ONLY valid JSON — no explanation text outside the JSON structure.
4. Every Action value in your output must exist in VALID_ACTIONS."""


def build_suggestion_prompt(
    policy: PolicyDoc,
    findings: list[Finding],
    valid_actions: list[str],
) -> tuple[str, str]:
    findings_summary = "\n".join(
        f"- [{f.severity.value}] {f.rule_id}: {f.message}" for f in findings
    ) or "No critical findings — still apply least-privilege."

    user_prompt = f"""VALID_ACTIONS (use ONLY these):
{json.dumps(valid_actions, indent=2)}

CURRENT POLICY (may be overly permissive):
{policy.model_dump_json(by_alias=True, indent=2)}

RISK FINDINGS:
{findings_summary}

TASK:
1. Identify the minimum set of actions from VALID_ACTIONS needed for the stated purpose.
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
