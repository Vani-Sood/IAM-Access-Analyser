"""Webhook delivery Celery task with HMAC-SHA256 signing and retry."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging

import requests

from app.worker.celery_app import celery

logger = logging.getLogger(__name__)

_TIMEOUT = 10

# Discord embed colors per event
_DISCORD_COLORS = {
    "privesc.detected":  0xE74C3C,  # red
    "compliance.failed": 0xE67E22,  # orange
    "analysis.complete": 0x3498DB,  # blue
}

_EVENT_TITLES = {
    "privesc.detected":  "Privilege Escalation Detected",
    "compliance.failed": "Compliance Check Failed",
    "analysis.complete": "IAM Policy Analysis Complete",
}

_EVENT_EMOJI = {
    "privesc.detected":  "🔴",
    "compliance.failed": "🟠",
    "analysis.complete": "🔵",
}


def _sign_payload(body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _is_discord_url(url: str) -> bool:
    return "discord.com/api/webhooks/" in url or "discordapp.com/api/webhooks/" in url


def _is_slack_url(url: str) -> bool:
    return "hooks.slack.com/services/" in url


def _discord_payload(event: str, data: dict) -> dict:
    analysis_id = data.get("analysis_id", "?")
    title = _EVENT_TITLES.get(event, event)
    emoji = _EVENT_EMOJI.get(event, "📋")
    color = _DISCORD_COLORS.get(event, 0x95A5A6)

    fields = []
    if data.get("risk_score") is not None:
        fields.append({"name": "Risk Score", "value": f"`{data['risk_score']} / 10`", "inline": True})
    if data.get("severity"):
        fields.append({"name": "Severity", "value": f"`{data['severity'].upper()}`", "inline": True})
    if data.get("findings_count") is not None:
        fields.append({"name": "Findings", "value": str(data["findings_count"]), "inline": True})
    if data.get("paths_found") is not None:
        fields.append({"name": "Privesc Paths", "value": str(data["paths_found"]), "inline": True})
    if data.get("top_finding"):
        fields.append({"name": "Top Finding", "value": data["top_finding"], "inline": False})

    return {
        "embeds": [{
            "title": f"{emoji} {title}",
            "description": f"Analysis **#{analysis_id}** — [View Details](http://localhost:8000/analysis.html?id={analysis_id})",
            "color": color,
            "fields": fields,
            "footer": {"text": "IAM Policy Analyzer"},
        }]
    }


def _slack_payload(event: str, data: dict) -> dict:
    analysis_id = data.get("analysis_id", "?")
    title = _EVENT_TITLES.get(event, event)
    emoji = _EVENT_EMOJI.get(event, "📋")

    lines = [f"*{emoji} {title}*", f"Analysis *#{analysis_id}*"]
    if data.get("risk_score") is not None:
        lines.append(f"Risk Score: `{data['risk_score']}`")
    if data.get("severity"):
        lines.append(f"Severity: `{data['severity'].upper()}`")
    if data.get("framework"):
        lines.append(f"Framework: `{data['framework'].upper()}`")

    text = "\n".join(lines)
    return {
        "text": f"{emoji} {title} — Analysis #{analysis_id}",
        "blocks": [{
            "type": "section",
            "text": {"type": "mrkdwn", "text": text},
        }],
    }


def _do_deliver(
    webhook_id: int,
    event: str,
    payload: dict,
    *,
    db_session=None,
) -> None:
    owns_session = db_session is None
    if owns_session:
        from app.db.database import _get_session_factory
        db_session = _get_session_factory()()

    try:
        from app.db.models import Webhook
        hook: Webhook | None = db_session.get(Webhook, webhook_id)
        if hook is None or not hook.is_active:
            return

        # Test payloads bypass subscription check — always deliver
        is_test = payload.get("test", False)
        if not is_test:
            subscribed = json.loads(hook.events)
            if event not in subscribed:
                return

        if _is_discord_url(hook.url):
            body_dict = _discord_payload(event, payload)
            body = json.dumps(body_dict, separators=(",", ":")).encode()
            headers = {"Content-Type": "application/json"}
        elif _is_slack_url(hook.url):
            body_dict = _slack_payload(event, payload)
            body = json.dumps(body_dict, separators=(",", ":")).encode()
            headers = {"Content-Type": "application/json"}
        else:
            body = json.dumps(payload, separators=(",", ":")).encode()
            signature = _sign_payload(body, hook.secret)
            headers = {
                "Content-Type": "application/json",
                "X-Vani-Event": event,
                "X-Vani-Signature": signature,
            }

        resp = requests.post(hook.url, data=body, headers=headers, timeout=_TIMEOUT)
        if not resp.ok:
            logger.warning("Webhook %s got HTTP %s: %s", webhook_id, resp.status_code, resp.text[:200])
        resp.raise_for_status()

    except Exception as exc:
        if "hook" in dir() and hook is not None:
            hook.failure_count = (hook.failure_count or 0) + 1
            db_session.commit()
        logger.warning("Webhook %s delivery failed: %s", webhook_id, exc)
        raise
    finally:
        if owns_session:
            db_session.close()


@celery.task(bind=True, max_retries=3, default_retry_delay=60)
def deliver_webhook(
    self,
    webhook_id: int,
    event: str,
    payload: dict,
) -> None:
    try:
        _do_deliver(webhook_id, event, payload)
    except Exception as exc:
        countdown = 60 * (2 ** self.request.retries)
        raise self.retry(exc=exc, countdown=countdown)
