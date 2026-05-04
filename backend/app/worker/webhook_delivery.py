"""Webhook delivery Celery task with HMAC-SHA256 signing and retry — Batch 23."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging

import requests

from app.worker.celery_app import celery

logger = logging.getLogger(__name__)

_TIMEOUT = 10


def _sign_payload(body: bytes, secret: str) -> str:
    """Return HMAC-SHA256 signature string in the format 'sha256=<hex>'."""
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _do_deliver(
    webhook_id: int,
    event: str,
    payload: dict,
    *,
    db_session=None,
) -> None:
    """Deliver one webhook. If db_session is None, creates its own session."""
    owns_session = db_session is None
    if owns_session:
        from app.db.database import _get_session_factory
        db_session = _get_session_factory()()

    try:
        from app.db.models import Webhook
        hook: Webhook | None = db_session.get(Webhook, webhook_id)
        if hook is None or not hook.is_active:
            return

        subscribed = json.loads(hook.events)
        if event not in subscribed:
            return

        body = json.dumps(payload, separators=(",", ":")).encode()
        signature = _sign_payload(body, hook.secret)

        headers = {
            "Content-Type": "application/json",
            "X-Vani-Event": event,
            "X-Vani-Signature": signature,
        }

        resp = requests.post(hook.url, data=body, headers=headers, timeout=_TIMEOUT)
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
    """Celery task: deliver webhook payload with exponential backoff retry."""
    try:
        _do_deliver(webhook_id, event, payload)
    except Exception as exc:
        countdown = 60 * (2 ** self.request.retries)
        raise self.retry(exc=exc, countdown=countdown)
