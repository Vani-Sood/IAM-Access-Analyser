"""Celery application factory."""
from __future__ import annotations

from celery import Celery


def make_celery() -> Celery:
    from app.config import Settings
    settings = Settings()
    return Celery(
        "iam_analyzer",
        broker=settings.redis_url,
        backend=settings.redis_url,
        include=["app.worker.tasks"],
    )


celery = make_celery()

celery.conf.include = ["app.worker.tasks"]

celery.conf.beat_schedule = {
    "weekly-rescan": {
        "task": "app.worker.tasks.rescan_completed_analyses",
        "schedule": 604800,  # every 7 days in seconds
    },
}
celery.conf.timezone = "UTC"
