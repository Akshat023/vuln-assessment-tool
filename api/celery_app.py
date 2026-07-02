"""
Celery App Configuration
========================
Defines the Celery application instance and task for running scans.

Redis runs on localhost:6379 (Docker container).

Start worker with:
    celery -A api.celery_app worker --loglevel=info --pool=solo

The --pool=solo flag is required on Windows.
"""

from celery import Celery
import os

# ──────────────────────────────────────────────
# Celery app instance
# broker: Redis receives task messages
# backend: Redis stores task results
# ──────────────────────────────────────────────
celery_app = Celery(
    "vuln_assessment",
    broker=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
    backend=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
    include=["api.celery_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    worker_prefetch_multiplier=1,   # one task at a time per worker
    task_acks_late=True,            # only ack after task completes
)