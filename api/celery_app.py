"""
Celery App Configuration
========================
Defines the Celery application instance and task for running scans.

Start worker with:
    celery -A api.celery_app worker --loglevel=info --pool=solo
"""

import os
from celery import Celery

redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
use_ssl = redis_url.startswith("rediss://")

celery_app = Celery(
    "vuln_assessment",
    broker=redis_url,
    backend=redis_url,
    include=["api.celery_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    broker_use_ssl={"ssl_cert_reqs": None} if use_ssl else None,
    redis_backend_use_ssl={"ssl_cert_reqs": None} if use_ssl else None,
)