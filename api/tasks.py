"""
Tasks Module - Redis-backed scan store
=======================================
Uses Redis to store scan state so both FastAPI and Celery workers
share the same data. This fixes the separate-process memory problem.
"""

import json
import logging
import redis
from datetime import datetime
from api.models import ScanStatus

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Redis client — shared between FastAPI + Celery
# ──────────────────────────────────────────────
redis_client = redis.Redis(host="localhost", port=6379, db=1, decode_responses=True)

SCAN_TTL = 60 * 60 * 24  # 24 hours


class RedisScanStore:
    """
    Dict-like interface backed by Redis.
    Stores each scan as a JSON string under key: scan:{scan_id}
    """

    def __getitem__(self, scan_id: str) -> dict:
        data = redis_client.get(f"scan:{scan_id}")
        if data is None:
            raise KeyError(scan_id)
        return json.loads(data)

    def __setitem__(self, scan_id: str, value: dict):
        redis_client.setex(f"scan:{scan_id}", SCAN_TTL, json.dumps(value, default=str))

    def __contains__(self, scan_id: str) -> bool:
        return redis_client.exists(f"scan:{scan_id}") > 0

    def __delitem__(self, scan_id: str):
        redis_client.delete(f"scan:{scan_id}")

    def get(self, scan_id: str, default=None):
        try:
            return self[scan_id]
        except KeyError:
            return default

    def update_fields(self, scan_id: str, fields: dict):
        """Update specific fields in a scan record."""
        try:
            current = self[scan_id]
            current.update(fields)
            self[scan_id] = current
        except KeyError:
            logger.error(f"Scan {scan_id} not found in Redis")

    def values(self):
        """Return all scan records."""
        keys = redis_client.keys("scan:*")
        results = []
        for key in keys:
            data = redis_client.get(key)
            if data:
                results.append(json.loads(data))
        return results


# Global store instance — imported by both FastAPI and Celery
scan_store = RedisScanStore()


def run_scan_task(scan_id: str, target_url: str):
    """
    Kept for backward compatibility.
    In production, Celery task is used instead.
    """
    from api.celery_tasks import run_scan_celery
    run_scan_celery.delay(scan_id, target_url)