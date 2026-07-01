"""
Tasks Module
============
Scan store is PostgreSQL-backed via db/scan_store.py.
Redis is kept only for Celery's task queue (broker/backend),
not for scan state storage.

Both FastAPI (main.py) and Celery (celery_tasks.py) import
scan_store from here so they share the exact same store.
"""

from db.scan_store import scan_store  # noqa: F401 — re-exported for main.py + celery_tasks.py


def run_scan_task(scan_id: str, target_url: str):
    """Kept for backward compatibility / direct invocation if ever needed."""
    from api.celery_tasks import run_scan_celery
    run_scan_celery.delay(scan_id, target_url)