"""
PostgreSQL Scan Store
=====================
Drop-in replacement for RedisScanStore.
Same dict-like interface — scan_store[id], scan_store.get(id),
scan_store.update_fields(id, fields), scan_store.values()
"""


import json
import logging
from db.database import SessionLocal
from db.models import Scan

logger = logging.getLogger(__name__)


class PostgresScanStore:
    """
    Dict-like interface backed by PostgreSQL.
    FastAPI and Celery both import this — they share the same DB.
    """

    def _to_dict(self, scan: Scan) -> dict:
        """Convert ORM object to plain dict."""
        return {
            "scan_id":           scan.scan_id,
            "url":               scan.url,
            "status":            scan.status,
            "created_at":        scan.created_at,
            "completed_at":      scan.completed_at,
            "findings":          scan.findings or [],
            "summary":           scan.summary or {},
            "executive_summary": scan.executive_summary or "",
            "user_id":           scan.user_id,
            "user_email":        scan.user_email,
            "error":             scan.error,
        }

    def __getitem__(self, scan_id: str) -> dict:
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            if scan is None:
                raise KeyError(scan_id)
            return self._to_dict(scan)
        finally:
            db.close()

    def __setitem__(self, scan_id: str, value: dict):
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            if scan is None:
                scan = Scan(scan_id=scan_id)
                db.add(scan)
            scan.url               = value.get("url", "")
            status_val = value.get("status", "queued")
            scan.status = status_val.value if hasattr(status_val, "value") else str(status_val)
            scan.created_at        = value.get("created_at", "")
            scan.completed_at      = value.get("completed_at")
            scan.findings          = value.get("findings", [])
            scan.summary           = value.get("summary", {})
            scan.executive_summary = value.get("executive_summary", "")
            scan.error             = value.get("error")
            scan.user_id    = value.get("user_id")
            scan.user_email = value.get("user_email")
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"DB write failed for scan {scan_id}: {e}")
            raise
        finally:
            db.close()

    def __contains__(self, scan_id: str) -> bool:
        db = SessionLocal()
        try:
            return db.query(Scan).filter(
                Scan.scan_id == scan_id
            ).first() is not None
        finally:
            db.close()

    def __delitem__(self, scan_id: str):
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            if scan:
                db.delete(scan)
                db.commit()
        finally:
            db.close()

    def get(self, scan_id: str, default=None):
        try:
            return self[scan_id]
        except KeyError:
            return default

    def update_fields(self, scan_id: str, fields: dict):
        """Update specific fields without overwriting the whole record."""
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            if scan is None:
                logger.error(f"Scan {scan_id} not found in DB")
                return
            for key, value in fields.items():
                if hasattr(scan, key):
                    if key == "status":
                        setattr(scan, key, value.value if hasattr(value, "value") else str(value))
                    else:
                        setattr(scan, key, value)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"update_fields failed for {scan_id}: {e}")
            raise
        finally:
            db.close()

    def values(self):
        """Return all scans ordered by created_at descending."""
        db = SessionLocal()
        try:
            scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
            return [self._to_dict(s) for s in scans]
        finally:
            db.close()


scan_store = PostgresScanStore()
