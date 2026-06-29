"""
Celery Tasks
============
Defines the background scan task that Celery workers pick up from Redis queue.

This replaces FastAPI BackgroundTasks with a proper production queue.
Multiple workers can run concurrently, tasks survive server restarts,
and task status is stored in Redis.

Start worker:
    celery -A api.celery_app worker --loglevel=info --pool=solo
"""

import logging
from datetime import datetime
from api.celery_app import celery_app
from api.models import ScanStatus

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="run_scan")
def run_scan_celery(self, scan_id: str, target_url: str):
    """
    Celery task: runs the full scan pipeline.

    Args:
        scan_id:    Unique scan ID
        target_url: URL to scan

    The task updates scan_store at each stage so the API
    can return live status when polled.
    """
    # Import here to avoid circular imports
    from api.tasks import scan_store

    logger.info(f"[Celery] Starting scan | scan_id={scan_id} | url={target_url}")

    # Update status to running
    scan_store.update_fields(scan_id, {"status": ScanStatus.RUNNING, "celery_task_id": self.request.id})

    try:
        # ── Step 1: ZAP Scan ──────────────────
        from scanner.modules.zap_scanner import ZAPScanner

        scanner = ZAPScanner(
            zap_url="http://localhost:8080",
            spider_timeout=300,
            ascan_timeout=1800,
            poll_interval=15,
        )

        result = scanner.run_full_scan(
            target_url=target_url,
            scan_id=scan_id,
            skip_active_scan=False,
        )

        if result["status"] == "failed":
            raise Exception("ZAP scan returned failed status")

        findings = result["findings"]
        summary  = result["summary"]

        # ── Step 2: AI Enrichment ─────────────
        from ai.analyzer import AIAnalyzer
        from dotenv import load_dotenv
        load_dotenv()

        try:
            analyzer = AIAnalyzer()
            findings, executive_summary = analyzer.enrich(findings, target_url)
        except Exception as e:
            logger.error(f"AI enrichment failed: {e} — continuing without AI")
            executive_summary = f"Automated scan of {target_url} completed. {len(findings)} vulnerabilities found."

        # ── Step 3: Store results ─────────────
        scan_store.update_fields(scan_id, {
                "status":            ScanStatus.COMPLETED,
                "completed_at":      datetime.utcnow().isoformat(),
                "findings":          findings,
                "summary":           summary,
                "executive_summary": executive_summary,
                "error":             None,
            })

        logger.info(f"[Celery] Scan complete | scan_id={scan_id} | total={summary['total']}")
        return {"status": "completed", "scan_id": scan_id, "total": summary["total"]}

    except Exception as e:
        logger.error(f"[Celery] Scan failed | scan_id={scan_id} | error={e}")
        scan_store.update_fields(scan_id, {
                "status":       ScanStatus.FAILED,
                "completed_at": datetime.utcnow().isoformat(),
                "error":        str(e),
            })
        raise