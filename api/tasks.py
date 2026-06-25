"""
Tasks Module
============
Background task that runs the full scan pipeline.

Phase 1: Uses FastAPI BackgroundTasks (simple, no extra infrastructure)
Phase 2: Replace with Celery + Redis for production async queue

The scan pipeline:
    1. ZAP spider + active scan
    2. CVSS + OWASP mapping (done inside ZAPScanner)
    3. AI analysis — remediation + business impact (Phase 2, Groq API)
    4. Store results
"""

import logging
from datetime import datetime
from api.models import ScanStatus

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# In-memory scan store (Phase 1)
# Phase 2: replace with PostgreSQL via SQLAlchemy
# ──────────────────────────────────────────────
scan_store: dict = {}


def run_scan_task(scan_id: str, target_url: str):
    """
    Main scan pipeline. Called as a background task by FastAPI.
    
    Args:
        scan_id:    Unique scan identifier
        target_url: URL to scan
    """
    logger.info(f"[Task] Starting scan pipeline | scan_id={scan_id} | url={target_url}")

    # Update status to running
    scan_store[scan_id]["status"] = ScanStatus.RUNNING

    try:
        # ── Step 1: ZAP Scan ──────────────────────────────
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
            skip_active_scan=False,  # set True for quick testing
        )

        if result["status"] == "failed":
            raise Exception("ZAP scan returned failed status")

        findings = result["findings"]
        summary  = result["summary"]

        # ── Step 2: AI Analysis (Phase 2 placeholder) ─────
        # findings = ai_analyzer.enrich(findings)
        # Uncomment above in Phase 2 when Groq integration is ready.
        # For now findings go straight to store with empty recommendation fields.

        # ── Step 3: Store results ─────────────────────────
        scan_store[scan_id].update({
            "status":       ScanStatus.COMPLETED,
            "completed_at": datetime.utcnow().isoformat(),
            "findings":     findings,
            "summary":      summary,
            "error":        None,
        })

        logger.info(f"[Task] Scan complete | scan_id={scan_id} | findings={summary['total']}")

    except Exception as e:
        logger.error(f"[Task] Scan failed | scan_id={scan_id} | error={e}")
        scan_store[scan_id].update({
            "status":       ScanStatus.FAILED,
            "completed_at": datetime.utcnow().isoformat(),
            "error":        str(e),
        })