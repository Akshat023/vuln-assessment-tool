"""
Celery Tasks
============
Defines the background scan task that Celery workers pick up from Redis queue.
"""

import logging
from datetime import datetime
from api.celery_app import celery_app
from api.models import ScanStatus

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="run_scan")
def run_scan_celery(self, scan_id: str, target_url: str):
    from api.tasks import scan_store

    logger.info(f"[Celery] Starting scan | scan_id={scan_id} | url={target_url}")

    scan_store.update_fields(scan_id, {
        "status": ScanStatus.RUNNING.value,
        "celery_task_id": self.request.id,
    })

    try:
        from scanner.orchestrator import ScanOrchestrator

        orchestrator = ScanOrchestrator(
            zap_url="http://vuln_zap:8080",
            run_zap=True,
            run_nuclei=True,
            zap_skip_active=False,
        )

        result = orchestrator.run_full_scan(target_url=target_url, scan_id=scan_id)

        if result["status"] == "failed":
            raise Exception("Orchestrator scan returned failed status — no scanner tools succeeded")

        findings = result["findings"]
        summary  = result["summary"]

        from ai.analyzer import AIAnalyzer
        from dotenv import load_dotenv
        load_dotenv()

        try:
            analyzer = AIAnalyzer()
            findings, executive_summary = analyzer.enrich(findings, target_url)
        except Exception as e:
            logger.error(f"AI enrichment failed: {e} — continuing without AI")
            executive_summary = f"Automated scan of {target_url} completed. {len(findings)} vulnerabilities found."

        scan_store.update_fields(scan_id, {
            "status":            ScanStatus.COMPLETED.value,
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
            "status":       ScanStatus.FAILED.value,
            "completed_at": datetime.utcnow().isoformat(),
            "error":        str(e),
        })
        raise