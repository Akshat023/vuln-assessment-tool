"""
Scan Orchestrator
=================
Coordinates multiple scanning engines (ZAP, Nuclei) and merges
their results into a single normalized findings list.

This is the layer that makes the system pluggable — new scanners
can be added here without touching the API or Celery task code.

Usage:
    from scanner.orchestrator import ScanOrchestrator
    orchestrator = ScanOrchestrator()
    result = orchestrator.run_full_scan("http://example.com")
"""

import uuid
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """
    Coordinates all scanning modules and produces a single
    merged, deduplicated findings list with combined summary.

    Args:
        zap_url:           ZAP daemon URL
        run_zap:            whether to run ZAP scan
        run_nuclei:         whether to run Nuclei scan
        zap_skip_active:    skip ZAP active scan (faster, passive only)
    """

    def __init__(
        self,
        zap_url: str = "http://localhost:8080",
        run_zap: bool = True,
        run_nuclei: bool = True,
        run_headers: bool = True,
        run_ssl: bool = True,
        zap_skip_active: bool = False,
    ):
        self.zap_url = zap_url
        self.run_zap = run_zap
        self.run_nuclei = run_nuclei
        self.run_headers = run_headers
        self.run_ssl = run_ssl
        self.zap_skip_active = zap_skip_active

    def _dedupe_findings(self, findings: list) -> list:
        """
        Remove findings that are essentially the same issue
        reported by both ZAP and Nuclei (e.g. both flag exposed .env file).
        Dedup key: (vuln_type lowercased, affected_url).
        """
        seen = set()
        deduped = []
        for f in findings:
            key = (f["vuln_type"].lower().strip(), f["affected_url"].rstrip("/"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)
        return deduped

    def run_full_scan(self, target_url: str, scan_id: Optional[str] = None) -> dict:
        """
        Run all enabled scanners against the target and merge results.

        Args:
            target_url: URL to scan
            scan_id:    Optional parent scan ID

        Returns:
            {
                "scan_id":      str,
                "target":       str,
                "status":       "completed" | "partial" | "failed",
                "findings":     merged, deduplicated, sorted findings list,
                "summary":      combined severity counts,
                "tools_run":    list of tool names that executed successfully,
                "tools_failed": list of tool names that failed
            }
        """
        if scan_id is None:
            scan_id = str(uuid.uuid4())

        logger.info(f"=== Orchestrator starting | scan_id={scan_id} | target={target_url} ===")

        all_findings = []
        tools_run = []
        tools_failed = []

        # ── ZAP scan ───────────────────────────
        if self.run_zap:
            try:
                from scanner.modules.zap_scanner import ZAPScanner
                zap = ZAPScanner(zap_url=self.zap_url)
                zap_result = zap.run_full_scan(
                    target_url=target_url,
                    scan_id=scan_id,
                    skip_active_scan=self.zap_skip_active,
                )
                if zap_result["status"] == "completed":
                    all_findings.extend(zap_result["findings"])
                    tools_run.append("zap")
                    logger.info(f"ZAP contributed {len(zap_result['findings'])} findings")
                else:
                    tools_failed.append("zap")
                    logger.warning("ZAP scan did not complete successfully")
            except Exception as e:
                tools_failed.append("zap")
                logger.error(f"ZAP scan raised exception: {e}")

        # ── Nuclei scan ────────────────────────
        if self.run_nuclei:
            try:
                from scanner.modules.nuclei_scanner import NucleiScanner
                nuclei = NucleiScanner()
                nuclei_result = nuclei.run_scan(target_url=target_url, scan_id=scan_id)
                if nuclei_result["status"] == "completed":
                    all_findings.extend(nuclei_result["findings"])
                    tools_run.append("nuclei")
                    logger.info(f"Nuclei contributed {len(nuclei_result['findings'])} findings")
                else:
                    tools_failed.append("nuclei")
                    logger.warning("Nuclei scan did not complete successfully")
            except Exception as e:
                tools_failed.append("nuclei")
                logger.error(f"Nuclei scan raised exception: {e}")
        
        # ── Normalize URL for direct Python connections ────
        # host.docker.internal only works inside Docker containers.
        # Header/SSL scanners connect directly from Windows, so use localhost.
        direct_url = target_url.replace("host.docker.internal", "localhost")
        # ── Header scan ────────────────────────
        if self.run_headers:
            try:
                from scanner.modules.header_scanner import HeaderScanner
                header = HeaderScanner()
                header_result = header.run_scan(target_url=direct_url, scan_id=scan_id)
                if header_result["status"] == "completed":
                    all_findings.extend(header_result["findings"])
                    tools_run.append("header_scanner")
                    logger.info(f"Header scanner contributed {len(header_result['findings'])} findings")
                else:
                    tools_failed.append("header_scanner")
                    logger.warning("Header scan did not complete successfully")
            except Exception as e:
                tools_failed.append("header_scanner")
                logger.error(f"Header scan raised exception: {e}")

        direct_url = target_url.replace("host.docker.internal", "localhost")
        # ── SSL scan ───────────────────────────
        if self.run_ssl:
            try:
                from scanner.modules.ssl_scanner import SSLScanner
                ssl = SSLScanner()
                ssl_result = ssl.run_scan(target_url=direct_url, scan_id=scan_id)
                if ssl_result["status"] == "completed":
                    all_findings.extend(ssl_result["findings"])
                    tools_run.append("ssl_scanner")
                    logger.info(f"SSL scanner contributed {len(ssl_result['findings'])} findings")
                else:
                    tools_failed.append("ssl_scanner")
                    logger.warning("SSL scan did not complete successfully")
            except Exception as e:
                tools_failed.append("ssl_scanner")
                logger.error(f"SSL scan raised exception: {e}")
        

        # ── Merge, dedupe, sort ────────────────
        merged_findings = self._dedupe_findings(all_findings)
        merged_findings.sort(key=lambda x: x["cvss_score"], reverse=True)

        summary = {"total": len(merged_findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in merged_findings:
            sev = f["severity"].lower()
            if sev in summary:
                summary[sev] += 1

        # ── Determine overall status ───────────
        if not tools_run:
            status = "failed"
        elif tools_failed:
            status = "partial"
        else:
            status = "completed"

        logger.info(
            f"=== Orchestrator complete | status={status} | "
            f"tools_run={tools_run} | tools_failed={tools_failed} | "
            f"total_findings={len(merged_findings)} (before dedup: {len(all_findings)}) ==="
        )

        return {
            "scan_id":      scan_id,
            "target":       target_url,
            "status":       status,
            "findings":     merged_findings,
            "summary":      summary,
            "tools_run":    tools_run,
            "tools_failed": tools_failed,
        }


# ──────────────────────────────────────────────
# Quick test
# ──────────────────────────────────────────────
if __name__ == "__main__":
    import json

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [Orchestrator] %(message)s")

    orchestrator = ScanOrchestrator(
        zap_skip_active=True,  # faster for testing
    )
    result = orchestrator.run_full_scan("http://host.docker.internal:8888")

    print("\n" + "=" * 60)
    print(f"Scan ID      : {result['scan_id']}")
    print(f"Status       : {result['status']}")
    print(f"Tools run    : {result['tools_run']}")
    print(f"Tools failed : {result['tools_failed']}")
    print(f"Summary      : {result['summary']}")
    print("=" * 60)

    for f in result["findings"][:5]:
        print(f"\n[{f['severity']}] {f['vuln_type']} (via {f['tool']})")
        print(f"  OWASP : {f['owasp_category']}")
        print(f"  CVSS  : {f['cvss_score']}")
        print(f"  URL   : {f['affected_url']}")

    with open("orchestrator_result.json", "w") as fp:
        json.dump(result, fp, indent=2)
    print("\nFull output saved to orchestrator_result.json")