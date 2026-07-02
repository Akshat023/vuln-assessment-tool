"""
ZAP Scanner Module
==================
Wraps OWASP ZAP REST API into a single Python function.
Handles: spider scan → active scan → fetch alerts → normalize findings.

Requirements:
    pip install requests

Usage:
    from scanner.modules.zap_scanner import ZAPScanner
    
    scanner = ZAPScanner(zap_url="http://localhost:8080")
    findings = scanner.run_full_scan("http://host.docker.internal:8888")
    print(findings)
"""
import os
import requests
import time
import uuid
import logging
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ZAP] %(message)s")
logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# CVSS Mapping: ZAP risk level → CVSS score
# AI explains severity, CVSS decides it.
# ──────────────────────────────────────────────
CVSS_MAP = {
    "Informational": 0.0,
    "Low":           3.1,
    "Medium":        5.3,
    "High":          8.1,
    "Critical":      9.8,
}

# ──────────────────────────────────────────────
# OWASP Top 10 (2021) mapping by ZAP plugin ID
# ──────────────────────────────────────────────
OWASP_MAP = {
    "40018": ("A03:2021 - Injection",                    "SQL Injection"),
    "40012": ("A03:2021 - Injection",                    "Cross-Site Scripting (Reflected)"),
    "40014": ("A03:2021 - Injection",                    "Cross-Site Scripting (Persistent)"),
    "40016": ("A03:2021 - Injection",                    "Cross-Site Scripting (Persistent)"),
    "40017": ("A03:2021 - Injection",                    "Cross-Site Scripting (Persistent)"),
    "40026": ("A03:2021 - Injection",                    "Cross-Site Scripting (DOM Based)"),
    "90021": ("A03:2021 - Injection",                    "XPath Injection"),
    "90035": ("A03:2021 - Injection",                    "Server Side Template Injection"),
    "10010": ("A05:2021 - Security Misconfiguration",    "Cookie No HttpOnly Flag"),
    "10054": ("A05:2021 - Security Misconfiguration",    "Cookie No SameSite Attribute"),
    "10020": ("A05:2021 - Security Misconfiguration",    "Missing Anti-Clickjacking Header"),
    "10021": ("A05:2021 - Security Misconfiguration",    "X-Content-Type-Options Header Missing"),
    "10038": ("A05:2021 - Security Misconfiguration",    "Content Security Policy Header Not Set"),
    "10036": ("A05:2021 - Security Misconfiguration",    "Server Leaks Version Information"),
    "10009": ("A05:2021 - Security Misconfiguration",    "In Page Banner Information Leak"),
    "10023": ("A05:2021 - Security Misconfiguration",    "Information Disclosure - Debug Error Messages"),
    "10027": ("A05:2021 - Security Misconfiguration",    "Information Disclosure - Suspicious Comments"),
    "0":     ("A01:2021 - Broken Access Control",        "Directory Browsing"),
    "6":     ("A01:2021 - Broken Access Control",        "Path Traversal"),
    "7":     ("A02:2021 - Cryptographic Failures",       "Remote File Inclusion"),
    "20015": ("A02:2021 - Cryptographic Failures",       "Heartbleed OpenSSL Vulnerability"),
    "90034": ("A05:2021 - Security Misconfiguration",    "Cloud Metadata Potentially Exposed"),
}

DEFAULT_OWASP = ("A05:2021 - Security Misconfiguration", "Security Issue")


class ZAPScanner:
    """
    Wraps OWASP ZAP REST API.
    
    Args:
        zap_url: Base URL where ZAP is listening (default: http://localhost:8080)
        spider_timeout: Max seconds to wait for spider to complete
        ascan_timeout:  Max seconds to wait for active scan to complete
        poll_interval:  Seconds between status checks
    """

    def __init__(
        self,
        zap_url: str = os.getenv("ZAP_URL", "http://localhost:8080"),
        spider_timeout: int = 300,
        ascan_timeout: int = 1800,
        poll_interval: int = 10,
    ):
        self.zap_url = zap_url.rstrip("/")
        self.spider_timeout = spider_timeout
        self.ascan_timeout = ascan_timeout
        self.poll_interval = poll_interval

    # ──────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────

    def _get(self, path: str, params: dict = {}) -> dict:
        """Make a GET request to ZAP API and return JSON."""
        url = f"{self.zap_url}{path}"
        try:
            response = requests.get(url, params=params, timeout=120)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"ZAP API request failed: {e}")
            raise

    def _wait_for_completion(self, status_path: str, scan_id: str, timeout: int, label: str) -> bool:
        """Poll ZAP status endpoint until 100% or timeout."""
        elapsed = 0
        while elapsed < timeout:
            try:
                data = self._get(status_path, {"scanId": scan_id})
                status = int(data.get("status", 0))
                logger.info(f"{label} progress: {status}%")
                if status >= 100:
                    return True
            except Exception as e:
                logger.warning(f"Status check failed: {e}")
            time.sleep(self.poll_interval)
            elapsed += self.poll_interval
        logger.error(f"{label} timed out after {timeout}s")
        return False

    # ──────────────────────────────────────────
    # Step 1: Seed the scan tree via proxy
    # ──────────────────────────────────────────

    def _seed_scan_tree(self, target_url: str):
        """Access the target through ZAP proxy to seed the scan tree."""
        logger.info(f"Seeding scan tree for: {target_url}")
        try:
            proxies = {"http": self.zap_url, "https": self.zap_url}
            requests.get(target_url, proxies=proxies, timeout=20, verify=False)
        except Exception as e:
            logger.warning(f"Seed request failed (non-fatal): {e}")

    # ──────────────────────────────────────────
    # Step 2: Spider scan
    # ──────────────────────────────────────────

    def _run_spider(self, target_url: str) -> Optional[str]:
        """Trigger ZAP spider and return scan ID."""
        logger.info(f"Starting spider scan on: {target_url}")
        data = self._get("/JSON/spider/action/scan/", {"url": target_url, "recurse": "true"})
        scan_id = data.get("scan")
        if scan_id is None:
            logger.error("Spider scan did not return a scan ID")
            return None
        logger.info(f"Spider scan ID: {scan_id}")
        completed = self._wait_for_completion(
            "/JSON/spider/view/status/", scan_id, self.spider_timeout, "Spider"
        )
        return scan_id if completed else None

    # ──────────────────────────────────────────
    # Step 3: Active scan
    # ──────────────────────────────────────────

    def _run_active_scan(self, target_url: str) -> Optional[str]:
        """Trigger ZAP active scan and return scan ID."""
        logger.info(f"Starting active scan on: {target_url}")
        data = self._get("/JSON/ascan/action/scan/", {"url": target_url, "recurse": "true"})
        scan_id = data.get("scan")
        if scan_id is None:
            logger.error("Active scan did not return a scan ID")
            return None
        logger.info(f"Active scan ID: {scan_id}")
        completed = self._wait_for_completion(
            "/JSON/ascan/view/status/", scan_id, self.ascan_timeout, "Active Scan"
        )
        return scan_id if completed else None

    # ──────────────────────────────────────────
    # Step 4: Fetch raw alerts
    # ──────────────────────────────────────────

    def _fetch_alerts(self, target_url: str) -> list:
        """Fetch all alerts from ZAP for the target URL."""
        logger.info(f"Fetching alerts for: {target_url}")
        data = self._get("/JSON/core/view/alerts/", {"baseurl": target_url})
        alerts = data.get("alerts", [])
        logger.info(f"Raw alerts fetched: {len(alerts)}")
        return alerts

    # ──────────────────────────────────────────
    # Step 5: Normalize alerts → our schema
    # ──────────────────────────────────────────

    def _normalize(self, alerts: list, scan_id: str) -> list:
        """
        Convert raw ZAP alerts into our normalized finding schema.
        
        Output schema per finding:
        {
            "vuln_id":        str  — unique ID for this finding
            "scan_id":        str  — parent scan ID
            "tool":           str  — always "zap"
            "plugin_id":      str  — ZAP plugin ID
            "vuln_type":      str  — human-readable vulnerability name
            "owasp_category": str  — OWASP Top 10 2021 category
            "cvss_score":     float — from CVSS_MAP based on ZAP risk level
            "severity":       str  — Critical / High / Medium / Low / Informational
            "confidence":     str  — High / Medium / Low
            "evidence":       str  — what ZAP found as proof
            "affected_url":   str  — URL where the issue was found
            "method":         str  — HTTP method (GET/POST)
            "param":          str  — affected parameter
            "attack":         str  — payload ZAP used
            "description":    str  — full description
            "solution":       str  — ZAP's recommended fix
            "cwe_id":         str  — CWE ID
            "recommendation": str  — empty string, filled later by AI layer
            "business_impact":str  — empty string, filled later by AI layer
        }
        """
        findings = []
        seen = set()  # deduplicate by (plugin_id, affected_url, param)

        # Skip pure informational noise
        SKIP_RISK_LEVELS = {"Informational"}
        SKIP_PLUGIN_IDS  = {"10112", "10111", "10104"}  # session ID, auth req, user-agent fuzzer

        for alert in alerts:
            risk      = alert.get("risk", "Informational")
            plugin_id = str(alert.get("pluginId", ""))

            # Filter noise
            if risk in SKIP_RISK_LEVELS:
                continue
            if plugin_id in SKIP_PLUGIN_IDS:
                continue

            # Deduplicate
            dedup_key = (plugin_id, alert.get("url", ""), alert.get("param", ""))
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # OWASP mapping
            owasp_category, vuln_type = OWASP_MAP.get(plugin_id, DEFAULT_OWASP)
            # Use ZAP's own alert name if we don't have a specific mapping
            if plugin_id not in OWASP_MAP:
                vuln_type = alert.get("name", vuln_type)

            # CVSS score
            cvss_score = CVSS_MAP.get(risk, 0.0)

            finding = {
                "vuln_id":         str(uuid.uuid4()),
                "scan_id":         scan_id,
                "tool":            "zap",
                "plugin_id":       plugin_id,
                "vuln_type":       vuln_type,
                "owasp_category":  owasp_category,
                "cvss_score":      cvss_score,
                "severity":        risk,
                "confidence":      alert.get("confidence", ""),
                "evidence":        alert.get("evidence", ""),
                "affected_url":    alert.get("url", ""),
                "method":          alert.get("method", "GET"),
                "param":           alert.get("param", ""),
                "attack":          alert.get("attack", ""),
                "description":     alert.get("description", ""),
                "solution":        alert.get("solution", ""),
                "cwe_id":          str(alert.get("cweid", "")),
                "recommendation":  "",   # filled by AI layer (Phase 2)
                "business_impact": "",   # filled by AI layer (Phase 2)
            }
            findings.append(finding)

        # Sort by CVSS score descending (most critical first)
        findings.sort(key=lambda x: x["cvss_score"], reverse=True)
        logger.info(f"Normalized findings (after dedup + filter): {len(findings)}")
        return findings

    # ──────────────────────────────────────────
    # Public API: run_full_scan
    # ──────────────────────────────────────────

    def run_full_scan(self, target_url: str, scan_id: Optional[str] = None, skip_active_scan: bool = False) -> dict:
        """
        Run a full ZAP scan: seed → spider → active scan → normalize findings.

        Args:
            target_url: The URL to scan (e.g. "http://example.com")
            scan_id:    Optional parent scan ID (generated if not provided)

        Returns:
            {
                "scan_id":   str,
                "target":    str,
                "status":    "completed" | "failed",
                "findings":  list of normalized finding dicts,
                "summary": {
                    "total":    int,
                    "critical": int,
                    "high":     int,
                    "medium":   int,
                    "low":      int,
                }
            }
        """
        if scan_id is None:
            scan_id = str(uuid.uuid4())

        logger.info(f"=== Starting full ZAP scan | scan_id={scan_id} | target={target_url} ===")

        result = {
            "scan_id":  scan_id,
            "target":   target_url,
            "status":   "failed",
            "findings": [],
            "summary":  {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        }

        try:
            # Step 1: Seed
            self._seed_scan_tree(target_url)

            # Step 2: Spider
            spider_id = self._run_spider(target_url)
            if spider_id is None:
                logger.error("Spider scan failed or timed out")
                return result

            # Step 3: Active scan (skippable to reuse existing ZAP results)
            if not skip_active_scan:
                ascan_id = self._run_active_scan(target_url)
                if ascan_id is None:
                    logger.warning("Active scan failed or timed out — returning spider-only results")
            else:
                logger.info("Skipping active scan — fetching existing ZAP alerts")

            # Step 4: Fetch alerts
            raw_alerts = self._fetch_alerts(target_url)

            # Step 5: Normalize
            findings = self._normalize(raw_alerts, scan_id)

            # Build summary
            summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in findings:
                sev = f["severity"].lower()
                if sev in summary:
                    summary[sev] += 1

            result["status"]   = "completed"
            result["findings"] = findings
            result["summary"]  = summary

            logger.info(f"=== Scan complete | {summary} ===")
            return result

        except Exception as e:
            logger.error(f"Scan failed with exception: {e}")
            return result


# ──────────────────────────────────────────────
# Quick test — run this file directly to verify
# ──────────────────────────────────────────────
if __name__ == "__main__":
    import json

    scanner = ZAPScanner(
        zap_url="http://localhost:8080",
        spider_timeout=300,
        ascan_timeout=1800,
        poll_interval=15,
    )

    result = scanner.run_full_scan("http://host.docker.internal:8888", skip_active_scan=True)

    print("\n" + "="*60)
    print(f"Scan ID : {result['scan_id']}")
    print(f"Target  : {result['target']}")
    print(f"Status  : {result['status']}")
    print(f"Summary : {result['summary']}")
    print("="*60)
    print("\nTop 5 findings:\n")
    for f in result["findings"][:5]:
        print(f"  [{f['severity']}] {f['vuln_type']}")
        print(f"    OWASP    : {f['owasp_category']}")
        print(f"    CVSS     : {f['cvss_score']}")
        print(f"    URL      : {f['affected_url']}")
        print(f"    Evidence : {f['evidence'][:80] if f['evidence'] else 'N/A'}")
        print()

    # Save full output to file
    with open("scan_result.json", "w") as fp:
        json.dump(result, fp, indent=2)
    print("Full output saved to scan_result.json")