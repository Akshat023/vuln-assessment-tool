"""
Nuclei Scanner Module
======================
Wraps Nuclei CLI tool for template-based vulnerability scanning.

Nuclei excels at detecting:
    - Exposed files (.env, .git, backup files)
    - Known CVEs in web applications and frameworks
    - Default credentials and admin panels
    - Misconfigurations not covered by ZAP

Install Nuclei (Windows):
    Download from: https://github.com/projectdiscovery/nuclei/releases
    Or via Go:     go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    Or via Docker: docker pull projectdiscovery/nuclei:latest

Update templates (run once after install):
    nuclei -update-templates

Usage:
    from scanner.modules.nuclei_scanner import NucleiScanner
    scanner = NucleiScanner()
    findings = scanner.run_scan("http://host.docker.internal:8888")
"""

import subprocess
import json
import uuid
import logging
import shutil
from typing import Optional

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# CVSS mapping — same convention as ZAP scanner
# Nuclei severities: info, low, medium, high, critical
# ──────────────────────────────────────────────
CVSS_MAP = {
    "info":     0.0,
    "low":      3.1,
    "medium":   5.3,
    "high":     8.1,
    "critical": 9.8,
}

SEVERITY_DISPLAY = {
    "info":     "Informational",
    "low":      "Low",
    "medium":   "Medium",
    "high":     "High",
    "critical": "Critical",
}

# ──────────────────────────────────────────────
# OWASP Top 10 mapping by Nuclei template tags
# ──────────────────────────────────────────────
TAG_TO_OWASP = {
    "exposure":       "A05:2021 - Security Misconfiguration",
    "config":         "A05:2021 - Security Misconfiguration",
    "misconfig":      "A05:2021 - Security Misconfiguration",
    "cve":            "A06:2021 - Vulnerable and Outdated Components",
    "default-login":  "A07:2021 - Identification and Authentication Failures",
    "panel":          "A01:2021 - Broken Access Control",
    "exposed-panel":  "A01:2021 - Broken Access Control",
    "takeover":       "A01:2021 - Broken Access Control",
    "sqli":           "A03:2021 - Injection",
    "xss":            "A03:2021 - Injection",
    "rce":            "A03:2021 - Injection",
    "ssrf":           "A10:2021 - Server-Side Request Forgery",
    "lfi":            "A01:2021 - Broken Access Control",
    "redirect":       "A01:2021 - Broken Access Control",
}

DEFAULT_OWASP = "A05:2021 - Security Misconfiguration"


class NucleiScanner:
    """
    Wraps the Nuclei CLI tool.

    Args:
        nuclei_path: Path to nuclei binary (default: assumes it's in PATH)
        templates:   Comma-separated template tags to run
                     (default: cves,exposures,misconfiguration,default-logins)
        timeout:     Max seconds to wait for scan completion
        rate_limit:  Max requests per second (be respectful to target)
    """

    def __init__(
        self,
        nuclei_path: str = "nuclei",
        templates: str = "cves,exposures,misconfiguration,default-logins,exposed-panels",
        timeout: int = 600,
        rate_limit: int = 50,
    ):
        self.nuclei_path = nuclei_path
        self.templates = templates
        self.timeout = timeout
        self.rate_limit = rate_limit

        if shutil.which(nuclei_path) is None:
            logger.warning(
                f"Nuclei binary '{nuclei_path}' not found in PATH. "
                "Install from https://github.com/projectdiscovery/nuclei/releases"
            )

    def _map_owasp(self, tags: list) -> str:
        """Map Nuclei template tags to an OWASP Top 10 category."""
        for tag in tags:
            if tag.lower() in TAG_TO_OWASP:
                return TAG_TO_OWASP[tag.lower()]
        return DEFAULT_OWASP

    def _run_nuclei_cli(self, target_url: str) -> list:
        """
        Run nuclei as a subprocess and parse JSONL output.
        Returns list of raw nuclei result dicts.
        """
        cmd = [
            self.nuclei_path,
            "-u", target_url,
            "-tags", self.templates,
            "-jsonl",            # JSON Lines output, one finding per line
            "-silent",           # suppress banner/progress noise
            "-rate-limit", str(self.rate_limit),
            "-timeout", "10",    # per-request timeout
            "-no-color",
        ]

        logger.info(f"Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            logger.error(f"Nuclei scan timed out after {self.timeout}s")
            return []
        except FileNotFoundError:
            logger.error(f"Nuclei binary not found: {self.nuclei_path}")
            return []

        if result.returncode not in (0, 1):  # 1 = findings found, still valid
            logger.warning(f"Nuclei exited with code {result.returncode}: {result.stderr[:300]}")

        raw_findings = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                raw_findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        logger.info(f"Nuclei raw findings: {len(raw_findings)}")
        return raw_findings

    def _normalize(self, raw_findings: list, scan_id: str) -> list:
        """Convert raw Nuclei JSON output into our normalized finding schema."""
        findings = []

        for item in raw_findings:
            info = item.get("info", {})
            severity = info.get("severity", "info").lower()
            tags = info.get("tags", [])

            finding = {
                "vuln_id":         str(uuid.uuid4()),
                "scan_id":         scan_id,
                "tool":            "nuclei",
                "plugin_id":       item.get("template-id", ""),
                "vuln_type":       info.get("name", "Unknown Issue"),
                "owasp_category":  self._map_owasp(tags),
                "cvss_score":      CVSS_MAP.get(severity, 0.0),
                "severity":        SEVERITY_DISPLAY.get(severity, "Informational"),
                "confidence":      "High",  # Nuclei templates are signature-based, high confidence
                "evidence":        item.get("matched-at", item.get("matcher-name", "")),
                "affected_url":    item.get("matched-at", item.get("host", "")),
                "method":          item.get("request", "").split(" ")[0] if item.get("request") else "GET",
                "param":           "",
                "attack":          "",
                "description":     info.get("description", ""),
                "solution":        info.get("remediation", "Review the finding and apply vendor-recommended fixes."),
                "cwe_id":          ", ".join(info.get("classification", {}).get("cwe-id", []) or []),
                "recommendation":  "",
                "business_impact": "",
            }
            findings.append(finding)

        # Sort by CVSS descending
        findings.sort(key=lambda x: x["cvss_score"], reverse=True)
        return findings

    def run_scan(self, target_url: str, scan_id: Optional[str] = None) -> dict:
        """
        Run a full Nuclei scan.

        Args:
            target_url: URL to scan
            scan_id:    Optional parent scan ID

        Returns:
            {
                "scan_id":  str,
                "target":   str,
                "status":   "completed" | "failed",
                "findings": list of normalized finding dicts,
                "summary":  {"total", "critical", "high", "medium", "low"}
            }
        """
        if scan_id is None:
            scan_id = str(uuid.uuid4())

        logger.info(f"=== Starting Nuclei scan | scan_id={scan_id} | target={target_url} ===")

        result = {
            "scan_id":  scan_id,
            "target":   target_url,
            "status":   "failed",
            "findings": [],
            "summary":  {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        }

        try:
            raw_findings = self._run_nuclei_cli(target_url)
            findings = self._normalize(raw_findings, scan_id)

            summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in findings:
                sev = f["severity"].lower()
                if sev in summary:
                    summary[sev] += 1

            result["status"] = "completed"
            result["findings"] = findings
            result["summary"] = summary

            logger.info(f"=== Nuclei scan complete | {summary} ===")
            return result

        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
            return result


# ──────────────────────────────────────────────
# Quick test
# ──────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [Nuclei] %(message)s")

    scanner = NucleiScanner()
    result = scanner.run_scan("http://host.docker.internal:8888")

    print("\n" + "=" * 60)
    print(f"Scan ID : {result['scan_id']}")
    print(f"Status  : {result['status']}")
    print(f"Summary : {result['summary']}")
    print("=" * 60)

    for f in result["findings"][:5]:
        print(f"\n[{f['severity']}] {f['vuln_type']}")
        print(f"  OWASP : {f['owasp_category']}")
        print(f"  CVSS  : {f['cvss_score']}")
        print(f"  URL   : {f['affected_url']}")

    with open("nuclei_result.json", "w") as fp:
        json.dump(result, fp, indent=2)
    print("\nFull output saved to nuclei_result.json")