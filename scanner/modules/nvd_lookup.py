"""
CVE/NVD Lookup Module
======================
Cross-references detected software versions against the NVD (National
Vulnerability Database) to find known CVEs.

Uses the free NVD REST API v2 — no API key required for basic usage,
though rate limits apply (5 requests per 30 seconds without a key).

NVD API docs: https://nvd.nist.gov/developers/vulnerabilities

Usage:
    from scanner.modules.nvd_lookup import NVDLookup
    lookup = NVDLookup()
    result = lookup.run_scan(technologies=[
        {"name": "Apache", "version": "2.4.25"},
        {"name": "PHP", "version": "7.0.0"},
    ], target_url="http://example.com", scan_id="abc-123")
"""

import uuid
import time
import logging
import requests
from typing import Optional

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# CVSS severity thresholds
def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0:
        return "Low"
    return "Informational"

# OWASP mapping for CVEs
CVE_OWASP = "A06:2021 - Vulnerable and Outdated Components"


class NVDLookup:
    """
    Looks up known CVEs for detected software versions via NVD API.

    Args:
        api_key:       Optional NVD API key for higher rate limits
                       Get one free at: https://nvd.nist.gov/developers/request-an-api-key
        results_per_tech: Max CVEs to return per technology (default: 5)
        request_delay:    Seconds to wait between API calls (respect rate limits)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        results_per_tech: int = 5,
        request_delay: float = 6.0,
    ):
        self.api_key = api_key
        self.results_per_tech = results_per_tech
        self.request_delay = request_delay
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"apiKey": api_key})

    def _search_cves(self, keyword: str, version: str = "") -> list:
        """
        Search NVD for CVEs matching a technology and version.
        Returns list of CVE dicts.
        """
        params = {
            "keywordSearch": f"{keyword} {version}".strip(),
            "resultsPerPage": self.results_per_tech,
        }

        try:
            resp = self.session.get(NVD_API_BASE, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return data.get("vulnerabilities", [])
        except requests.RequestException as e:
            logger.error(f"NVD API request failed for '{keyword} {version}': {e}")
            return []

    def _extract_cvss_score(self, cve_item: dict) -> tuple:
        """Extract the highest CVSS score and version from a CVE item."""
        metrics = cve_item.get("cve", {}).get("metrics", {})

        # Try CVSS v3.1 first, then v3.0, then v2
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                data = metric_list[0].get("cvssData", {})
                score = data.get("baseScore", 0.0)
                vector = data.get("vectorString", "")
                return float(score), vector

        return 0.0, ""

    def _cve_to_finding(
        self,
        cve_item: dict,
        tech_name: str,
        tech_version: str,
        target_url: str,
        scan_id: str,
    ) -> Optional[dict]:
        """Convert a NVD CVE item into a normalized finding."""
        cve = cve_item.get("cve", {})
        cve_id = cve.get("id", "Unknown")

        # Get description
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )

        # Get CVSS score
        cvss_score, vector = self._extract_cvss_score(cve_item)

        # Skip info-only CVEs
        if cvss_score == 0.0:
            return None

        severity = cvss_to_severity(cvss_score)

        # Get references
        refs = cve.get("references", [])
        ref_url = refs[0].get("url", "") if refs else ""

        return {
            "vuln_id":         str(uuid.uuid4()),
            "scan_id":         scan_id,
            "tool":            "nvd_lookup",
            "plugin_id":       cve_id,
            "vuln_type":       f"Known CVE in {tech_name} {tech_version} ({cve_id})",
            "owasp_category":  CVE_OWASP,
            "cvss_score":      cvss_score,
            "severity":        severity,
            "confidence":      "High",
            "evidence":        f"{cve_id} affects {tech_name} {tech_version}. CVSS: {cvss_score} ({vector})",
            "affected_url":    target_url,
            "method":          "GET",
            "param":           "",
            "attack":          "",
            "description":     f"{cve_id}: {description[:500]}",
            "solution":        f"Update {tech_name} to the latest stable version. Reference: {ref_url}",
            "cwe_id":          "",
            "recommendation":  f"Upgrade {tech_name} from version {tech_version} to the latest stable release to patch {cve_id}.",
            "business_impact": f"This known vulnerability ({cve_id}) in {tech_name} {tech_version} may allow attackers to compromise the system. CVSS score {cvss_score} indicates {severity.lower()} risk.",
        }

    def lookup_technology(
        self,
        tech_name: str,
        tech_version: str,
        target_url: str,
        scan_id: str,
    ) -> list:
        """
        Look up CVEs for a single technology + version combination.
        Returns list of normalized findings.
        """
        if not tech_version:
            logger.info(f"Skipping NVD lookup for {tech_name} — no version detected")
            return []

        logger.info(f"NVD lookup: {tech_name} {tech_version}")
        cve_items = self._search_cves(tech_name, tech_version)

        findings = []
        for item in cve_items:
            finding = self._cve_to_finding(item, tech_name, tech_version, target_url, scan_id)
            if finding:
                findings.append(finding)

        logger.info(f"Found {len(findings)} CVEs for {tech_name} {tech_version}")
        return findings

    def run_scan(
        self,
        technologies: list,
        target_url: str,
        scan_id: Optional[str] = None,
    ) -> dict:
        """
        Look up CVEs for a list of detected technologies.

        Args:
            technologies: List of dicts with "name" and "version" keys
                          (output from TechFingerprinter)
            target_url:   The scanned URL
            scan_id:      Optional parent scan ID

        Returns:
            Standard result dict with CVE findings
        """
        if scan_id is None:
            scan_id = str(uuid.uuid4())

        logger.info(f"=== Starting NVD lookup | scan_id={scan_id} | techs={len(technologies)} ===")

        result = {
            "scan_id":  scan_id,
            "target":   target_url,
            "status":   "failed",
            "findings": [],
            "summary":  {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        }

        all_findings = []

        # Only look up techs where we have a version — no point searching without it
        techs_with_version = [t for t in technologies if t.get("version")]

        if not techs_with_version:
            logger.info("No technologies with known versions — skipping NVD lookup")
            result["status"] = "completed"
            result["findings"] = []
            result["summary"] = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            return result

        for i, tech in enumerate(techs_with_version):
            findings = self.lookup_technology(
                tech_name=tech["name"],
                tech_version=tech["version"],
                target_url=target_url,
                scan_id=scan_id,
            )
            all_findings.extend(findings)

            # Rate limiting — NVD allows 5 req/30s without API key
            if i < len(techs_with_version) - 1:
                logger.info(f"Rate limiting pause: {self.request_delay}s")
                time.sleep(self.request_delay)

        # Sort by CVSS descending
        all_findings.sort(key=lambda x: x["cvss_score"], reverse=True)

        summary = {"total": len(all_findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in all_findings:
            sev = f["severity"].lower()
            if sev in summary:
                summary[sev] += 1

        result["status"]   = "completed"
        result["findings"] = all_findings
        result["summary"]  = summary

        logger.info(f"=== NVD lookup complete | {summary} ===")
        return result


# ──────────────────────────────────────────────
# Quick test
# ──────────────────────────────────────────────
if __name__ == "__main__":
    import json

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [NVD] %(message)s")

    # Test with Apache 2.4.25 — known vulnerable version
    lookup = NVDLookup()
    result = lookup.run_scan(
        technologies=[
            {"name": "Apache", "version": "2.4.25"},
            {"name": "PHP",    "version": "7.0.0"},
        ],
        target_url="http://localhost:8888",
    )

    print(f"\nStatus  : {result['status']}")
    print(f"Summary : {result['summary']}")
    print(f"\nTop CVE findings:")
    for f in result["findings"][:5]:
        print(f"  [{f['severity']}] {f['vuln_type']}")
        print(f"    CVSS     : {f['cvss_score']}")
        print(f"    Evidence : {f['evidence'][:100]}")

    with open("nvd_result.json", "w") as fp:
        json.dump(result, fp, indent=2)
    print("\nSaved to nvd_result.json")