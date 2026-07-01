"""
HTTP Header Scanner Module
==========================
Passive scanner — checks for missing or misconfigured HTTP security headers.
No attack payloads sent. Pure header inspection.

Checks for:
    - Content-Security-Policy
    - X-Frame-Options
    - X-Content-Type-Options
    - Strict-Transport-Security (HSTS)
    - Referrer-Policy
    - Permissions-Policy
    - X-XSS-Protection (legacy but still checked)

Usage:
    from scanner.modules.header_scanner import HeaderScanner
    scanner = HeaderScanner()
    result = scanner.run_scan("https://example.com")
"""

import uuid
import logging
import requests
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [Headers] %(message)s")
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Security headers we check for
# Each entry: header_name → (owasp_category, cvss_score, severity, description, fix)
# ──────────────────────────────────────────────
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "A05:2021 - Security Misconfiguration",
        5.3,
        "Medium",
        "Content Security Policy (CSP) header is not set. This allows attackers to inject malicious scripts via XSS attacks.",
        "Add Content-Security-Policy header. Example: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
    ),
    "X-Frame-Options": (
        "A05:2021 - Security Misconfiguration",
        5.3,
        "Medium",
        "X-Frame-Options header is missing. The site may be vulnerable to clickjacking attacks where an attacker embeds the page in an iframe.",
        "Add X-Frame-Options: DENY or SAMEORIGIN header. For Nginx: add_header X-Frame-Options DENY; For Apache: Header always set X-Frame-Options DENY",
    ),
    "X-Content-Type-Options": (
        "A05:2021 - Security Misconfiguration",
        3.1,
        "Low",
        "X-Content-Type-Options header is not set. Browsers may perform MIME-type sniffing, potentially executing malicious content.",
        "Add X-Content-Type-Options: nosniff header to all responses.",
    ),
    "Strict-Transport-Security": (
        "A02:2021 - Cryptographic Failures",
        5.9,
        "Medium",
        "HTTP Strict Transport Security (HSTS) header is missing. Users may be vulnerable to SSL stripping attacks.",
        "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload header.",
    ),
    "Referrer-Policy": (
        "A05:2021 - Security Misconfiguration",
        3.1,
        "Low",
        "Referrer-Policy header is not set. Sensitive URL parameters may leak to third parties via the Referer header.",
        "Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer header.",
    ),
    "Permissions-Policy": (
        "A05:2021 - Security Misconfiguration",
        3.1,
        "Low",
        "Permissions-Policy header is missing. Browser features like camera, microphone, and geolocation are not restricted.",
        "Add Permissions-Policy header. Example: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    ),
    "X-XSS-Protection": (
        "A05:2021 - Security Misconfiguration",
        3.1,
        "Low",
        "X-XSS-Protection header is not set. While deprecated in modern browsers, older browsers lack XSS filter activation.",
        "Add X-XSS-Protection: 1; mode=block header for legacy browser support.",
    ),
}

# Headers that should NOT be present (information leakage)
DANGEROUS_HEADERS = {
    "Server": (
        "A05:2021 - Security Misconfiguration",
        3.1,
        "Low",
        "Server header reveals web server software and version, aiding attackers in targeting known vulnerabilities.",
        "Configure your web server to suppress or genericise the Server header. For Nginx: server_tokens off; For Apache: ServerTokens Prod",
    ),
    "X-Powered-By": (
        "A05:2021 - Security Misconfiguration",
        3.1,
        "Low",
        "X-Powered-By header reveals the backend technology stack, helping attackers identify exploitable components.",
        "Remove X-Powered-By header. For Express.js: app.disable('x-powered-by'); For PHP: expose_php = Off in php.ini",
    ),
    "X-AspNet-Version": (
        "A05:2021 - Security Misconfiguration",
        3.1,
        "Low",
        "X-AspNet-Version header exposes the ASP.NET version being used.",
        "Remove X-AspNet-Version by adding <httpRuntime enableVersionHeader='false'/> in web.config",
    ),
}


class HeaderScanner:
    """
    Passive HTTP security header scanner.

    Args:
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
    """

    def __init__(self, timeout: int = 15, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"
        })

    def _fetch_headers(self, url: str) -> dict:
        """Fetch HTTP response headers from the target URL."""
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True,
            )
            logger.info(f"Fetched headers from {url} — status {response.status_code}")
            # Normalize to lowercase keys for case-insensitive comparison
            return {k.lower(): v for k, v in response.headers.items()}
        except requests.RequestException as e:
            logger.error(f"Failed to fetch headers from {url}: {e}")
            raise

    def _normalize_finding(
        self,
        scan_id: str,
        header_name: str,
        owasp_category: str,
        cvss_score: float,
        severity: str,
        description: str,
        solution: str,
        affected_url: str,
        finding_type: str = "missing_header",
        evidence: str = "",
    ) -> dict:
        """Build a normalized finding dict matching the standard schema."""
        return {
            "vuln_id":         str(uuid.uuid4()),
            "scan_id":         scan_id,
            "tool":            "header_scanner",
            "plugin_id":       f"header_{header_name.lower().replace('-', '_')}",
            "vuln_type":       f"{'Missing' if finding_type == 'missing_header' else 'Information Disclosure via'} {header_name} Header",
            "owasp_category":  owasp_category,
            "cvss_score":      cvss_score,
            "severity":        severity,
            "confidence":      "High",
            "evidence":        evidence,
            "affected_url":    affected_url,
            "method":          "GET",
            "param":           header_name.lower(),
            "attack":          "",
            "description":     description,
            "solution":        solution,
            "cwe_id":          "693",
            "recommendation":  solution,
            "business_impact": "",
        }

    def run_scan(self, target_url: str, scan_id: str = None) -> dict:
        """
        Run header security scan against the target URL.

        Args:
            target_url: URL to scan
            scan_id:    Optional parent scan ID

        Returns:
            Standard result dict with findings and summary
        """
        if scan_id is None:
            scan_id = str(uuid.uuid4())

        logger.info(f"=== Starting header scan | scan_id={scan_id} | target={target_url} ===")

        result = {
            "scan_id":  scan_id,
            "target":   target_url,
            "status":   "failed",
            "findings": [],
            "summary":  {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        }

        try:
            headers = self._fetch_headers(target_url)
            findings = []

            # Check for missing security headers
            for header_name, (owasp, cvss, severity, desc, fix) in SECURITY_HEADERS.items():
                if header_name.lower() not in headers:
                    finding = self._normalize_finding(
                        scan_id=scan_id,
                        header_name=header_name,
                        owasp_category=owasp,
                        cvss_score=cvss,
                        severity=severity,
                        description=desc,
                        solution=fix,
                        affected_url=target_url,
                        finding_type="missing_header",
                    )
                    findings.append(finding)
                    logger.info(f"Missing header: {header_name} [{severity}]")

            # Check for dangerous headers that should be removed
            for header_name, (owasp, cvss, severity, desc, fix) in DANGEROUS_HEADERS.items():
                if header_name.lower() in headers:
                    evidence = f"{header_name}: {headers[header_name.lower()]}"
                    finding = self._normalize_finding(
                        scan_id=scan_id,
                        header_name=header_name,
                        owasp_category=owasp,
                        cvss_score=cvss,
                        severity=severity,
                        description=desc,
                        solution=fix,
                        affected_url=target_url,
                        finding_type="dangerous_header",
                        evidence=evidence,
                    )
                    findings.append(finding)
                    logger.info(f"Dangerous header present: {header_name} = {headers[header_name.lower()]} [{severity}]")

            # Build summary
            summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in findings:
                sev = f["severity"].lower()
                if sev in summary:
                    summary[sev] += 1

            result["status"]   = "completed"
            result["findings"] = findings
            result["summary"]  = summary

            logger.info(f"=== Header scan complete | {summary} ===")
            return result

        except Exception as e:
            logger.error(f"Header scan failed: {e}")
            return result


# ──────────────────────────────────────────────
# Quick test
# ──────────────────────────────────────────────
if __name__ == "__main__":
    import json

    scanner = HeaderScanner()
    result = scanner.run_scan("http://host.docker.internal:8888")

    print(f"\nStatus  : {result['status']}")
    print(f"Summary : {result['summary']}")
    print(f"\nFindings:")
    for f in result["findings"]:
        print(f"  [{f['severity']}] {f['vuln_type']}")
        print(f"    OWASP : {f['owasp_category']}")
        print(f"    Fix   : {f['recommendation'][:80]}...")

    with open("header_scan_result.json", "w") as fp:
        json.dump(result, fp, indent=2)
    print("\nSaved to header_scan_result.json")