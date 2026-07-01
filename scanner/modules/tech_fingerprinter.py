"""
Technology Fingerprinting Module
=================================
Detects web technologies (CMS, frameworks, server software, JS libraries)
by analyzing HTTP headers, response body patterns, and known signatures.

Does NOT send attack payloads — pure passive detection.

Detects:
    - Web servers (Apache, Nginx, IIS, LiteSpeed)
    - CMS (WordPress, Drupal, Joomla, Magento)
    - Frameworks (Laravel, Django, Rails, Express, ASP.NET)
    - JS libraries (jQuery, React, Angular, Vue)
    - Programming languages (PHP, Python, Ruby, Java)
    - CDN / WAF (Cloudflare, Akamai, Fastly)

Usage:
    from scanner.modules.tech_fingerprinter import TechFingerprinter
    scanner = TechFingerprinter()
    result = scanner.run_scan("http://example.com")
"""

import uuid
import re
import logging
import requests
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Technology signatures
# Format: tech_name → list of detection rules
# Each rule: {"type": "header|body|url", "pattern": regex, "header": header_name}
# ──────────────────────────────────────────────
TECH_SIGNATURES = {
    # ── Web Servers ──────────────────────────
    "Apache": [
        {"type": "header", "header": "server", "pattern": r"Apache"},
        {"type": "header", "header": "x-powered-by", "pattern": r"Apache"},
    ],
    "Nginx": [
        {"type": "header", "header": "server", "pattern": r"nginx"},
    ],
    "Microsoft IIS": [
        {"type": "header", "header": "server", "pattern": r"IIS"},
        {"type": "header", "header": "x-powered-by", "pattern": r"ASP\.NET"},
    ],
    "LiteSpeed": [
        {"type": "header", "header": "server", "pattern": r"LiteSpeed"},
    ],

    # ── CMS ───────────────────────────────────
    "WordPress": [
        {"type": "body", "pattern": r"wp-content|wp-includes|wordpress"},
        {"type": "body", "pattern": r"/wp-json/"},
        {"type": "header", "header": "x-powered-by", "pattern": r"WordPress"},
    ],
    "Drupal": [
        {"type": "body", "pattern": r"Drupal|drupal\.js|drupal\.css"},
        {"type": "header", "header": "x-generator", "pattern": r"Drupal"},
    ],
    "Joomla": [
        {"type": "body", "pattern": r"joomla|/components/com_"},
        {"type": "body", "pattern": r"Joomla!"},
    ],
    "Magento": [
        {"type": "body", "pattern": r"Magento|mage/cookies"},
        {"type": "header", "header": "x-powered-by", "pattern": r"Magento"},
    ],
    "Shopify": [
        {"type": "body", "pattern": r"cdn\.shopify\.com|Shopify\.theme"},
        {"type": "header", "header": "x-served-by", "pattern": r"shopify"},
    ],

    # ── Frameworks ────────────────────────────
    "Laravel": [
        {"type": "header", "header": "set-cookie", "pattern": r"laravel_session"},
        {"type": "body", "pattern": r"Laravel"},
    ],
    "Django": [
        {"type": "header", "header": "x-frame-options", "pattern": r"SAMEORIGIN"},
        {"type": "header", "header": "set-cookie", "pattern": r"csrftoken|sessionid"},
    ],
    "Ruby on Rails": [
        {"type": "header", "header": "x-powered-by", "pattern": r"Phusion Passenger"},
        {"type": "header", "header": "set-cookie", "pattern": r"_session_id"},
    ],
    "ASP.NET": [
        {"type": "header", "header": "x-powered-by", "pattern": r"ASP\.NET"},
        {"type": "header", "header": "x-aspnet-version", "pattern": r"\d+\.\d+"},
        {"type": "header", "header": "set-cookie", "pattern": r"ASP\.NET_SessionId"},
    ],
    "Express.js": [
        {"type": "header", "header": "x-powered-by", "pattern": r"Express"},
    ],
    "Next.js": [
        {"type": "header", "header": "x-powered-by", "pattern": r"Next\.js"},
        {"type": "body", "pattern": r"__NEXT_DATA__"},
    ],

    # ── Programming Languages ─────────────────
    "PHP": [
        {"type": "header", "header": "x-powered-by", "pattern": r"PHP"},
        {"type": "header", "header": "set-cookie", "pattern": r"PHPSESSID"},
    ],
    "Python": [
        {"type": "header", "header": "x-powered-by", "pattern": r"Python|Django|Flask"},
        {"type": "header", "header": "server", "pattern": r"Python|gunicorn|uvicorn"},
    ],
    "Java": [
        {"type": "header", "header": "x-powered-by", "pattern": r"JSP|Servlet|Java"},
        {"type": "header", "header": "set-cookie", "pattern": r"JSESSIONID"},
    ],

    # ── JavaScript Libraries ──────────────────
    "jQuery": [
        {"type": "body", "pattern": r"jquery[\.\-][\d\.]+\.min\.js|jquery\.js"},
    ],
    "React": [
        {"type": "body", "pattern": r"react\.min\.js|react-dom|__reactInternalInstance"},
    ],
    "Angular": [
        {"type": "body", "pattern": r"angular\.min\.js|ng-version|ng-app"},
    ],
    "Vue.js": [
        {"type": "body", "pattern": r"vue\.min\.js|vue\.js|__vue__"},
    ],
    "Bootstrap": [
        {"type": "body", "pattern": r"bootstrap\.min\.js|bootstrap\.min\.css"},
    ],

    # ── CDN / WAF ─────────────────────────────
    "Cloudflare": [
        {"type": "header", "header": "cf-ray", "pattern": r".+"},
        {"type": "header", "header": "server", "pattern": r"cloudflare"},
    ],
    "Akamai": [
        {"type": "header", "header": "x-check-cacheable", "pattern": r".+"},
        {"type": "header", "header": "x-akamai-transformed", "pattern": r".+"},
    ],
}

# Version extraction patterns per technology
VERSION_PATTERNS = {
    "Apache":        r"Apache/([\d\.]+)",
    "Nginx":         r"nginx/([\d\.]+)",
    "Microsoft IIS": r"IIS/([\d\.]+)",
    "PHP":           r"PHP/([\d\.]+)",
    "ASP.NET":       r"ASP\.NET Version:([\d\.]+)|X-AspNet-Version: ([\d\.]+)",
}


class TechFingerprinter:
    """
    Passive technology fingerprinting scanner.

    Args:
        timeout:    Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
    """

    def __init__(self, timeout: int = 15, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    def _fetch(self, url: str) -> tuple:
        """Fetch page and return (headers_dict, body_text)."""
        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True,
            )
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.text[:50000]  # limit body size for pattern matching
            logger.info(f"Fetched {url} — {resp.status_code} — {len(body)} chars")
            return headers, body
        except requests.RequestException as e:
            logger.error(f"Failed to fetch {url}: {e}")
            raise

    def _extract_version(self, tech_name: str, headers: dict, body: str) -> str:
        """Try to extract a version string for a detected technology."""
        pattern = VERSION_PATTERNS.get(tech_name)
        if not pattern:
            return ""
        # Search headers
        for header_val in headers.values():
            match = re.search(pattern, header_val, re.IGNORECASE)
            if match:
                return match.group(1) or match.group(0)
        # Search body
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            return match.group(1) or match.group(0)
        return ""

    def _detect_technologies(self, headers: dict, body: str) -> list:
        """
        Run all signatures against headers and body.
        Returns list of detected tech dicts: {name, version, category}
        """
        detected = []

        for tech_name, rules in TECH_SIGNATURES.items():
            for rule in rules:
                matched = False
                if rule["type"] == "header":
                    header_val = headers.get(rule["header"], "")
                    if re.search(rule["pattern"], header_val, re.IGNORECASE):
                        matched = True
                elif rule["type"] == "body":
                    if re.search(rule["pattern"], body, re.IGNORECASE):
                        matched = True

                if matched:
                    version = self._extract_version(tech_name, headers, body)
                    detected.append({
                        "name":    tech_name,
                        "version": version,
                    })
                    break  # one rule match per tech is enough

        return detected

    def _technologies_to_findings(
        self,
        detected: list,
        target_url: str,
        scan_id: str,
        headers: dict,
    ) -> list:
        """
        Convert detected technologies into normalized findings.
        Detected tech itself isn't a vulnerability, but version disclosure
        and outdated versions are flagged.
        """
        findings = []

        # Flag version disclosure for server software
        version_disclosing_techs = {"Apache", "Nginx", "Microsoft IIS", "PHP", "ASP.NET"}

        for tech in detected:
            name = tech["name"]
            version = tech["version"]

            if name in version_disclosing_techs and version:
                findings.append({
                    "vuln_id":         str(uuid.uuid4()),
                    "scan_id":         scan_id,
                    "tool":            "tech_fingerprinter",
                    "plugin_id":       f"tech_{name.lower().replace(' ', '_')}_version",
                    "vuln_type":       f"Technology Version Disclosure ({name})",
                    "owasp_category":  "A05:2021 - Security Misconfiguration",
                    "cvss_score":      3.1,
                    "severity":        "Low",
                    "confidence":      "High",
                    "evidence":        f"{name} {version} detected via response headers",
                    "affected_url":    target_url,
                    "method":          "GET",
                    "param":           "",
                    "attack":          "",
                    "description":     f"The server discloses it is running {name} version {version}. This information helps attackers identify known vulnerabilities for this specific version.",
                    "solution":        f"Configure {name} to suppress version information. Suppress the Server/X-Powered-By headers.",
                    "cwe_id":          "497",
                    "recommendation":  f"Hide {name} version disclosure in server configuration.",
                    "business_impact": "Version disclosure aids attackers in identifying and exploiting known CVEs for the specific software version in use.",
                })

        return findings

    def run_scan(self, target_url: str, scan_id: str = None) -> dict:
        """
        Run technology fingerprinting scan.

        Returns:
            Standard result dict with:
            - findings: version disclosure findings
            - technologies: list of all detected technologies (in metadata)
        """
        if scan_id is None:
            scan_id = str(uuid.uuid4())

        logger.info(f"=== Starting tech fingerprint | scan_id={scan_id} | target={target_url} ===")

        result = {
            "scan_id":      scan_id,
            "target":       target_url,
            "status":       "failed",
            "findings":     [],
            "technologies": [],
            "summary":      {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        }

        try:
            headers, body = self._fetch(target_url)
            detected = self._detect_technologies(headers, body)

            logger.info(f"Detected {len(detected)} technologies: {[t['name'] for t in detected]}")

            findings = self._technologies_to_findings(detected, target_url, scan_id, headers)

            summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in findings:
                sev = f["severity"].lower()
                if sev in summary:
                    summary[sev] += 1

            result["status"]       = "completed"
            result["findings"]     = findings
            result["technologies"] = detected
            result["summary"]      = summary

            logger.info(f"=== Tech fingerprint complete | {summary} ===")
            return result

        except Exception as e:
            logger.error(f"Tech fingerprint failed: {e}")
            return result


# ──────────────────────────────────────────────
# Quick test
# ──────────────────────────────────────────────
if __name__ == "__main__":
    import json

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [Tech] %(message)s")

    scanner = TechFingerprinter()
    result = scanner.run_scan("http://localhost:8888")

    print(f"\nStatus       : {result['status']}")
    print(f"Technologies : {[t['name'] + (' ' + t['version'] if t['version'] else '') for t in result['technologies']]}")
    print(f"Summary      : {result['summary']}")
    print(f"\nFindings:")
    for f in result["findings"]:
        print(f"  [{f['severity']}] {f['vuln_type']}")
        print(f"    Evidence : {f['evidence']}")

    with open("tech_fingerprint_result.json", "w") as fp:
        json.dump(result, fp, indent=2)
    print("\nSaved to tech_fingerprint_result.json")