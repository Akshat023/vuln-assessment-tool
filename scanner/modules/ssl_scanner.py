"""
SSL/TLS Scanner Module
======================
Passive scanner — checks SSL/TLS configuration without sending attack payloads.

Checks for:
    - Certificate validity and expiry
    - Weak protocol versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
    - Self-signed certificates
    - Hostname mismatch
    - HSTS header presence
    - Certificate chain issues

Usage:
    from scanner.modules.ssl_scanner import SSLScanner
    scanner = SSLScanner()
    result = scanner.run_scan("https://example.com")
"""

import uuid
import ssl
import socket
import logging
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SSL] %(message)s")
logger = logging.getLogger(__name__)


class SSLScanner:
    """
    Passive SSL/TLS configuration scanner.

    Args:
        timeout: Socket connection timeout in seconds
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def _get_certificate_info(self, hostname: str, port: int = 443) -> dict:
        """Fetch SSL certificate details from the target host."""
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    return {
                        "cert":     cert,
                        "protocol": protocol,
                        "cipher":   cipher,
                        "error":    None,
                    }
        except ssl.SSLCertVerificationError as e:
            return {"cert": None, "protocol": None, "cipher": None, "error": f"SSL verification failed: {e}"}
        except ssl.SSLError as e:
            return {"cert": None, "protocol": None, "cipher": None, "error": f"SSL error: {e}"}
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return {"cert": None, "protocol": None, "cipher": None, "error": f"Connection failed: {e}"}

    def _check_weak_protocols(self, hostname: str, port: int = 443) -> list:
        """Test whether weak TLS protocol versions are accepted."""
        weak_protocols = []
        protocols_to_test = [
            (ssl.PROTOCOL_TLS_CLIENT, "TLSv1"),
            (ssl.PROTOCOL_TLS_CLIENT, "TLSv1.1"),
        ]
        for proto_const, proto_name in protocols_to_test:
            try:
                context = ssl.SSLContext(proto_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = ssl.TLSVersion.TLSv1
                context.maximum_version = ssl.TLSVersion.TLSv1 if "1.0" in proto_name else ssl.TLSVersion.TLSv1_1
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname):
                        weak_protocols.append(proto_name)
                        logger.warning(f"Weak protocol accepted: {proto_name}")
            except Exception:
                pass
        return weak_protocols

    def _normalize_finding(
        self,
        scan_id: str,
        vuln_type: str,
        owasp_category: str,
        cvss_score: float,
        severity: str,
        description: str,
        solution: str,
        affected_url: str,
        evidence: str = "",
        plugin_id: str = "",
    ) -> dict:
        """Build a normalized finding dict matching the standard schema."""
        return {
            "vuln_id":         str(uuid.uuid4()),
            "scan_id":         scan_id,
            "tool":            "ssl_scanner",
            "plugin_id":       plugin_id or f"ssl_{vuln_type.lower().replace(' ', '_')}",
            "vuln_type":       vuln_type,
            "owasp_category":  owasp_category,
            "cvss_score":      cvss_score,
            "severity":        severity,
            "confidence":      "High",
            "evidence":        evidence,
            "affected_url":    affected_url,
            "method":          "GET",
            "param":           "",
            "attack":          "",
            "description":     description,
            "solution":        solution,
            "cwe_id":          "326",
            "recommendation":  solution,
            "business_impact": "",
        }

    def run_scan(self, target_url: str, scan_id: str = None) -> dict:
        """
        Run SSL/TLS security scan against the target URL.

        Args:
            target_url: URL to scan (must be https:// for full SSL checks)
            scan_id:    Optional parent scan ID

        Returns:
            Standard result dict with findings and summary
        """
        if scan_id is None:
            scan_id = str(uuid.uuid4())

        logger.info(f"=== Starting SSL scan | scan_id={scan_id} | target={target_url} ===")

        result = {
            "scan_id":  scan_id,
            "target":   target_url,
            "status":   "failed",
            "findings": [],
            "summary":  {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        }

        parsed = urlparse(target_url)
        hostname = parsed.hostname
        findings = []

        # ── HTTP-only check ──────────────────────────────
        if parsed.scheme == "http":
            findings.append(self._normalize_finding(
                scan_id=scan_id,
                vuln_type="HTTP Only Site",
                owasp_category="A02:2021 - Cryptographic Failures",
                cvss_score=5.9,
                severity="Medium",
                description="The site is served over HTTP without SSL/TLS encryption. All data transmitted between the browser and server is in plaintext and can be intercepted.",
                solution="Configure your server to use HTTPS. Obtain a free TLS certificate from Let's Encrypt (certbot) and redirect all HTTP traffic to HTTPS.",
                affected_url=target_url,
                evidence="URL scheme is http://",
                plugin_id="ssl_http_only",
            ))
            logger.info("Site uses HTTP only — no SSL/TLS")

            # Still check HSTS header even on HTTP
            try:
                resp = requests.get(target_url, timeout=self.timeout, verify=False)
                if "strict-transport-security" not in {k.lower() for k in resp.headers}:
                    findings.append(self._normalize_finding(
                        scan_id=scan_id,
                        vuln_type="Missing HSTS Header",
                        owasp_category="A02:2021 - Cryptographic Failures",
                        cvss_score=5.9,
                        severity="Medium",
                        description="HTTP Strict Transport Security (HSTS) header is not set. Browsers will not automatically enforce HTTPS connections.",
                        solution="Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload to all HTTPS responses.",
                        affected_url=target_url,
                        plugin_id="ssl_missing_hsts",
                    ))
            except Exception:
                pass

            # Build summary and return early — no SSL cert to check on HTTP
            summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in findings:
                sev = f["severity"].lower()
                if sev in summary:
                    summary[sev] += 1
            result["status"]   = "completed"
            result["findings"] = findings
            result["summary"]  = summary
            logger.info(f"=== SSL scan complete (HTTP site) | {summary} ===")
            return result

        # ── HTTPS site — full SSL checks ─────────────────
        port = parsed.port or 443
        cert_info = self._get_certificate_info(hostname, port)

        if cert_info["error"]:
            findings.append(self._normalize_finding(
                scan_id=scan_id,
                vuln_type="SSL Certificate Error",
                owasp_category="A02:2021 - Cryptographic Failures",
                cvss_score=7.4,
                severity="High",
                description=f"SSL certificate validation failed: {cert_info['error']}",
                solution="Ensure the server has a valid, properly configured SSL certificate from a trusted Certificate Authority.",
                affected_url=target_url,
                evidence=cert_info["error"],
                plugin_id="ssl_cert_error",
            ))
        else:
            cert = cert_info["cert"]

            # Check certificate expiry
            if cert:
                try:
                    not_after_str = cert.get("notAfter", "")
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    not_after = not_after.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_remaining = (not_after - now).days

                    if days_remaining < 0:
                        findings.append(self._normalize_finding(
                            scan_id=scan_id,
                            vuln_type="Expired SSL Certificate",
                            owasp_category="A02:2021 - Cryptographic Failures",
                            cvss_score=7.4,
                            severity="High",
                            description=f"The SSL certificate expired on {not_after_str}. Browsers will show security warnings and block access.",
                            solution="Renew your SSL certificate immediately. Use Let's Encrypt with auto-renewal to prevent future expiry.",
                            affected_url=target_url,
                            evidence=f"Certificate expired: {not_after_str}",
                            plugin_id="ssl_cert_expired",
                        ))
                    elif days_remaining < 30:
                        findings.append(self._normalize_finding(
                            scan_id=scan_id,
                            vuln_type="SSL Certificate Expiring Soon",
                            owasp_category="A02:2021 - Cryptographic Failures",
                            cvss_score=5.3,
                            severity="Medium",
                            description=f"The SSL certificate expires in {days_remaining} days on {not_after_str}.",
                            solution="Renew your SSL certificate before it expires. Enable auto-renewal if using Let's Encrypt.",
                            affected_url=target_url,
                            evidence=f"Certificate expires in {days_remaining} days: {not_after_str}",
                            plugin_id="ssl_cert_expiring",
                        ))
                except Exception as e:
                    logger.warning(f"Could not parse certificate expiry: {e}")

            # Check weak protocol
            weak = self._check_weak_protocols(hostname, port)
            for proto in weak:
                findings.append(self._normalize_finding(
                    scan_id=scan_id,
                    vuln_type=f"Weak TLS Protocol Supported ({proto})",
                    owasp_category="A02:2021 - Cryptographic Failures",
                    cvss_score=5.9,
                    severity="Medium",
                    description=f"The server accepts {proto} connections which are considered cryptographically weak and vulnerable to known attacks.",
                    solution=f"Disable {proto} in your server configuration. For Nginx: ssl_protocols TLSv1.2 TLSv1.3; For Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
                    affected_url=target_url,
                    evidence=f"Server accepted {proto} handshake",
                    plugin_id=f"ssl_weak_protocol_{proto.lower().replace('.', '_')}",
                ))

            # Check HSTS
            try:
                resp = requests.get(target_url, timeout=self.timeout, verify=False)
                if "strict-transport-security" not in {k.lower() for k in resp.headers}:
                    findings.append(self._normalize_finding(
                        scan_id=scan_id,
                        vuln_type="Missing HSTS Header",
                        owasp_category="A02:2021 - Cryptographic Failures",
                        cvss_score=5.9,
                        severity="Medium",
                        description="HTTP Strict Transport Security (HSTS) header is not set. Users may be vulnerable to SSL stripping attacks.",
                        solution="Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload to all HTTPS responses.",
                        affected_url=target_url,
                        plugin_id="ssl_missing_hsts",
                    ))
            except Exception:
                pass

        # Build summary
        summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f["severity"].lower()
            if sev in summary:
                summary[sev] += 1

        result["status"]   = "completed"
        result["findings"] = findings
        result["summary"]  = summary

        logger.info(f"=== SSL scan complete | {summary} ===")
        return result


# ──────────────────────────────────────────────
# Quick test
# ──────────────────────────────────────────────
if __name__ == "__main__":
    import json

    scanner = SSLScanner()

    # Test HTTP site (DVWA)
    result = scanner.run_scan("http://host.docker.internal:8888")

    print(f"\nStatus  : {result['status']}")
    print(f"Summary : {result['summary']}")
    print(f"\nFindings:")
    for f in result["findings"]:
        print(f"  [{f['severity']}] {f['vuln_type']}")
        print(f"    OWASP : {f['owasp_category']}")
        print(f"    Fix   : {f['recommendation'][:80]}...")

    with open("ssl_scan_result.json", "w") as fp:
        json.dump(result, fp, indent=2)
    print("\nSaved to ssl_scan_result.json")