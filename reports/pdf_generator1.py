"""
PDF Report Generator
====================
Generates a professional vulnerability assessment PDF report
from enriched scan findings using WeasyPrint.

Report structure:
    Page 1: Cover page — target, date, overall risk score
    Page 2: Executive summary (AI-generated)
    Page 3+: Findings table — severity, OWASP, CVSS, evidence, fix
    Last page: Appendix — scan metadata

Install:
    pip install weasyprint jinja2

Usage:
    from reports.pdf_generator import PDFGenerator
    generator = PDFGenerator()
    pdf_path = generator.generate(scan_data, output_path="report.pdf")
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Severity colors for badges
# ──────────────────────────────────────────────
SEVERITY_COLORS = {
    "Critical":     "#7B0000",
    "High":         "#C0392B",
    "Medium":       "#E67E22",
    "Low":          "#2980B9",
    "Informational": "#7F8C8D",
}

SEVERITY_BG = {
    "Critical":     "#FFE5E5",
    "High":         "#FDECEA",
    "Medium":       "#FEF3E2",
    "Low":          "#EBF5FB",
    "Informational": "#F2F3F4",
}


class PDFGenerator:
    """
    Generates PDF vulnerability reports from scan data.

    Args:
        output_dir: Directory to save generated PDFs (default: reports/output/)
    """

    def __init__(self, output_dir: str = "reports/output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _build_html(self, scan_data: dict) -> str:
        """Build the full HTML string for the report."""

        scan_id        = scan_data.get("scan_id", "N/A")
        target_url     = scan_data.get("url", "N/A")
        status         = scan_data.get("status", "completed")
        created_at     = scan_data.get("created_at", datetime.utcnow().isoformat())
        completed_at   = scan_data.get("completed_at", "N/A")
        findings       = scan_data.get("findings", [])
        summary        = scan_data.get("summary", {})
        exec_summary   = scan_data.get("executive_summary", "No executive summary available.")

        # Format date nicely
        try:
            date_str = datetime.fromisoformat(created_at).strftime("%B %d, %Y %H:%M UTC")
        except Exception:
            date_str = created_at

        # Overall risk level
        if summary.get("critical", 0) > 0:
            overall_risk = "Critical"
        elif summary.get("high", 0) > 0:
            overall_risk = "High"
        elif summary.get("medium", 0) > 0:
            overall_risk = "Medium"
        else:
            overall_risk = "Low"

        risk_color = SEVERITY_COLORS.get(overall_risk, "#2980B9")

        # Build findings rows HTML
        findings_rows = ""
        for i, f in enumerate(findings, 1):
            sev   = f.get("severity", "Low")
            color = SEVERITY_COLORS.get(sev, "#2980B9")
            bg    = SEVERITY_BG.get(sev, "#F2F3F4")

            findings_rows += f"""
            <tr style="background: {'#FAFAFA' if i % 2 == 0 else '#FFFFFF'}">
                <td style="padding:10px 8px; border-bottom:1px solid #ECF0F1;">
                    <span style="background:{bg}; color:{color}; padding:3px 8px;
                          border-radius:4px; font-weight:600; font-size:11px;">
                        {sev}
                    </span>
                </td>
                <td style="padding:10px 8px; border-bottom:1px solid #ECF0F1; font-weight:500;">
                    {f.get('vuln_type', 'N/A')}
                </td>
                <td style="padding:10px 8px; border-bottom:1px solid #ECF0F1; font-size:12px; color:#555;">
                    {f.get('owasp_category', 'N/A')}
                </td>
                <td style="padding:10px 8px; border-bottom:1px solid #ECF0F1; text-align:center; font-weight:600; color:{color};">
                    {f.get('cvss_score', 'N/A')}
                </td>
                <td style="padding:10px 8px; border-bottom:1px solid #ECF0F1; font-size:11px; color:#666; max-width:200px; word-break:break-all;">
                    {f.get('affected_url', 'N/A')}
                </td>
                <td style="padding:10px 8px; border-bottom:1px solid #ECF0F1; font-size:11px; color:#444;">
                    {f.get('recommendation', f.get('solution', 'N/A'))[:200]}{'...' if len(f.get('recommendation', f.get('solution', ''))) > 200 else ''}
                </td>
            </tr>
            <tr style="background:#F8F9FA;">
                <td colspan="6" style="padding:8px 8px 12px 8px; border-bottom:2px solid #ECF0F1;">
                    <span style="font-size:11px; color:#666;">
                        <strong>Business Impact:</strong>
                        {f.get('business_impact', 'N/A')}
                    </span>
                </td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Helvetica Neue', Arial, sans-serif; color: #2C3E50; font-size: 13px; }}

    /* Cover page — xhtml2pdf compatible (no flex, no gradient, no rgba) */
    .cover {{
        page-break-after: always;
        background-color: #1a1a2e;
        padding: 80px 60px;
        color: white;
    }}
    .cover-badge {{
        display: block;
        background-color: {risk_color};
        color: white;
        padding: 6px 16px;
        font-size: 13px;
        font-weight: 700;
        margin-bottom: 20px;
        width: 200px;
    }}
    .cover h1 {{
        font-size: 32px;
        font-weight: 700;
        margin-bottom: 10px;
        color: #FFFFFF;
    }}
    .cover h2 {{
        font-size: 16px;
        font-weight: 400;
        color: #A8C6FA;
        margin-bottom: 30px;
    }}
    .cover-meta {{
        background-color: #2C3E6E;
        padding: 20px;
        margin-top: 30px;
    }}
    .cover-meta table {{
        width: 100%;
        border-collapse: collapse;
    }}
    .cover-meta td {{
        padding: 6px 4px;
        font-size: 13px;
        color: #FFFFFF;
        border: none;
    }}
    .cover-meta .label {{
        color: #A8C6FA;
        font-weight: 600;
        width: 140px;
    }}

    /* Summary section */
    .summary-section {{
        page-break-after: always;
        padding: 40px 40px 20px;
    }}
    .section-title {{
        font-size: 20px;
        font-weight: 700;
        color: #1a1a2e;
        border-bottom: 3px solid #0f3460;
        padding-bottom: 8px;
        margin-bottom: 20px;
    }}
    .stat-boxes {{
        width: 100%;
        margin-bottom: 24px;
    }}
    .stat-box {{
        padding: 16px;
        text-align: center;
        width: 18%;
    }}
    .stat-number {{
        font-size: 32px;
        font-weight: 700;
        margin-bottom: 4px;
    }}
    .stat-label {{
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
    }}
    .exec-summary {{
        background: #F8F9FA;
        border-left: 4px solid #0f3460;
        padding: 20px 24px;
        border-radius: 0 8px 8px 0;
        line-height: 1.7;
        color: #444;
        font-size: 13px;
    }}

    /* Findings table */
    .findings-section {{ padding: 30px 50px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
    thead tr {{ background: #1a1a2e; color: white; }}
    thead th {{
        padding: 12px 8px;
        text-align: left;
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }}

    /* Footer */
    .footer {{
        position: fixed;
        bottom: 0;
        left: 0;
        right: 0;
        padding: 10px 50px;
        background: #F8F9FA;
        border-top: 1px solid #ECF0F1;
        font-size: 10px;
        color: #999;
        display: flex;
        justify-content: space-between;
    }}
</style>
</head>
<body>

<!-- COVER PAGE -->
<div class="cover">
    <div class="cover-badge">Overall Risk: {overall_risk}</div>
    <h1>Vulnerability Assessment Report</h1>
    <h2>AI-Powered Security Analysis</h2>
    <div class="cover-meta">
        <table>
            <tr><td class="label">Target URL</td><td>{target_url}</td></tr>
            <tr><td class="label">Scan Date</td><td>{date_str}</td></tr>
            <tr><td class="label">Scan ID</td><td style="font-size:11px;">{scan_id}</td></tr>
            <tr><td class="label">Total Findings</td><td>{summary.get('total', 0)}</td></tr>
            <tr><td class="label">Powered By</td><td>OWASP ZAP + Groq AI (Llama 3.3 70B)</td></tr>
        </table>
    </div>
</div>

<!-- EXECUTIVE SUMMARY PAGE -->
<div class="summary-section">
    <div class="section-title">Executive Summary</div>

    <!-- Stat boxes using table -->
    <table class="stat-boxes">
        <tr>
            <td class="stat-box" style="background-color:#FFE5E5;">
                <div class="stat-number" style="color:#7B0000;">{summary.get('critical', 0)}</div>
                <div class="stat-label" style="color:#7B0000;">Critical</div>
            </td>
            <td class="stat-box" style="background-color:#FDECEA;">
                <div class="stat-number" style="color:#C0392B;">{summary.get('high', 0)}</div>
                <div class="stat-label" style="color:#C0392B;">High</div>
            </td>
            <td class="stat-box" style="background-color:#FEF3E2;">
                <div class="stat-number" style="color:#E67E22;">{summary.get('medium', 0)}</div>
                <div class="stat-label" style="color:#E67E22;">Medium</div>
            </td>
            <td class="stat-box" style="background-color:#EBF5FB;">
                <div class="stat-number" style="color:#2980B9;">{summary.get('low', 0)}</div>
                <div class="stat-label" style="color:#2980B9;">Low</div>
            </td>
            <td class="stat-box" style="background-color:#F0F0F0;">
                <div class="stat-number" style="color:#2C3E50;">{summary.get('total', 0)}</div>
                <div class="stat-label" style="color:#2C3E50;">Total</div>
            </td>
        </tr>
    </table>

    <!-- AI Executive Summary -->
    <div class="exec-summary">{exec_summary}</div>

    <div style="margin-top:20px; font-size:11px; color:#999;">
        <strong>Disclaimer:</strong> This report is generated by an automated scanner and AI analysis tool.
        It is intended as a first-pass security assessment and does not replace a professional penetration test.
        Automated tools may produce false positives. Human review is recommended before acting on findings.
    </div>
</div>

<!-- FINDINGS TABLE -->
<div class="findings-section">
    <div class="section-title">Vulnerability Findings ({summary.get('total', 0)} total)</div>
    <table>
        <thead>
            <tr>
                <th style="width:80px;">Severity</th>
                <th style="width:160px;">Vulnerability</th>
                <th style="width:160px;">OWASP Category</th>
                <th style="width:50px;">CVSS</th>
                <th style="width:160px;">Affected URL</th>
                <th>Recommendation</th>
            </tr>
        </thead>
        <tbody>
            {findings_rows}
        </tbody>
    </table>
</div>

<!-- FOOTER -->
<div class="footer">
    <span>AI-Powered Vulnerability Assessment Tool — Confidential</span>
    <span>Generated: {date_str}</span>
</div>

</body>
</html>"""

        return html

    def generate(self, scan_data: dict, output_filename: str = None) -> str:
        """
        Generate a PDF report from scan data.

        Args:
            scan_data:        Full scan result dict (from scan_store or DB)
            output_filename:  Optional custom filename (default: report_{scan_id}.pdf)

        Returns:
            Path to the generated PDF file
        """
        try:
            from xhtml2pdf import pisa
        except ImportError:
            raise ImportError("xhtml2pdf not installed. Run: pip install xhtml2pdf")

        scan_id = scan_data.get("scan_id", "unknown")

        if output_filename is None:
            output_filename = f"report_{scan_id}.pdf"

        output_path = self.output_dir / output_filename

        logger.info(f"Generating PDF report for scan {scan_id}")

        html_content = self._build_html(scan_data)
        with open(str(output_path), "wb") as pdf_file:
            pisa.CreatePDF(html_content, dest=pdf_file)
        logger.info(f"PDF saved to: {output_path}")
        return str(output_path)


# ──────────────────────────────────────────────
# Quick test
# ──────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    for fname in ["scan_result_enriched.json", "scan_result.json"]:
        if os.path.exists(fname):
            with open(fname) as f:
                raw = json.load(f)
            print(f"Loaded from {fname}")
            break
    else:
        print("No scan_result.json found.")
        sys.exit(1)

    # Handle both formats
    if "findings" in raw and "summary" not in raw:
        findings = raw["findings"]
        summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "Low").lower()
            if sev in summary:
                summary[sev] += 1
        raw["summary"] = summary

    if "executive_summary" not in raw:
        raw["executive_summary"] = raw.get("summary", "")

    generator = PDFGenerator(output_dir="reports/output")
    pdf_path = generator.generate(raw)
    print(f"\nPDF report generated: {pdf_path}")
    print("Open it to see the full report!")