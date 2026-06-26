"""
AI Analyzer Module
==================
Uses Groq API (Llama 3.3 70B) to enrich vulnerability findings with:
    1. Remediation guidance — specific, actionable fix per finding
    2. Business impact     — consequence in plain English per finding
    3. Executive summary   — full scan risk narrative for non-technical stakeholders

Design principles:
    - CVSS decides severity. AI explains it.
    - All prompts return structured JSON — never free-form text.
    - Findings are batched to minimize API calls.
    - Graceful degradation — if AI fails, findings still have scanner data.

Install:
    pip install groq

Usage:
    from ai.analyzer import AIAnalyzer
    analyzer = AIAnalyzer(api_key="your_groq_key")
    enriched_findings, executive_summary = analyzer.enrich(findings, target_url)
"""

import os
import json
import logging
from typing import Optional
from groq import Groq

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Batch size — how many findings per API call
# Groq is fast but we keep batches small to
# stay within token limits and get clean output
# ──────────────────────────────────────────────
BATCH_SIZE = 5


class AIAnalyzer:
    """
    Enriches ZAP findings with AI-generated remediation and business impact.

    Args:
        api_key: Groq API key (or set GROQ_API_KEY env variable)
        model:   Groq model to use (default: llama-3.3-70b-versatile)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "llama-3.3-70b-versatile",
    ):
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        if not self.api_key:
            raise ValueError("Groq API key required. Set GROQ_API_KEY env variable or pass api_key.")
        self.client = Groq(api_key=self.api_key)
        self.model = model
        logger.info(f"AIAnalyzer initialized with model: {self.model}")

    # ──────────────────────────────────────────
    # Internal: call Groq and parse JSON
    # ──────────────────────────────────────────

    def _call_groq(self, system_prompt: str, user_prompt: str) -> dict | list:
        """
        Call Groq API and return parsed JSON.
        Always instructs model to return JSON only — no markdown, no preamble.
        """
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ],
                temperature=0.3,   # lower = more consistent, less creative
                max_tokens=2048,
            )
            raw = response.choices[0].message.content.strip()

            # Strip markdown code fences if model adds them
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            raw = raw.strip()

            return json.loads(raw)

        except json.JSONDecodeError as e:
            logger.error(f"Groq returned invalid JSON: {e}")
            raise
        except Exception as e:
            logger.error(f"Groq API call failed: {e}")
            raise

    # ──────────────────────────────────────────
    # Job 1: Remediation + business impact
    # ──────────────────────────────────────────

    def _enrich_batch(self, batch: list) -> list:
        """
        Send a batch of findings to Groq and get back
        remediation + business_impact for each.

        Returns list of dicts with vuln_id, recommendation, business_impact.
        """
        system_prompt = """You are a senior cybersecurity engineer writing vulnerability reports.

You will receive a JSON array of vulnerability findings. For each finding, return:
- "vuln_id": the exact vuln_id from the input (do not change it)
- "recommendation": specific, actionable fix instructions (2-3 sentences, technical but clear)
- "business_impact": one sentence explaining the real-world consequence for the business

Rules:
- Return ONLY a valid JSON array. No markdown, no explanation, no preamble.
- Keep recommendations specific — mention exact headers, config changes, or code fixes.
- Keep business impact focused on data, money, reputation, or compliance risk.
- Do not repeat the vulnerability description — only give fixes and impact.

Example output format:
[
  {
    "vuln_id": "abc-123",
    "recommendation": "Add X-Frame-Options: DENY header in your web server config. For Nginx: add_header X-Frame-Options DENY; For Apache: Header always set X-Frame-Options DENY",
    "business_impact": "Without this header, attackers can embed your login page in an invisible iframe to trick users into submitting credentials to a malicious site."
  }
]"""

        # Strip heavy fields to save tokens — AI only needs key context
        simplified = []
        for f in batch:
            simplified.append({
                "vuln_id":        f["vuln_id"],
                "vuln_type":      f["vuln_type"],
                "owasp_category": f["owasp_category"],
                "severity":       f["severity"],
                "cvss_score":     f["cvss_score"],
                "affected_url":   f["affected_url"],
                "param":          f.get("param", ""),
                "evidence":       f.get("evidence", "")[:200],  # truncate long evidence
                "solution":       f.get("solution", "")[:300],  # ZAP's raw solution as hint
            })

        user_prompt = f"Enrich these {len(simplified)} findings:\n{json.dumps(simplified, indent=2)}"

        result = self._call_groq(system_prompt, user_prompt)

        if not isinstance(result, list):
            raise ValueError(f"Expected list from Groq, got {type(result)}")

        return result

    # ──────────────────────────────────────────
    # Job 2: Executive summary
    # ──────────────────────────────────────────

    def _generate_executive_summary(self, findings: list, target_url: str) -> str:
        """
        Generate a 3-4 paragraph executive risk summary for the full scan.
        Written for non-technical stakeholders — no jargon.
        """
        system_prompt = """You are a cybersecurity consultant writing an executive summary for a vulnerability scan report.

Your audience is non-technical business stakeholders — CEOs, product managers, compliance officers.

Write 3-4 paragraphs covering:
1. Overall security posture (how serious is the situation overall?)
2. What an attacker could realistically do with these vulnerabilities
3. Business risk — data breach, compliance, reputation, financial impact
4. Prioritized action plan — what to fix first and why

Rules:
- Return ONLY a valid JSON object with a single key "summary" containing the text.
- Write in plain English. No bullet points. No technical jargon.
- Be direct and honest about risk — don't minimize or exaggerate.
- Keep it under 300 words.

Example format:
{"summary": "The security assessment of example.com revealed..."}"""

        # Build a concise summary of findings for the prompt
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        owasp_categories = set()
        top_findings = []

        for f in findings[:10]:  # top 10 by CVSS
            sev = f.get("severity", "Low")
            if sev in severity_counts:
                severity_counts[sev] += 1
            owasp_categories.add(f.get("owasp_category", ""))
            if len(top_findings) < 5:
                top_findings.append({
                    "type":     f["vuln_type"],
                    "severity": f["severity"],
                    "cvss":     f["cvss_score"],
                    "url":      f["affected_url"],
                })

        user_prompt = f"""Generate an executive summary for this vulnerability scan:

Target URL: {target_url}
Total findings: {len(findings)}
Severity breakdown: {json.dumps(severity_counts)}
OWASP categories affected: {list(owasp_categories)}
Top findings: {json.dumps(top_findings, indent=2)}"""

        result = self._call_groq(system_prompt, user_prompt)

        if isinstance(result, dict) and "summary" in result:
            return result["summary"]
        raise ValueError("Groq did not return expected summary format")

    # ──────────────────────────────────────────
    # Public API: enrich
    # ──────────────────────────────────────────

    def enrich(self, findings: list, target_url: str) -> tuple[list, str]:
        """
        Main entry point. Enriches all findings with AI analysis.

        Args:
            findings:   List of normalized findings from ZAPScanner
            target_url: The scanned URL (for executive summary context)

        Returns:
            Tuple of (enriched_findings, executive_summary)
            - enriched_findings: same list with recommendation + business_impact filled
            - executive_summary: string with full executive narrative
        """
        if not findings:
            logger.warning("No findings to enrich")
            return findings, "No vulnerabilities were detected in this scan."

        logger.info(f"Starting AI enrichment for {len(findings)} findings")

        # ── Step 1: Enrich findings in batches ────────────
        enriched_map = {}  # vuln_id -> {recommendation, business_impact}

        # Only enrich meaningful findings (skip pure Low noise if too many)
        findings_to_enrich = [f for f in findings if f["severity"] in ("Critical", "High", "Medium")]
        low_findings = [f for f in findings if f["severity"] == "Low"]

        # If no medium+ findings, enrich all
        if not findings_to_enrich:
            findings_to_enrich = findings
            low_findings = []

        logger.info(f"Enriching {len(findings_to_enrich)} medium+ findings via Groq")

        # Process in batches
        for i in range(0, len(findings_to_enrich), BATCH_SIZE):
            batch = findings_to_enrich[i:i + BATCH_SIZE]
            batch_num = (i // BATCH_SIZE) + 1
            total_batches = (len(findings_to_enrich) + BATCH_SIZE - 1) // BATCH_SIZE
            logger.info(f"Processing batch {batch_num}/{total_batches}")

            try:
                enriched_batch = self._enrich_batch(batch)
                for item in enriched_batch:
                    enriched_map[item["vuln_id"]] = {
                        "recommendation":  item.get("recommendation", ""),
                        "business_impact": item.get("business_impact", ""),
                    }
            except Exception as e:
                logger.error(f"Batch {batch_num} failed: {e} — skipping, findings will have empty AI fields")

        # Apply enrichment back to findings
        for finding in findings:
            if finding["vuln_id"] in enriched_map:
                finding["recommendation"]  = enriched_map[finding["vuln_id"]]["recommendation"]
                finding["business_impact"] = enriched_map[finding["vuln_id"]]["business_impact"]
            elif finding["severity"] == "Low" and finding not in findings_to_enrich:
                # Give low findings a generic recommendation from ZAP's solution field
                finding["recommendation"]  = finding.get("solution", "")
                finding["business_impact"] = "This issue represents a low-severity misconfiguration that could aid attackers in reconnaissance."

        # ── Step 2: Executive summary ──────────────────────
        logger.info("Generating executive summary")
        try:
            executive_summary = self._generate_executive_summary(findings, target_url)
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            executive_summary = f"Automated scan of {target_url} completed. {len(findings)} vulnerabilities were identified. Please review individual findings for details."

        logger.info("AI enrichment complete")
        return findings, executive_summary


# ──────────────────────────────────────────────
# Quick test — run this file directly
# ──────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    from dotenv import load_dotenv
    load_dotenv()

    # Load findings from previous scan
    try:
        with open("scan_result.json") as f:
            scan_data = json.load(f)
        findings = scan_data.get("findings", [])
        target_url = scan_data.get("target", "http://host.docker.internal:8888")
    except FileNotFoundError:
        print("scan_result.json not found. Run zap_scanner.py first.")
        sys.exit(1)

    if not findings:
        print("No findings in scan_result.json")
        sys.exit(1)

    print(f"Loaded {len(findings)} findings from scan_result.json")
    print("Starting AI enrichment...\n")

    analyzer = AIAnalyzer()
    enriched, summary = analyzer.enrich(findings, target_url)

    print("=" * 60)
    print("EXECUTIVE SUMMARY")
    print("=" * 60)
    print(summary)
    print()

    print("=" * 60)
    print("TOP 3 ENRICHED FINDINGS")
    print("=" * 60)
    for f in enriched[:3]:
        print(f"\n[{f['severity']}] {f['vuln_type']}")
        print(f"  CVSS     : {f['cvss_score']}")
        print(f"  OWASP    : {f['owasp_category']}")
        print(f"  URL      : {f['affected_url']}")
        print(f"  Fix      : {f['recommendation'][:150]}...")
        print(f"  Impact   : {f['business_impact']}")

    # Save enriched output
    with open("scan_result_enriched.json", "w") as f:
        json.dump({"target": target_url, "findings": enriched, "executive_summary": summary}, f, indent=2)
    print("\nFull enriched output saved to scan_result_enriched.json")