"use client";

import { useState, useEffect, useCallback } from "react";
import {
  submitScan,
  getScan,
  getScanProgress,
  listScans,
  getReportUrl,
  Scan,
  Finding,
} from "@/lib/api";

const SEVERITY_CONFIG: Record<string, { bg: string; text: string }> = {
  Critical: { bg: "bg-red-900",    text: "text-white" },
  High:     { bg: "bg-red-500",    text: "text-white" },
  Medium:   { bg: "bg-orange-400", text: "text-white" },
  Low:      { bg: "bg-blue-500",   text: "text-white" },
};

const SEVERITY_CARD: Record<string, { bg: string; text: string; num: string }> = {
  critical: { bg: "bg-red-50",    text: "text-red-900",    num: "text-red-800" },
  high:     { bg: "bg-red-50",    text: "text-red-600",    num: "text-red-600" },
  medium:   { bg: "bg-orange-50", text: "text-orange-600", num: "text-orange-600" },
  low:      { bg: "bg-blue-50",   text: "text-blue-600",   num: "text-blue-600" },
};

function SeverityBadge({ severity }: { severity: string }) {
  const cfg = SEVERITY_CONFIG[severity] || { bg: "bg-gray-400", text: "text-white" };
  return (
    <span className={`px-2 py-1 rounded text-xs font-bold ${cfg.bg} ${cfg.text}`}>
      {severity}
    </span>
  );
}

function SummaryCards({ summary }: { summary: Scan["summary"] }) {
  const items = [
    { key: "critical", label: "Critical" },
    { key: "high",     label: "High" },
    { key: "medium",   label: "Medium" },
    { key: "low",      label: "Low" },
    { key: "total",    label: "Total", special: true },
  ];

  return (
    <div className="grid grid-cols-5 gap-3 mb-6">
      {items.map(({ key, label, special }) => {
        const val = summary[key as keyof typeof summary] ?? 0;
        const cfg = special
          ? { bg: "bg-gray-50", text: "text-gray-600", num: "text-gray-800" }
          : SEVERITY_CARD[key] || { bg: "bg-gray-50", text: "text-gray-600", num: "text-gray-800" };
        return (
          <div key={key} className={`${cfg.bg} rounded-xl p-4 text-center border border-gray-100`}>
            <div className={`text-3xl font-bold ${cfg.num}`}>{val}</div>
            <div className={`text-xs font-semibold uppercase mt-1 ${cfg.text}`}>{label}</div>
          </div>
        );
      })}
    </div>
  );
}

function FindingRow({ finding, index }: { finding: Finding; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const rowBg = index % 2 === 0 ? "bg-white" : "bg-gray-50";

  const scoreColor =
    finding.cvss_score >= 9 ? "#7F1D1D" :
    finding.cvss_score >= 7 ? "#DC2626" :
    finding.cvss_score >= 4 ? "#EA580C" : "#2563EB";

  return (
    <>
      <tr
        className={`${rowBg} hover:bg-blue-50 cursor-pointer transition-colors`}
        onClick={() => setExpanded(!expanded)}
      >
        <td className="px-4 py-3 text-center">
          <SeverityBadge severity={finding.severity} />
        </td>
        <td className="px-4 py-3 font-medium text-gray-800 text-sm">{finding.vuln_type}</td>
        <td className="px-4 py-3 text-xs text-gray-500">{finding.owasp_category}</td>
        <td className="px-4 py-3 text-center font-bold text-sm" style={{ color: scoreColor }}>
          {finding.cvss_score}
        </td>
        <td
          className="px-4 py-3 text-xs text-gray-500 max-w-xs truncate"
          title={finding.affected_url}
        >
          {finding.affected_url}
        </td>
        <td className="px-4 py-3 text-center text-gray-400 text-sm">
          {expanded ? "▲" : "▼"}
        </td>
      </tr>
      {expanded && (
        <tr className="bg-blue-50">
          <td colSpan={6} className="px-6 py-4">
            <div className="space-y-3">
              {finding.description && (
                <div>
                  <div className="text-xs font-bold text-gray-500 uppercase mb-1">Description</div>
                  <div className="text-sm text-gray-700 leading-relaxed">{finding.description}</div>
                </div>
              )}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-xs font-bold text-gray-500 uppercase mb-1">Recommendation</div>
                  <div className="text-sm text-gray-700 leading-relaxed">
                    {finding.recommendation || finding.solution || "No recommendation available."}
                  </div>
                </div>
                <div>
                  <div className="text-xs font-bold text-gray-500 uppercase mb-1">Business Impact</div>
                  <div className="text-sm text-gray-700 leading-relaxed">
                    {finding.business_impact || "No business impact data available."}
                  </div>
                </div>
              </div>
              <div className="flex gap-6 flex-wrap">
                {finding.evidence && (
                  <div>
                    <div className="text-xs font-bold text-gray-500 uppercase mb-1">Evidence</div>
                    <code className="text-xs bg-gray-200 px-2 py-1 rounded">{finding.evidence}</code>
                  </div>
                )}
                {finding.cwe_id && (
                  <div>
                    <div className="text-xs font-bold text-gray-500 uppercase mb-1">CWE</div>
                    <span className="text-xs bg-gray-200 px-2 py-1 rounded">CWE-{finding.cwe_id}</span>
                  </div>
                )}
                {finding.tool && (
                  <div>
                    <div className="text-xs font-bold text-gray-500 uppercase mb-1">Scanner</div>
                    <span className="text-xs bg-indigo-100 text-indigo-700 px-2 py-1 rounded font-medium">
                      {finding.tool.replace(/_/g, " ").toUpperCase()}
                    </span>
                  </div>
                )}
                {finding.confidence && (
                  <div>
                    <div className="text-xs font-bold text-gray-500 uppercase mb-1">Confidence</div>
                    <span className="text-xs bg-gray-200 px-2 py-1 rounded">{finding.confidence}</span>
                  </div>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function ProgressBar({ progress }: {
  progress: { progress: number; stage: string; estimated_seconds_left: number | null } | null;
}) {
  const pct = progress?.progress ?? 0;
  const minsLeft = progress?.estimated_seconds_left != null
    ? Math.ceil(progress.estimated_seconds_left / 60)
    : null;

  return (
    <div className="p-4 bg-yellow-50 rounded-xl border border-yellow-200">
      <div className="flex items-center gap-3 mb-3">
        <div className="w-4 h-4 border-2 border-yellow-500 border-t-transparent rounded-full animate-spin flex-shrink-0" />
        <div className="flex-1">
          <div className="flex justify-between items-center">
            <span className="text-sm font-medium text-yellow-800">
              {progress?.stage || "Scanning in progress..."}
            </span>
            <span className="text-xs text-yellow-600">
              {minsLeft != null ? `~${minsLeft}m left` : "Estimating..."}
            </span>
          </div>
        </div>
      </div>
      <div className="w-full bg-yellow-200 rounded-full h-2.5">
        <div
          className="bg-yellow-500 h-2.5 rounded-full transition-all duration-1000"
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="text-xs text-yellow-600 mt-1 text-right">{pct}% complete</div>
    </div>
  );
}

function ScanResults({ scan }: { scan: Scan }) {
  return (
    <div className="mt-6">
      <SummaryCards summary={scan.summary} />

      {scan.executive_summary && (
        <div className="mb-6 p-4 bg-indigo-50 border-l-4 border-indigo-600 rounded-r-xl">
          <div className="text-xs font-bold text-indigo-600 uppercase mb-2">AI Executive Summary</div>
          <p className="text-sm text-gray-700 leading-relaxed">{scan.executive_summary}</p>
        </div>
      )}

      <div className="flex gap-3 mb-6">
  <a
    href={getReportUrl(scan.scan_id, "pdf")}
    target="_blank"
    rel="noopener noreferrer"
    className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg text-sm font-semibold hover:bg-red-700 transition-colors"
  >
    ↓ Download PDF
  </a>

  <a
    href={getReportUrl(scan.scan_id, "excel")}
    target="_blank"
    rel="noopener noreferrer"
    className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg text-sm font-semibold hover:bg-green-700 transition-colors"
  >
    ↓ Download Excel
  </a>
</div>

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
          <h3 className="font-bold text-gray-800">
            Vulnerability Findings ({scan.findings.length})
          </h3>
          <span className="text-xs text-gray-400">Click a row to expand details</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="bg-gray-800 text-white text-xs uppercase">
                <th className="px-4 py-3 text-center w-24">Severity</th>
                <th className="px-4 py-3 text-left">Vulnerability</th>
                <th className="px-4 py-3 text-left">OWASP Category</th>
                <th className="px-4 py-3 text-center w-16">CVSS</th>
                <th className="px-4 py-3 text-left">Affected URL</th>
                <th className="px-4 py-3 w-8"></th>
              </tr>
            </thead>
            <tbody>
              {scan.findings.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-10 text-center">
                    <div className="text-4xl mb-2">✅</div>
                    <div className="font-semibold text-gray-700">No vulnerabilities found</div>
                    <div className="text-sm text-gray-400 mt-1">
                      This scan completed successfully and no issues were detected.
                    </div>
                  </td>
                </tr>
              ) : (
                scan.findings.map((f, i) => (
                  <FindingRow key={f.vuln_id} finding={f} index={i} />
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function ScanHistory({ scans, onSelect }: { scans: Scan[]; onSelect: (s: Scan) => void }) {
  if (scans.length === 0) return null;

  const sorted = [...scans].sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  );

  return (
    <div className="mt-8">
      <h2 className="text-lg font-bold text-gray-800 mb-3">Scan History</h2>
      <div className="space-y-2">
        {sorted.map((scan) => (
          <div
            key={scan.scan_id}
            onClick={() => onSelect(scan)}
            className="flex items-center justify-between p-4 bg-white rounded-xl border border-gray-200 hover:border-indigo-300 hover:bg-indigo-50 cursor-pointer transition-all"
          >
            <div>
              <div className="font-medium text-gray-800 text-sm">{scan.url}</div>
              <div className="text-xs text-gray-400 mt-0.5">
                {new Date(scan.created_at).toLocaleString()} · {scan.summary?.total ?? 0} findings
              </div>
            </div>
            <div className="flex items-center gap-3">
              <span className={`text-xs font-bold px-2 py-1 rounded-full ${
                scan.status === "completed" ? "bg-green-100 text-green-700" :
                scan.status === "running"   ? "bg-yellow-100 text-yellow-700" :
                scan.status === "failed"    ? "bg-red-100 text-red-600" :
                                              "bg-gray-100 text-gray-500"
              }`}>
                {scan.status}
              </span>
              {scan.summary && (
                <div className="flex gap-1 text-xs">
                  {scan.summary.critical > 0 && (
                    <span className="bg-red-900 text-white px-1.5 py-0.5 rounded font-bold">
                      {scan.summary.critical}C
                    </span>
                  )}
                  {scan.summary.high > 0 && (
                    <span className="bg-red-500 text-white px-1.5 py-0.5 rounded font-bold">
                      {scan.summary.high}H
                    </span>
                  )}
                  {scan.summary.medium > 0 && (
                    <span className="bg-orange-400 text-white px-1.5 py-0.5 rounded font-bold">
                      {scan.summary.medium}M
                    </span>
                  )}
                  {scan.summary.low > 0 && (
                    <span className="bg-blue-500 text-white px-1.5 py-0.5 rounded font-bold">
                      {scan.summary.low}L
                    </span>
                  )}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Home() {
  const [url, setUrl]                 = useState("");
  const [loading, setLoading]         = useState(false);
  const [currentScan, setCurrentScan] = useState<Scan | null>(null);
  const [scanHistory, setScanHistory] = useState<Scan[]>([]);
  const [error, setError]             = useState("");
  const [polling, setPolling]         = useState(false);
  const [progress, setProgress]       = useState<{
    progress: number;
    stage: string;
    estimated_seconds_left: number | null;
  } | null>(null);

  const pollScan = useCallback((scanId: string) => {
    setPolling(true);
    const interval = setInterval(async () => {
      try {
        const scan = await getScan(scanId);
        setCurrentScan(scan);

        getScanProgress(scanId)
          .then(setProgress)
          .catch(() => {});

        if (scan.status === "completed" || scan.status === "failed") {
          clearInterval(interval);
          setProgress({ progress: 100, stage: "Scan complete", estimated_seconds_left: 0 });
          setPolling(false);
          setLoading(false);
          listScans()
            .then((data) => setScanHistory(data.scans))
            .catch(() => {});
        }
      } catch (err) {
        console.error("Poll error (will retry):", err);
      }
    }, 5000);
  }, []);

  useEffect(() => {
    listScans().then((data) => {
      const scans = data.scans;
      setScanHistory(scans);

      const runningScan = scans.find(
        (s) => s.status === "running" || s.status === "queued"
      );
      if (runningScan) {
        setCurrentScan(runningScan);
        pollScan(runningScan.scan_id);
      }
    }).catch(() => {});
  }, [pollScan]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setError("");
    setLoading(true);
    setCurrentScan(null);
    setProgress(null);

    try {
      const result = await submitScan(url.trim());
      const initialScan: Scan = {
        scan_id: result.scan_id,
        url: url.trim(),
        status: "queued",
        created_at: new Date().toISOString(),
        findings: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
      };
      setCurrentScan(initialScan);
      pollScan(result.scan_id);
    } catch {
      setError("Failed to submit scan. Make sure the API is running.");
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-gray-900 text-white px-6 py-4 shadow-lg">
        <div className="max-w-6xl mx-auto flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold">🛡 VulnAssess</h1>
            <p className="text-xs text-gray-400 mt-0.5">AI-Powered Website Vulnerability Assessment</p>
          </div>
          <div className="flex items-center gap-2 text-xs text-gray-400">
            <span className="w-2 h-2 bg-green-400 rounded-full inline-block" />
            OWASP ZAP + Groq AI
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-8">
        <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-sm mb-6">
          <h2 className="text-lg font-bold text-gray-800 mb-1">Start a New Scan</h2>
          <p className="text-sm text-gray-500 mb-4">
            Enter a URL to scan for vulnerabilities. Only scan websites you own or have permission to test.
          </p>
          <form onSubmit={handleSubmit} className="flex gap-3">
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              required
              className="flex-1 px-4 py-3 rounded-xl border border-gray-300 bg-white text-gray-900 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            />
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="px-6 py-3 bg-indigo-600 text-white rounded-xl font-semibold text-sm hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {loading ? "Scanning..." : "Start Scan"}
            </button>
          </form>
          {error && (
            <div className="mt-3 p-3 bg-red-50 text-red-600 text-sm rounded-lg">{error}</div>
          )}
        </div>

        {currentScan && (
          <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-sm">
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-lg font-bold text-gray-800">Scan Results</h2>
              <span className={`text-xs font-bold px-3 py-1 rounded-full ${
                currentScan.status === "completed" ? "bg-green-100 text-green-700" :
                currentScan.status === "running"   ? "bg-yellow-100 text-yellow-700" :
                currentScan.status === "failed"    ? "bg-red-100 text-red-600" :
                                                     "bg-gray-100 text-gray-500"
              }`}>
                {currentScan.status.toUpperCase()}
              </span>
            </div>
            <div className="text-sm text-gray-500 mb-4">
              Target: <span className="font-medium text-gray-700">{currentScan.url}</span>
            </div>

            {(currentScan.status === "queued" || currentScan.status === "running") && (
              <ProgressBar progress={progress} />
            )}

            {currentScan.status === "failed" && (
              <div className="p-4 bg-red-50 rounded-xl border border-red-200 text-red-700 text-sm">
                Scan failed: {currentScan.error || "Unknown error"}
              </div>
            )}

            {currentScan.status === "completed" && (
              <ScanResults scan={currentScan} />
            )}
          </div>
        )}

        <ScanHistory
          scans={scanHistory.filter((s) => s.scan_id !== currentScan?.scan_id)}
          onSelect={setCurrentScan}
        />
      </main>
    </div>
  );
}