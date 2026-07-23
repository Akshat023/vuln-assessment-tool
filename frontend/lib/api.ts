// lib/api.ts
// API client for the vulnerability assessment backend

import axios from "axios";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export const api = axios.create({
  baseURL: API_BASE,
  headers: { "Content-Type": "application/json" },
});

// Types
export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export async function getScanProgress(scanId: string): Promise<{
  progress: number;
  stage: string;
  estimated_seconds_left: number | null;
}> {
  const res = await api.get(`/scans/${scanId}/progress`);
  return res.data;
}

export interface Finding {
  vuln_id: string;
  scan_id: string;
  tool: string;
  vuln_type: string;
  owasp_category: string;
  cvss_score: number;
  severity: string;
  confidence: string;
  evidence: string;
  affected_url: string;
  method: string;
  param: string;
  description: string;
  solution: string;
  recommendation: string;
  business_impact: string;
  cwe_id: string;
}

export interface Scan {
  scan_id: string;
  url: string;
  status: "queued" | "running" | "completed" | "failed";
  created_at: string;
  completed_at?: string;
  findings: Finding[];
  summary: ScanSummary;
  executive_summary?: string;
  error?: string;
}

// API calls
export async function submitScan(url: string, userId: string, userEmail: string) {
  const res = await api.post("/scans", { url, user_id: userId, user_email: userEmail });
  return res.data;
}

export const getScan = async (scanId: string): Promise<Scan> => {
  const res = await api.get(`/scans/${scanId}`);
  return res.data;
};

export const listScans = async (): Promise<{ scans: Scan[]; total: number }> => {
  const res = await api.get("/scans");
  return res.data;
};

export const getReportUrl = (scanId: string, format: "pdf" | "excel") =>
  `${API_BASE}/scans/${scanId}/report/${format}`;