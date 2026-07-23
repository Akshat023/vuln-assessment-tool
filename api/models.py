"""
Pydantic Models
===============
Request and response schemas for the vulnerability assessment API.
FastAPI uses these for automatic validation and OpenAPI docs generation.
"""

from pydantic import BaseModel, HttpUrl
from typing import Optional, List
from enum import Enum


class ScanStatus(str, Enum):
    QUEUED    = "queued"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"


# ──────────────────────────────────────────────
# Request models
# ──────────────────────────────────────────────

class ScanRequest(BaseModel):
    url: HttpUrl
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    # Future fields (Phase 4):
    # scan_type: str = "full"       # "passive" | "active" | "full"
    # notify_email: Optional[str]   # send email when done
    # scheduled_at: Optional[str]   # for scheduled scans

    class Config:
        json_schema_extra = {
            "example": {
                "url": "http://host.docker.internal:8888"
            }
        }


# ──────────────────────────────────────────────
# Finding schema (matches zap_scanner output)
# ──────────────────────────────────────────────

class Finding(BaseModel):
    vuln_id:          str
    scan_id:          str
    tool:             str
    plugin_id:        str
    vuln_type:        str
    owasp_category:   str
    cvss_score:       float
    severity:         str
    confidence:       str
    evidence:         str
    affected_url:     str
    method:           str
    param:            str
    attack:           str
    description:      str
    solution:         str
    cwe_id:           str
    recommendation:   str   # filled by AI layer
    business_impact:  str   # filled by AI layer


# ──────────────────────────────────────────────
# Summary schema
# ──────────────────────────────────────────────

class ScanSummary(BaseModel):
    total:    int
    critical: int
    high:     int
    medium:   int
    low:      int


# ──────────────────────────────────────────────
# Response models
# ──────────────────────────────────────────────

class ScanResponse(BaseModel):
    """Returned immediately when a scan is submitted."""
    scan_id: str
    url:     str
    status:  ScanStatus
    message: str


class ScanStatusResponse(BaseModel):
    """Returned when polling scan status."""
    scan_id:      str
    url:          str
    status:       ScanStatus
    created_at:   str
    completed_at: Optional[str]
    findings:     List[dict]     # List[Finding] — using dict for flexibility
    summary:      dict           # ScanSummary
    error:        Optional[str]
    executive_summary: Optional[str] = ""


class ScanListResponse(BaseModel):
    """Returned when listing all scans."""
    scans: List[dict]
    total: int