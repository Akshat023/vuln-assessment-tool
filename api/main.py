"""
FastAPI Main Application
========================
Provides REST API endpoints for the vulnerability assessment tool.

Endpoints:
    POST /scans          — Submit a URL for scanning, returns scan_id immediately
    GET  /scans/{id}     — Get scan status and results
    GET  /scans          — List all scans
    DELETE /scans/{id}   — Delete a scan

Install dependencies:
    pip install fastapi uvicorn celery redis sqlalchemy psycopg2-binary python-dotenv requests

Run:
    uvicorn api.main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from reports.pdf_generator import PDFGenerator
from reports.excel_generator import ExcelGenerator
from datetime import datetime
from typing import Optional
import uuid
import json
import os

from api.models import (
    ScanRequest,
    ScanResponse,
    ScanStatusResponse,
    ScanListResponse,
    ScanStatus,
)
from api.tasks import run_scan_task
from db.scan_store import scan_store
# ──────────────────────────────────────────────
# App setup
# ──────────────────────────────────────────────

app = FastAPI(
    title="AI-Powered Vulnerability Assessment Tool",
    description="Submit a URL and get a full vulnerability report powered by OWASP ZAP and AI analysis.",
    version="0.1.0",
)

# Allow frontend (React/Next.js) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    """Health check endpoint."""
    return {"status": "ok", "message": "Vulnerability Assessment API is running"}


@app.post("/scans", response_model=ScanResponse, tags=["Scans"])
def create_scan(request: ScanRequest ):
    """
    Submit a URL for vulnerability scanning.
    
    - Returns a scan_id immediately (async — scan runs in background)
    - Poll GET /scans/{scan_id} to check progress and get results
    
    The scan pipeline:
        1. Spider scan (passive — crawls all links)
        2. Active scan (sends payloads — SQLi, XSS, etc.)
        3. CVSS + OWASP Top 10 mapping
        4. AI analysis (remediation + business impact)
    """
    scan_id = str(uuid.uuid4())
    target_url = str(request.url)

    # Validate URL has a scheme
    if not target_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    # Initialize scan record in store
    scan_store[scan_id] = {
        "scan_id":    scan_id,
        "url":        target_url,
        "status":     ScanStatus.QUEUED,
        "created_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "findings":   [],
        "summary":    {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "executive_summary": "",
        "error":      None,
    }

    # Run scan in background (Phase 1: no Celery yet — uses FastAPI BackgroundTasks)
    # In Phase 2 this becomes: celery_task.delay(scan_id, target_url)
    from api.celery_tasks import run_scan_celery
    run_scan_celery.delay(scan_id, target_url)

    return ScanResponse(
        scan_id=scan_id,
        url=target_url,
        status=ScanStatus.QUEUED,
        message=f"Scan queued. Poll GET /scans/{scan_id} for status and results.",
    )


@app.get("/scans/{scan_id}", response_model=ScanStatusResponse, tags=["Scans"])
def get_scan(scan_id: str):
    """
    Get the current status and results of a scan.
    
    Status values:
        queued    — waiting to start
        running   — scan in progress
        completed — finished, findings available
        failed    — something went wrong, check error field
    """
    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return scan


@app.get("/scans", response_model=ScanListResponse, tags=["Scans"])
def list_scans():
    """List all scans (most recent first)."""
    scans = list(scan_store.values())
    scans.sort(key=lambda x: x["created_at"], reverse=True)
    return {"scans": scans, "total": len(scans)}


@app.delete("/scans/{scan_id}", tags=["Scans"])
def delete_scan(scan_id: str):
    """Delete a scan record."""
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    del scan_store[scan_id]
    return {"message": f"Scan {scan_id} deleted"}


@app.get("/scans/{scan_id}/report/pdf", tags=["Reports"])
def download_pdf(scan_id: str):
    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed yet")
    generator = PDFGenerator()
    path = generator.generate(scan, output_filename=f"report_{scan_id}.pdf")
    return FileResponse(path, media_type="application/pdf", filename=f"report_{scan_id}.pdf")

@app.get("/scans/{scan_id}/report/excel", tags=["Reports"])
def download_excel(scan_id: str):
    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed yet")
    generator = ExcelGenerator()
    path = generator.generate(scan, output_filename=f"report_{scan_id}.xlsx")
    return FileResponse(path, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", filename=f"report_{scan_id}.xlsx")