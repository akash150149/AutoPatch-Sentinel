"""
web/app.py
AutoPatch Sentinel - Tactical Web Command Center Backend

Lightweight FastAPI server exposing the pipeline state to the browser dashboard.

Endpoints:
  GET  /                   Serve dashboard HTML
  GET  /api/status         Return pipeline_state JSON (polled every 1s by dashboard)
  POST /api/run            Start pipeline in background thread
  POST /api/reset          Reset state for a fresh run
  GET  /api/reports        List completed audit reports
  GET  /api/reports/{name} Read a specific report file

Launch:
    # From project root:
    python -m web.app
    # Or:
    uvicorn web.app:app --host 127.0.0.1 --port 8000 --reload

Then open: http://localhost:8000
"""

from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path
from typing import Any

# ── ensure src/ is importable ─────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Import orchestrator state dict and run function
from orchestrator import run_pipeline, pipeline_state, parse_args, setup_logging

import argparse
import logging

log = logging.getLogger("sentinel.web")

app = FastAPI(title="AutoPatch Sentinel — Web Command Center", version="1.0.0")

# Mount static files (CSS, JS)
STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ── Models ────────────────────────────────────────────────────────────────────

class RunRequest(BaseModel):
    target: str = "telemetry_parser"
    provider: str = "ollama"
    model: str | None = "llama3.2"  # matches what user has pulled
    mode: str = "seed_replay"
    max_retries: int = 3
    fuzz_duration: float = 30.0
    no_sast: bool = False

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the main dashboard HTML page."""
    html_path = STATIC_DIR / "index.html"
    if not html_path.exists():
        return HTMLResponse("<h1>Dashboard not found</h1><p>web/static/index.html is missing.</p>", status_code=404)
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@app.get("/api/status")
async def get_status():
    """
    Return current pipeline state.
    Called by the dashboard every 1 second.
    The response is a copy so mutations don't corrupt mid-send.
    """
    state_copy = dict(pipeline_state)
    # Trim asan_log for browser performance (keep first 8KB)
    if state_copy.get("asan_log"):
        state_copy["asan_log"] = state_copy["asan_log"][:8192]
    # Trim patch_diff for browser performance
    if state_copy.get("patch_diff"):
        state_copy["patch_diff"] = state_copy["patch_diff"][:16384]
    return JSONResponse(content=state_copy)


@app.post("/api/run")
async def start_run(req: RunRequest, background_tasks: BackgroundTasks):
    """Start a pipeline run in a background thread."""
    if pipeline_state.get("running"):
        raise HTTPException(status_code=409, detail="Pipeline already running")

    background_tasks.add_task(_run_pipeline_thread, req)
    return {"status": "started", "target": req.target}


@app.post("/api/reset")
async def reset_state():
    """Reset the pipeline state for a fresh run."""
    if pipeline_state.get("running"):
        raise HTTPException(status_code=409, detail="Cannot reset while pipeline is running")

    pipeline_state.update({
        "running": False, "stage": "idle", "stage_index": 0,
        "target": "", "sast_report": None, "crash_found": False,
        "crash_summary": "", "asan_log": "", "patch_diff": "",
        "patch_explain": "", "verification": None,
        "report_md": "", "report_json": "",
        "log_lines": [], "finished": False, "success": False, "error": "",
    })
    return {"status": "reset"}


@app.get("/api/reports")
async def list_reports():
    """List all generated audit reports."""
    reports_dir = PROJECT_ROOT / "reports"
    if not reports_dir.exists():
        return {"reports": []}

    files = sorted(reports_dir.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    report_list = []
    for f in files[:20]:
        json_counterpart = f.with_suffix(".json")
        report_list.append({
            "name": f.stem,
            "md": f.name,
            "json": json_counterpart.name if json_counterpart.exists() else None,
            "size_bytes": f.stat().st_size,
            "mtime": f.stat().st_mtime,
        })
    return {"reports": report_list}


@app.get("/api/reports/{filename}")
async def get_report(filename: str):
    """Return the content of a specific report file."""
    reports_dir = PROJECT_ROOT / "reports"
    report_path = reports_dir / filename

    # Security: ensure path stays inside reports/
    try:
        report_path.resolve().relative_to(reports_dir.resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="Access denied")

    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    if filename.endswith(".json"):
        return JSONResponse(content=json.loads(report_path.read_text()))
    else:
        return {"content": report_path.read_text(encoding="utf-8", errors="replace")}


# ── Background runner ─────────────────────────────────────────────────────────

def _run_pipeline_thread(req: RunRequest):
    """Run the pipeline in a background thread so the API stays responsive."""
    setup_logging(verbose=False)

    # ── WSL2 Ollama networking note ───────────────────────────────────────────
    # In WSL2, the Windows host IP is read from /etc/resolv.conf nameserver.
    # Ollama on Windows must be configured with OLLAMA_HOST=0.0.0.0 so it
    # listens on the WSL bridge interface, not just Windows loopback.
    # The llm_patcher._get_ollama_base_url() already handles reading the
    # nameserver IP automatically — no override needed here.
    # If OLLAMA_BASE_URL is set in the shell, that takes precedence.

    # Build a fake argparse.Namespace matching orchestrator.run_pipeline() signature
    args = argparse.Namespace(
        target=req.target,
        provider=req.provider,
        model=req.model,
        mode=req.mode,
        max_retries=req.max_retries,
        fuzz_duration=req.fuzz_duration,
        no_sast=req.no_sast,
        verbose=False,
    )
    try:
        run_pipeline(args)
    except Exception as e:
        log.exception(f"Pipeline crashed: {e}")
        pipeline_state["error"] = str(e)
        pipeline_state["running"] = False
        pipeline_state["finished"] = True
        pipeline_state["success"] = False


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "web.app:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="info",
    )
