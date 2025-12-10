# app.py
import asyncio
import json
from pathlib import Path
from datetime import datetime
from typing import Optional
import os
import importlib
import traceback

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Try to import your original script as a module
try:
    analyzer_module = importlib.import_module("browse_history_analyzer")
except Exception:
    analyzer_module = None
    import_err = traceback.format_exc()

app = FastAPI(title="Web History Analyzer - Wrapper")

# Allow browser requests (adjust origin for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class BrowserQuery(BaseModel):
    browser: Optional[str] = None  # e.g., "Chrome", "Firefox", "Edge"


@app.get("/")
def root():
    return {"status": "ok", "note": "Wrapper ready. Use /analyze_all or /analyze?browser=Chrome"}


@app.post("/analyze_all")
def analyze_all():
    if not analyzer_module:
        return {"error": "browse_history_analyzer.py failed to import", "import_error": import_err}
    try:
        AnalyzerClass = getattr(analyzer_module, "BrowserHistoryAnalyzer")
        a = AnalyzerClass()
        results = a.analyze_all_browsers()
        return {
            "status": "done",
            "results_summary": {
                k: {"entries": v.get("total_entries", 0), "security_issues": v.get("security_issues_count", 0)}
                for k, v in results.items()
            },
        }
    except Exception:
        return {"error": "analyze_all failed", "trace": traceback.format_exc()}


@app.post("/analyze")
def analyze(payload: BrowserQuery):
    if not analyzer_module:
        return {"error": "browse_history_analyzer.py failed to import", "import_error": import_err}

    browser = payload.browser
    if not browser:
        raise HTTPException(status_code=400, detail="Please provide a browser (e.g. Chrome, Firefox, Edge)")

    try:
        AnalyzerClass = getattr(analyzer_module, "BrowserHistoryAnalyzer")
        a = AnalyzerClass()
        res = a.analyze_browser(browser)
        return {"status": "done", "result": res}
    except Exception:
        return {"error": "analyze failed", "trace": traceback.format_exc()}


@app.get("/reports")
def list_reports():
    outdir = Path("browser_analysis_reports")
    if not outdir.exists():
        return {"reports": []}
    files = [str(p) for p in outdir.glob("*") if p.is_file()]
    return {"reports": files}


@app.get("/download")
def download_report(filename: str):
    folder = Path("browser_analysis_reports")
    safe_name = Path(filename).name
    file_path = folder / safe_name

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    return {"filename": safe_name, "content": file_path.read_text(encoding="utf-8")}


# ----------------------
# Server-Sent Events (SSE) realtime polling endpoint
# ----------------------

POLL_INTERVAL = 5.0  # seconds between polls (adjust as needed)


async def fetch_history_snapshot(browser="Chrome"):
    """
    Return a list of history entries (dict) usable by frontend.
    Attempts to read real DBs via analyzer extractors; falls back to sample_history.json.
    """
    # Try reading real DBs via analyzer
    try:
        if analyzer_module:
            AnalyzerClass = getattr(analyzer_module, "BrowserHistoryAnalyzer")
            a = AnalyzerClass()
            if browser in ("Chrome", "Edge"):
                db_path = a.browser_paths.get(browser)
                if db_path and os.path.exists(db_path):
                    data = a.extract_chrome_history(db_path)
                else:
                    data = []
            elif browser == "Firefox":
                db_path = a.browser_paths.get("Firefox")
                if db_path and os.path.exists(db_path):
                    data = a.extract_firefox_history(db_path)
                else:
                    data = []
            else:
                data = []

            result = []
            for e in data:
                entry = dict(e)
                ts = entry.get("timestamp")
                if isinstance(ts, datetime):
                    entry["timestamp"] = ts.isoformat()
                result.append(entry)
            return result
    except Exception:
        pass

    # Fallback: sample file
    try:
        sample_file = Path("sample_history.json")
        if sample_file.exists():
            raw = json.loads(sample_file.read_text(encoding="utf-8"))
            out = []
            for entry in raw:
                e = dict(entry)
                ts = e.get("timestamp")
                # keep string timestamps as-is
                out.append(e)
            return out
    except Exception:
        pass

    return []


async def event_generator(browser: str = "Chrome"):
    seen = set()  # store (url, timestamp) tuples to avoid duplicates
    while True:
        try:
            snapshot = await fetch_history_snapshot(browser)
            new_items = []
            for entry in snapshot:
                key = (entry.get("url"), entry.get("timestamp"))
                if key not in seen:
                    new_items.append(entry)
                    seen.add(key)
            if new_items:
                payload = json.dumps({"type": "new_history", "data": new_items})
                yield f"data: {payload}\n\n"
        except Exception:
            try:
                err_payload = json.dumps({"type": "error", "message": "sse fetch error"})
                yield f"event: error\ndata: {err_payload}\n\n"
            except Exception:
                pass

        # heartbeat
        yield "event: heartbeat\ndata: {}\n\n"
        await asyncio.sleep(POLL_INTERVAL)


@app.get("/events")
async def sse_events(browser: str = "Chrome"):
    return StreamingResponse(event_generator(browser), media_type="text/event-stream")


# --- sample analyzer endpoint (keeps existing behavior) ---
@app.post("/analyze_sample")
def analyze_sample():
    sample_file = Path("sample_history.json")
    if not sample_file.exists():
        raise HTTPException(status_code=404, detail="sample_history.json not found in repo")

    try:
        raw = json.loads(sample_file.read_text(encoding="utf-8"))
        # convert timestamps
        for entry in raw:
            if isinstance(entry.get("timestamp"), str):
                try:
                    entry["timestamp"] = datetime.strptime(entry["timestamp"], "%Y-%m-%d %H:%M:%S")
                except Exception:
                    entry["timestamp"] = datetime.now()

        if not analyzer_module:
            return {"error": "browse_history_analyzer.py failed to import", "import_error": import_err}

        AnalyzerClass = getattr(analyzer_module, "BrowserHistoryAnalyzer")
        analyzer = AnalyzerClass()

        analysis = analyzer.analyze_browsing_patterns(raw)
        security_issues = analyzer.detect_security_issues(raw)

        os.makedirs(analyzer.output_dir, exist_ok=True)
        txt = analyzer.generate_comprehensive_report("sample", analysis, security_issues)
        txt_path = Path(analyzer.output_dir) / "sample_forensic_report.txt"
        txt_path.write_text(txt, encoding="utf-8")

        analyzer.save_csv_data("sample", raw, security_issues)

        return {
            "status": "done",
            "analysis_summary": {
                "total_entries": analysis.get("total_entries", 0),
                "suspicious_domains": len(analysis.get("suspicious_domains", [])),
                "suspicious_keywords": len(analysis.get("suspicious_keywords", []))
            },
            "report_file": str(txt_path),
        }
    except Exception:
        raise HTTPException(status_code=500, detail=f"Error processing sample: {traceback.format_exc()}")
