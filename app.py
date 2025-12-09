# app.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import os
from pathlib import Path
import importlib
import traceback

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
        return {"status": "done", "results_summary": {k: {"entries": v.get("total_entries", 0),
                                                          "security_issues": v.get("security_issues_count", 0)}
                                                     for k, v in results.items()}}
    except Exception as e:
        return {"error": str(e), "trace": traceback.format_exc()}

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
    except Exception as e:
        return {"error": str(e), "trace": traceback.format_exc()}

@app.get("/reports")
def list_reports():
    # List files in browser_analysis_reports folder
    outdir = Path("browser_analysis_reports")
    if not outdir.exists():
        return {"reports": []}
    files = [str(p) for p in outdir.glob("*") if p.is_file()]
    return {"reports": files}

@app.get("/download")
def download_report(filename: str):
    # Serve textual report content (safe for small demo)
    outdir = Path("browser_analysis_reports")
    file_path = outdir / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return {"filename": filename, "content": file_path.read_text(encoding="utf-8")}
