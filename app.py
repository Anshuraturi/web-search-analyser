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
    # --- paste this at bottom of app.py ---

import json
from pathlib import Path
from datetime import datetime

@app.post("/analyze_sample")
def analyze_sample():
    """
    Analyze bundled sample_history.json so the hosted server can produce a real report.
    """
    # Load sample file
    sample_file = Path("sample_history.json")
    if not sample_file.exists():
        raise HTTPException(status_code=404, detail="sample_history.json not found in repo")

    try:
        raw = json.loads(sample_file.read_text(encoding="utf-8"))
        # Convert timestamps to datetime objects like analyzer expects
        for entry in raw:
            if isinstance(entry.get("timestamp"), str):
                try:
                    entry["timestamp"] = datetime.strptime(entry["timestamp"], "%Y-%m-%d %H:%M:%S")
                except Exception:
                    entry["timestamp"] = datetime.now()

        # Use the analyzer class directly
        if not analyzer_module:
            return {"error": "browse_history_analyzer.py failed to import", "import_error": import_err}

        AnalyzerClass = getattr(analyzer_module, "BrowserHistoryAnalyzer")
        analyzer = AnalyzerClass()

        # Run pattern analysis and security checks on the sample
        analysis = analyzer.analyze_browsing_patterns(raw)
        security_issues = analyzer.detect_security_issues(raw)

        # Save output files (so /reports will show them)
        os.makedirs(analyzer.output_dir, exist_ok=True)
        # write a small text report
        txt = analyzer.generate_comprehensive_report("sample", analysis, security_issues)
        txt_path = Path(analyzer.output_dir) / "sample_forensic_report.txt"
        txt_path.write_text(txt, encoding="utf-8")

        # Save CSVs
        analyzer.save_csv_data("sample", raw, security_issues)

        return {
            "status": "done",
            "analysis_summary": {
                "total_entries": analysis.get("total_entries", 0),
                "suspicious_domains": len(analysis.get("suspicious_domains", [])),
                "suspicious_keywords": len(analysis.get("suspicious_keywords", []))
            },
            "report_file": str(txt_path)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing sample: {e}")

