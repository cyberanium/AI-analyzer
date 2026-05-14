import hashlib
import json
import os
import argparse
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import anthropic
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# ------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------

# Information for the API key and DB path can be changed to what you need the information to be.

API_KEY = os.getenv("ANTROPIC_API_KEY", "")
DB_PATH = "forensics_cases.db"

# Do not change the system prompt unless the prompt is not working properly.

SYSTEM_PROMPT = """You are an expert AI forensics analyst. Your job is to examine AI conversation logs and determine:
1. Whether the AI was manipulated by the user (prompt injection, jailbreaking, social engineering, adversarial inputs)
2. Whether the AI itself malfunctioned (hallucination, inconsistency, bias, unexpected refusals, contradiction)
3. Whether the log shows signs of tampering or alteration (missing context, abrupt changes, formatting inconsistencies)
4. Wheter everything appears normal and legitimate

Respond ONLY in valid JSON with this exact structure:
{
    "verdict": "NORMAL" | "SUSPICIOUS" | "MANIPULATED" | "TAMPERED",
    "confidence": 0-100,
    "summary": "2-3 sentance overall summary of findings",
    "findings": [
        {
        "category": "EXternal Manipulation" | "AI Behavior" | "Log Tampering" | "Normal",
        "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
        "title": "short finding title",
        "description": "detailed explanation of what was found and why it matters forensically"
        }
    ],
    "recommendation": "what should be done next based on findings"
}

Be thorough and percise. Flag even subtle anomalies. If normal, still list what you checked."""

#-----------------------------------------------------
# DATABASE SETUP
#-----------------------------------------------------

def init_db():
    """Used to create the database to store case information."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cases (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT NOT NULL,
                sha256_hash     TEXT NOT NULL,
                log_text        TEXT NOT NULL,
                verdict         TEXT NOT NULL,
                confidence      TEXT NOT NULL,
                result_json     TEXT NOT NULL
                ) 
    """)
    conn.commit()
    conn.close()

def save_case(timestamp: str, sha256: str, log_text: str, result: dict) -> int:
    """Saves the forensics case to the datebase then returns case number."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute(
        "INSERT INTO cases (timestamp, sha256_hash, log_text, verdict, confidence, result_json) VALUES (?,?,?,?,?,?)",
        (timestamp, sha256, log_text, result["verdict"], result["confidence"], json.dumps(result))
    )
    case_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return case_id

def get_all_cases() -> list:
    """Retrieve all cases from the database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, timestamp, sha256_hash, verdict, confidence FROM cases ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_case_by_id(case_id: int) -> dict | None:
    """Retrieve a single case by ID."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

#------------------------------------------
# CORE FORENSICS LOGIC
#------------------------------------------

def hash_evidence(text: str) -> str:
    """Generates sha256 hash of the evidence for chain of custody"""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def analyze_log(log_text: str) -> dict:
    """ 
    Send the log to Claude for foensic analysis.
    Returns a structured result dict.
    """
    if not API_KEY:
        raise ValueError("ANTROPIC_API_KEY enviorment varabile not set.")
    
    client = anthropic.Anthropic(api_key=API_KEY)

    message = client.messages.create(
        model = "claude-sonnet-4-20250514",
        max_tokens = 1024,
        system = SYSTEM_PROMPT,
        messages = [
            {
                "role": "user",
                "content": f"Analyse this AI interaction log for forensic evidence:\n\n{log_text}"
            }
        ]
    )

    raw_text = message.content[0].text.strip()

    if raw_text.startswith("```"):
        lines = raw_text.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:] 
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        raw_text = "\n".join(lines).strip()
    
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError as e:
        print(f"\n[!] DEBUG: Failed to parse JSON. Claude's output was:\n{raw_text}\n")
        raise e

def run_full_analysis(log_text: str) -> dict:
    """
    Process pipeline for forenics:
        1. Hash the evidence
        2. Analyze with Claude
        3. Save to database
        4. Return complete report
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    sha256 = hash_evidence(log_text)

    print(f"\n[*] Evidence hash (SHA-256): {sha256}")
    print(f"[*] Timestamp: {timestamp}")
    print("[*] Sending to Claude for analysis...\n")

    result = analyze_log(log_text)
    case_id = save_case(timestamp, sha256, log_text, result)

    return{
        "case_id": case_id,
        "timestamp": timestamp,
        "sha256_hash": sha256,
        **result
    }

#-------------------------------------
# REPORT GENERATION
#-------------------------------------

def generate_report(report:dict, log_text: str) -> str:
    """ Format a human-readable forensic report."""
    sep = "=" * 60
    lines = [
        sep,
        "       AI FORENSICS ANALYZER - CASE REPORT",
        sep,
        f"  Case ID     : {report.get('case_id', ' N/A')}",
        f"  Timestamp   : {report.get('timestamp')}",
        f"  SHA-256     : {report['sha256_hash']}",
        sep,
        "",
        "SUMMARY",
        "-------",
        report["summary"],
        "",
        f"FINDINGS ({len(report['findings'])} total)",
    ]

    for i, f in enumerate(report["findings"], 1):
        lines += [
            f"\n[{i}] {f['title']}",
            f"  Category : {f['category']}",
            f"  Severity : {f['severity']}",
            f"  Detail   : {f['description']}",
        ]
    lines += [
        "",
        "RECOMMENDED ACTION",
        "------------------",
        report["recommendation"],
        "",
        sep,
        "ORIGINAL EVIDENCE LOG",
        sep,
        log_text,
        sep,
    ]
    
    return "\n".join(lines)


def save_report(report: dict, log_text: str, output_path: str = None):
    """Saves report to log file."""
    text = generate_report(report, log_text)
    if not output_path:
        output_path = f"forensics_report_{report.get('case_id', 'unknown')}.txt"
    Path(output_path).write_text(text, encoding="utf-8")
    print(f"[+] Report saved to: {output_path}")
    return output_path

#--------------------------------
# FASTAPI - REST API
#--------------------------------

app = FastAPI(title = "AI Forensics Analyzer API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins = ["*"],  #Restrict in production
    allow_methods = ["*"],
    allow_headers = ["*"],
)

class AnalyzeRequest(BaseModel):
    log_text: str

@app.on_event("startup")
def startup():
    init_db()

@app.post("/analyze")
def analyze_endpoint(request: AnalyzeRequest):
    """Analyze an AI log and return a forensic report"""
    if not request.log_text.strip():
        raise HTTPExecption(status_code = 400, detail = "log_text cannot be empty.")
    try:
        return run_full_analysis(request.log_text)
    except ValueError as e:
        raise HTTPExecption(status_code = 500, detail = str(e))
    except json.JSONDecodeError:
        raise HTTPExecption(status_code = 500, detail = "Claude returned invaild JSON. Try again.")
    
@app.get("/cases")
def list_cases():
    """Lists all past forensic cases"""
    return get_all_cases

@app.get("/cases/{case_id}")
def get_case(case_id: int):
    """Retrieve a secific case by ID."""
    case = get_case_by_id(case_id)
    if not case:
        raise HTTPExecption(status_code = 404, detail = "Case not found.")
    case["result"] = json.loads(case["result_json"])
    del case["result_json"]
    return case

@app.get("/health")
def health():
    return {"status": "online", "version": "0.1.0"}


#---------------------------------
# CLI - Command Line Interface
#---------------------------------

def cli():
    parser = argparse.ArgumentParser(
        description = "AI Forensics Analyzer - analyze AI logs from the command line"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--file", "-f", help = "Path to a .txt file containing the AI log")
    group.add_argument("--text", "-t", help = "AI log text passed directly as a string")
    parser.add_argument("--save", "-s", action = "store_true", help = "Save report to a .txt file")
    parser.add_argument("--server", action = "store_true", help = "Start the FastAPI server instead")
    args = parser.parse_args()

    if args.server:
        print("[*] Starting AI Forensics API server at http://localhost:8000")
        init_db()
        uvicorn.run(app, host = "0.0.0.0", port = "8000")
        return
    
    if args.file:
        log_text = Path(args.file).read_text(encoding = "utf-8")
    elif args.text:
        log_text = args.text
    else:
        print("Paste your AI log below. Press Ctrl+D (or Ctrl+Z on Windows) when done:\n")
        import sys
        log_text = sys.stdin.read()
    
    init_db()
    report = run_full_analysis(log_text)

    print(generate_report(report, log_text))

    if args.save:
        save_report(report, log_text)

#---------------------
# ENTRY POINT
#---------------------

if __name__ == "__main__":
    cli()