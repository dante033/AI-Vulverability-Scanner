# src/api/app.py

import sys
from pathlib import Path
import subprocess
import re
import json
import os

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import pandas as pd
import joblib
import torch
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from transformers import T5ForConditionalGeneration, T5Tokenizer
import nmap

# ─── 1) Project root on path ────────────────────────────────────────────────
project_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(project_root))

# ─── 2) FastAPI setup ───────────────────────────────────────────────────────
app = FastAPI(title="AI Vulnerability Scanner")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # adjust to your domain if you lock down
    allow_methods=["*"],
    allow_headers=["*"],
)

# serve the static frontend
app.mount("/", StaticFiles(directory=str(project_root/"frontend"), html=True), name="frontend")

# ─── 3) Globals for models/dataset/scanner ─────────────────────────────────
df_cve    = None
embedder  = None
cve_emb   = None
clf       = None
tokenizer = None
rem_model = None
scanner   = None

# ─── 4) Startup event: load everything once ─────────────────────────────────
@app.on_event("startup")
def load_models_and_data():
    global df_cve, embedder, cve_emb, clf, tokenizer, rem_model, scanner

    print("1) Reading CSV…")
    df_cve = pd.read_csv(project_root/"data"/"processed"/"cve_full_dataset.csv")
    print(f"   Loaded {len(df_cve)} CVE rows.")

    print("2) Loading classifier & SBERT…")
    clf      = joblib.load(project_root/"models"/"severity_classifier.pkl")
    embedder = SentenceTransformer("all-MiniLM-L6-v2", device="cpu")

    print("3) Computing SBERT embeddings…")
    cve_emb = embedder.encode(df_cve["Description"].tolist(), convert_to_tensor=False)
    print("   Embeddings complete.")

    print("4) Loading T5 tokenizer & remediation model…")
    # point at the checkpoint folder if needed, or use "t5-small"
    # Here we assume your final safetensors lives in models/checkpoint-53500
    ckpt = project_root/"models"/"checkpoint-53500"
    tokenizer = T5Tokenizer.from_pretrained(str(ckpt))
    rem_model = T5ForConditionalGeneration.from_pretrained(str(ckpt), local_files_only=True).to("cpu")
    rem_model.eval()

    print("5) Initializing Nmap scanner…")
    scanner = nmap.PortScanner()

    print("✅ Startup complete; service is ready.")

# ─── 5) Utility functions ───────────────────────────────────────────────────
# Update the scan_services function to use direct Nmap executable
def scan_services(ip: str):
    """
    Use the system's Nmap executable to scan services and return open ports.
    Returns list of {"Port": int, "Service": str}.
    """
    try:
        print(f"[scan_services] Starting Nmap scan of {ip}")
        
        # Try to find nmap.exe in common locations
        nmap_paths = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            # Extract actual path from the shortcut the user provided
            os.path.dirname(r"C:\Program Files (x86)\Nmap\nmap.exe") + r"\nmap.exe",
            # Just use nmap command and let Windows find it
            "nmap"
        ]
        
        nmap_exe = None
        for path in nmap_paths:
            if os.path.exists(path) and path.endswith('.exe'):
                nmap_exe = path
                break
            elif path == "nmap":
                nmap_exe = path
                break
                
        if not nmap_exe:
            print("[scan_services] Could not find nmap executable")
            return []
            
        # Run nmap with XML output for easier parsing
        cmd = [nmap_exe, "-sV", "-oX", "-", ip]
        print(f"[scan_services] Running command: {' '.join(cmd)}")
        
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if proc.returncode != 0:
            print(f"[scan_services] Nmap exited with code {proc.returncode}: {proc.stderr}")
            return []
            
        # Parse the XML output
        import xml.etree.ElementTree as ET
        root = ET.fromstring(proc.stdout)
        
        services = []
        for host in root.findall('.//host'):
            for port in host.findall('.//port'):
                state = port.find('state')
                if state is not None and state.get('state') == 'open':
                    port_num = int(port.get('portid'))
                    service = port.find('service')
                    if service is not None:
                        name = service.get('name', '')
                        product = service.get('product', '')
                        version = service.get('version', '')
                        
                        # Build description
                        desc_parts = [part for part in [name, product, version] if part]
                        desc = ' '.join(desc_parts).strip()
                        
                        services.append({"Port": port_num, "Service": desc})
        
        print(f"[scan_services] found {len(services)} services on {ip}")
        if services:
            print(f"[scan_services] first service: {services[0]}")
        return services
    except Exception as e:
        print(f"[scan_services] Error scanning {ip}: {str(e)}")
        import traceback
        traceback.print_exc()
        return []

def map_to_cves(services, k=3):
    descs = [s["Service"] for s in services]
    us    = embedder.encode(descs, convert_to_tensor=False)
    out   = []
    for svc,ue in zip(services, us):
        sims = cosine_similarity([ue], cve_emb)[0]
        idxs = sims.argsort()[-k:][::-1]
        cves = [{
            "CVE_ID":      df_cve.iloc[i]["CVE_ID"],
            "Description": df_cve.iloc[i]["Description"],
            "Severity":    df_cve.iloc[i]["Severity"]
        } for i in idxs]
        out.append({**svc, "CVEs": cves})
    return out

# ─── 6) /api/scan endpoint ──────────────────────────────────────────────────
@app.post("/api/scan")
async def api_scan(payload: dict):
    ip = payload.get("ip","").strip()
    print(f"[SCAN] Received scan request for IP: {ip}")
    if not ip:
        raise HTTPException(status_code=400, detail="No IP provided")

    services = scan_services(ip)
    if not services:
        return JSONResponse(content=[])

    mapped = map_to_cves(services, k=3)
    return JSONResponse(content=mapped)

# ─── 7) /api/fix endpoint ───────────────────────────────────────────────────
@app.post("/api/fix")
async def api_fix(payload: dict):
    desc = payload.get("description","").strip()
    print(f"[FIX] Received fix request for desc: {desc[:50]}...")
    if not desc:
        raise HTTPException(status_code=400, detail="No description provided")

    ue    = embedder.encode([desc], convert_to_tensor=False)
    sims  = cosine_similarity(ue, cve_emb)[0]
    idxs  = sims.argsort()[-5:][::-1]
    out   = []
    for i in idxs:
        row = df_cve.iloc[i]
        inp = tokenizer(f"remediate: {row['Description']}", return_tensors="pt")
        with torch.no_grad():
            gen = rem_model.generate(**inp, max_length=150, num_beams=5, early_stopping=True)
        fix = tokenizer.decode(gen[0], skip_special_tokens=True)
        out.append({"CVE_ID":row["CVE_ID"], "Severity":row["Severity"], "Fix":fix})
    return JSONResponse(content=out)

# ─── 8) Entrypoint ───────────────────────────────────────────────────────────
if __name__=="__main__":
    uvicorn.run("src.api.app:app", host="0.0.0.0", port=5000, reload=False)
