# AI-Driven Vulnerability Scanner & Remediation System

---

## Table of Contents

1. [Project Overview](#project-overview)  
2. [Features](#features)  
3. [Architecture](#architecture)  
4. [Setup & Installation](#setup--installation)  
   - [Prerequisites](#prerequisites)  
   - [Clone & Install Dependencies](#clone--install-dependencies)  
   - [Environment Setup](#environment-setup)  
5. [Usage](#usage)  
   - [Running the Server](#running-the-server)  
   - [Web Interface](#web-interface)  
   - [Scan Workflow](#scan-workflow)  
   - [Remediation Workflow](#remediation-workflow)  
6. [Project Structure](#project-structure)  
7. [Model Training](#model-training)  
8. [Troubleshooting](#troubleshooting)  
9. [Future Improvements](#future-improvements)  
10. [References](#references)

---

## Project Overview

This repository contains an AI-driven vulnerability scanning and remediation system. Given a user-provided IP address, the system performs:

1. **Network Scanning:** Uses Nmap to discover open TCP ports and service versions.  
2. **Vulnerability Matching:** Utilizes SBERT embeddings to semantically match discovered services with relevant CVE entries (2023–2025) from the NVD.  
3. **Severity Classification:** Applies a RandomForest classifier (trained on CVE descriptions and CVSS scores) to categorize each CVE into Low, Medium, High, or Critical.  
4. **Remediation Generation:** Fine-tunes a T5 model to generate customized remediation steps for each CVE description.  
5. **Web Interface:** Provides a browser-based UI (HTML/CSS/JavaScript) that allows real-time scanning and remediation lookups.

---

## Features

- **Real-Time Scanning:** Enter an IP address and instantly scan for open services using Nmap.  
- **CVE Prioritization:** For each service, retrieve top-3 matching CVEs based on semantic similarity.  
- **Severity Ranking:** Classify CVEs by severity to help prioritize remediation.  
- **AI-Generated Fixes:** Generate human-readable remediation instructions using a fine-tuned T5 model.  
- **User-Friendly UI:** Interactive web interface with progress spinners and result tables.  

---

## Architecture

1. **Frontend (Browser):**  
   - HTML/CSS for layout and styling.  
   - JavaScript (`app.js`) to call backend APIs and render results.  
   - Spinner to indicate scan progress.

2. **Backend (FastAPI):**  
   - **`/api/scan`:** Receives `{ ip }`, runs Nmap via subprocess, parses output, computes SBERT similarity against CVE embeddings, returns list of services with top-3 CVEs.  
   - **`/api/fix`:** Receives `{ description }`, computes SBERT similarity against CVE descriptions, retrieves top-5 CVEs, generates T5 remediation.  
   - Models and embeddings are loaded at startup (`@app.on_event("startup")`).

3. **Data & Models:**  
   - **CVE Dataset:** `data/processed/cve_full_dataset.csv` containing CVE_ID, description, CVSS_score, attack_vector, severity, remediation_steps (for training).  
   - **SBERT Embeddings:** Precomputed 384-dim vectors for 80k CVE descriptions.  
   - **RandomForest Classifier:** Trained on SBERT embeddings to predict severity.  
   - **T5 Remediation Model:** Fine-tuned T5-small with safetensors under `models/checkpoint-53500`.

---

## Setup & Installation

### Prerequisites

- **Operating System:** Windows 10/11, macOS, or Linux  
- **Python:** 3.10.x  
- **Nmap:** Latest version (v7.95+), ensure `nmap` or `nmap.exe` is on your PATH.  
- **Git:** For cloning the repository.

### Clone & Install Dependencies

```bash
# Clone the repository
git clone https://github.com/YourUserName/ai-vuln-scanner.git
cd ai-vuln-scanner

# Create a Python virtual environment (optional but recommended)
python -m venv venv
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install required Python packages
pip install -r requirements.txt
```

**Contents of `requirements.txt`:**

```
fastapi
uvicorn
pandas
joblib
torch
sentence-transformers
transformers
scikit-learn
python-nmap
safetensors
```

### Environment Setup

No additional environment variables are required. Ensure Nmap is installed and accessible:

```bash
nmap --version
```

---

## Usage

### Running the Server

From the project root:

```bash
python src/api/app.py
```

You will see console logs indicating:

```
1) Reading CSV…
2) Loading classifier & SBERT…
3) Computing SBERT embeddings…
4) Loading T5 tokenizer & remediation model…
5) Initializing Nmap scanner…
✅ Startup complete; service is ready.
INFO: Uvicorn running on http://0.0.0.0:5000
```

### Web Interface

Open your browser and navigate to:

```
http://127.0.0.1:5000
```

You should see the AI-Driven Vulnerability Scanner UI.

### Scan Workflow

1. **Enter IP Address:** In the input box labeled “Enter IP to scan”, type an IPv4 address (e.g., `scanme.nmap.org`, `127.0.0.1`, or a local network IP).  
2. **Click “Scan”:** A circular spinner appears, showing progress.  
3. **View Results:** After Nmap completes (first 1000 ports, version detection), a table appears:

   | Port | Service           | Top CVEs                               |
   |------|-------------------|----------------------------------------|
   | 22   | ssh OpenSSH_7.4   | CVE-2023-1234 (HIGH)<br>CVE-2023-2345 (MEDIUM) … |
   | 80   | http Apache/2.4.29| CVE-2023-3456 (CRITICAL)<br>…            |

### Remediation Workflow

1. **Paste a CVE Description:** In the “Get CVE Fixes” textarea, paste any CVE description (e.g., “Apache HTTP Server versions 2.4.29 …”).  
2. **Click “Get Fixes”:** The spinner appears briefly as the T5 model generates fixes.  
3. **View Fix:** A list appears with up to 5 CVE IDs, their severity, and the AI-generated remediation text:

   - **CVE-2023-3456 (CRITICAL):** “Update Apache to 2.4.41 or later …”

---

## Project Structure

```
ai-vuln-scanner/
├─ data/
│  └─ processed/
│      └─ cve_full_dataset.csv        # CSV used for training & lookup
├─ models/
│  ├─ checkpoint-53500/               # Fine-tuned T5 checkpoint & tokenizer
│  └─ severity_classifier.pkl         # RandomForest classifier
├─ src/
│  ├─ api/
│  │   └─ app.py                      # FastAPI application
│  ├─ integration/
│  │   └─ scan_and_map.py             # (Optional) scanner/CVE-mapping logic
│  ├─ remediation/
│  │   └─ retrieve_remediations.py    # Scripts to build dataset (not used at runtime)
│  ├─ training/
│  │   └─ train_models.py             # Model training scripts
│  └─ …other modules…
├─ frontend/
│  ├─ index.html                      # Web UI
│  ├─ styles.css                      # Spinner & layout styling
│  └─ app.js                          # JavaScript for scan & fix
├─ .gitignore                         # Excludes models, caches, etc.
├─ README.md                          # ← You’re reading this
└─ requirements.txt                   # Python dependencies
```

---

## Model Training

If you need to retrain or update the models:

1. **Ensure `cve_full_dataset.csv` is present:** Contains CVE_ID, Description, CVSS, Severity, Remediation_Steps, etc.  
2. **Run Training Script:**

   ```bash
   python src/training/train_models.py
   ```

   - Trains a RandomForest severity classifier (`models/severity_classifier.pkl`).  
   - Fine-tunes T5-small for remediation, saving to `models/checkpoint-53500/`.  

---

## Troubleshooting

- **Nmap not found:**  
  - Ensure you installed Nmap from https://nmap.org/download.html and added it to PATH.  
  - Running `nmap --version` should print version info.

- **Port Scan Returns Empty:**  
  - Check network/firewall settings.  
  - Try scanning a known host (e.g., `127.0.0.1` or `scanme.nmap.org`).

- **Spinner Stuck at 0%:**  
  - Confirm `app.js loaded` appears in your browser’s console.  
  - Use Opera GX’s DevTools (Ctrl+Shift+I) → Console, Network to inspect `/api/scan` requests.

- **Model Loading Errors:**  
  - Ensure `models/checkpoint-53500/` contains `config.json`, `spiece.model`, `pytorch_model.bin` or `model.safetensors`.  
  - If you see a pickle/safetensors error, update `app.py` to use `from_pretrained(..., local_files_only=True)`.

---

## Future Improvements

- **Precompute & Cache Service Embeddings:** Speed up per-scan CVE lookup.  
- **Expand CVE Data Sources:** Include ExploitDB, GitHub Security Advisories.  
- **Enhance UI:** Add pagination, filters (by severity), and CSV export.  
- **Dockerize:** Provide a Dockerfile for containerized deployment.  
- **Risk Scoring:** Incorporate asset context and business criticality into prioritization.  

---

## References

1. National Vulnerability Database (NVD): CVE JSON Feeds – https://nvd.nist.gov/feeds/json/cve/1.1/  
2. Reimers & Gurevych (2019): Sentence-BERT – https://arxiv.org/abs/1908.10084  
3. Raffel et al. (2020): Exploring the Limits of Transfer Learning with a Unified Text-to-Text Transformer – https://arxiv.org/abs/1910.10683  
4. python-nmap: Python wrapper for Nmap – https://pypi.org/project/python-nmap/  
5. Hugging Face Transformers – https://huggingface.co/  
6. Nmap Reference Guide – https://nmap.org/book/man.html  
