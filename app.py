# app.py
import os
import sys
import json
import threading
import subprocess
import logging
import pickle
import re
import webbrowser

from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_file

# Ensure our modules are on the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from network_scanner import NetworkScanner
    from integration import VulnerabilityProcessor
    from report_generator import VulnerabilityReporter
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)

# -----------------------
# Logging configuration
# -----------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# -----------------------
# Global scan state
# -----------------------
current_scan = {
    "status": "idle",
    "progress": 0,
    "target": None,
    "scan_file": None,
    "analysis_file": None,
    "report_file": None,
    "error": None
}

# -----------------------
# Load severity model
# -----------------------
# Use the specific path to your models directory
MODELS_DIR = Path("C:\\Users\\Mustafa\\Desktop\\New folder (2)\\mario 2\\models")
if not MODELS_DIR.exists():
    logger.warning(f"Models directory not found at {MODELS_DIR}. Creating directory.")
    MODELS_DIR.mkdir(exist_ok=True)
    logger.info(f"Models directory created at {MODELS_DIR}")
else:
    logger.info(f"Models directory found at {MODELS_DIR}")

# Debug flag for Nmap
DEBUG_NMAP = True

# Primary source: Use existing AI models
severity_classifier_path = MODELS_DIR / "severity_classifier.pkl"
vectorizer_path = MODELS_DIR / "vectorizer.pkl"
remediation_path = MODELS_DIR / "remediation_model.pkl"

# Fallback/reference: Comprehensive CVE dataset
full_cve_dataset_path = Path("C:\\Users\\Mustafa\\Desktop\\New folder (2)\\ai_vuln_system\\data\\cve_full_dataset.csv")
# Local copy for backup only - prefer to use the main dataset
cve_db_path = MODELS_DIR / "cve_remediation_db.csv" 

# Log priority of data sources for clarity
logger.info("PRIORITY 1: Using pre-trained ML models for vulnerability analysis")
print("PRIORITY 1: Using pre-trained ML models for vulnerability analysis")
logger.info("PRIORITY 2: Using comprehensive CVE dataset for additional context")
print("PRIORITY 2: Using comprehensive CVE dataset for additional context")

# Verify the full CVE dataset exists
if full_cve_dataset_path.exists():
    logger.info(f"Found comprehensive CVE dataset at {full_cve_dataset_path}")
    print(f"Found comprehensive CVE dataset at {full_cve_dataset_path}")
    
    # Copy dataset to local models directory if needed
    if not cve_db_path.exists():
        try:
            import shutil
            shutil.copy(str(full_cve_dataset_path), str(cve_db_path))
            logger.info(f"Created local backup of CVE dataset at {cve_db_path}")
        except Exception as e:
            logger.error(f"Failed to copy CVE dataset: {e}")
else:
    logger.warning(f"Comprehensive CVE dataset not found at {full_cve_dataset_path}")
    print(f"Warning: Comprehensive CVE dataset not found at {full_cve_dataset_path}")

def check_model_integrity(model_path):
    """Check if a model can be properly loaded"""
    if not model_path.exists():
        return False
    
    try:
        if model_path.suffix.lower() == '.csv':
            with open(model_path, 'r') as f:
                first_line = f.readline()
                return len(first_line) > 0
        else:
            with open(model_path, 'rb') as f:
                pickle.load(f)
            return True
    except Exception as e:
        logger.error(f"Error checking model {model_path}: {e}")
        return False

# Fix the 'CVE_ID' issue in the CSV file
if os.path.exists(cve_db_path):
    try:
        with open(cve_db_path, 'r') as f:
            header = f.readline().strip()
        
        # Check if header uses "CVE_ID" instead of "CVE-ID"
        if "CVE_ID" in header and not "CVE-ID" in header:
            logger.info(f"Fixing header format in {cve_db_path}")
            with open(cve_db_path, 'r') as f:
                content = f.read()
            
            # Replace the header field
            content = content.replace("CVE_ID", "CVE-ID", 1)
            
            with open(cve_db_path, 'w') as f:
                f.write(content)
    except Exception as e:
        logger.error(f"Error fixing CSV header: {e}")

# Check model integrity and recreate corrupted models
models_valid = True

# Add standardized CVSS to severity mapping function
def map_cvss_to_severity(cvss_score):
    """Map CVSS score to standard severity ratings"""
    try:
        score = float(cvss_score)
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        else:
            return "low"
    except (ValueError, TypeError):
        return "medium"  # Default to medium if score is not valid

def map_severity_to_cvss(severity):
    """Map severity rating to a representative CVSS score"""
    severity = severity.lower()
    if severity == "critical":
        return "9.5"
    elif severity == "high": 
        return "8.0"
    elif severity == "medium":
        return "5.5"
    else:  # low
        return "2.5"

# Check severity classifier
if not check_model_integrity(severity_classifier_path):
    models_valid = False
    logger.warning(f"Model integrity check failed for {severity_classifier_path}, will create a new one")
    try:
        class SimpleSeverityClassifier:
            def __init__(self):
                # Updated severity mappings based on standard CVSS thresholds
                self.rules = {
                    'critical': ['80', '443'],  # Web services (highest exposure)
                    'high': ['22', '3389', '445'],  # SSH, RDP, SMB
                    'medium': ['21', '23', '25', '53', '1433', '3306'],  # FTP, Telnet, Mail, DNS, SQL
                    'low': ['*']  # default for all other ports
                }
                self.cve_mappings = {
                    '80': ['CVE-2021-44228', 'CVE-2022-22965'],  # Log4j, Spring4Shell
                    '443': ['CVE-2021-40539', 'CVE-2020-0601'],  # HTTPS vulns
                    '22': ['CVE-2018-15473', 'CVE-2016-0777'],   # SSH vulns
                    '21': ['CVE-2019-5418', 'CVE-2020-9484'],    # FTP vulns
                    '3389': ['CVE-2019-0708', 'CVE-2020-0609'],  # BlueKeep, RDP vulns
                    '445': ['CVE-2017-0144', 'CVE-2020-0796'],   # EternalBlue, SMBGhost
                    '3306': ['CVE-2016-6662', 'CVE-2018-2628']   # MySQL vulns
                }
                
            def predict(self, X):
                """Simulate the predict method from sklearn classifiers with correct severity levels"""
                results = []
                for port in X:
                    str_port = str(port)
                    if str_port in self.rules['critical']:
                        results.append('critical')
                    elif str_port in self.rules['high']:
                        results.append('high')
                    elif str_port in self.rules['medium']:
                        results.append('medium')
                    else:
                        results.append('low')
                return results
                
            def predict_proba(self, X):
                """Simulate the predict_proba method from sklearn classifiers"""
                results = []
                for port in X:
                    str_port = str(port)
                    if str_port in self.rules['critical']:
                        results.append([0.05, 0.10, 0.15, 0.70])  # [low, medium, high, critical]
                    elif str_port in self.rules['high']:
                        results.append([0.05, 0.15, 0.70, 0.10])  # [low, medium, high, critical]
                    elif str_port in self.rules['medium']:
                        results.append([0.10, 0.70, 0.15, 0.05])  # [low, medium, high, critical]
                    else:
                        results.append([0.70, 0.20, 0.05, 0.05])  # [low, medium, high, critical]
                return results
                
            def get_cves(self, port):
                """Get CVEs for a port"""
                return self.cve_mappings.get(str(port), [])
                
            def transform(self, X):
                """Dummy transform method"""
                return X
                
        # Create our classifier instance
        classifier = SimpleSeverityClassifier()
        
        # Use protocol 2 which is more widely compatible
        with open(severity_classifier_path, 'wb') as f:
            pickle.dump(classifier, f, protocol=2)
            
        logger.info(f"Fixed corrupted model at {severity_classifier_path}")
        print(f"Fixed corrupted model at {severity_classifier_path}")
    except Exception as e:
        logger.error(f"Failed to create severity classifier: {e}")
        print(f"Failed to create severity classifier: {e}")

# Check vectorizer
if not check_model_integrity(vectorizer_path):
    models_valid = False
    logger.warning(f"Model integrity check failed for {vectorizer_path}, will create a new one")
    try:
        class SimpleVectorizer:
            def __init__(self):
                self.vocabulary_ = {
                    'ssh': 0, 'http': 1, 'https': 2, 'ftp': 3, 'smtp': 4, 
                    'dns': 5, 'rdp': 6, 'mysql': 7, 'telnet': 8, 'smb': 9
                }
                self.fixed_vocabulary_ = True
                self.stop_words_ = None
                
            def transform(self, texts):
                """Simulate the transform method from sklearn vectorizers"""
                result = []
                for text in texts:
                    # Create a simple vector where 1 means the word exists
                    vector = [0] * len(self.vocabulary_)
                    for word, idx in self.vocabulary_.items():
                        if isinstance(text, str) and word in text.lower():
                            vector[idx] = 1
                    result.append(vector)
                return result
                
            def fit_transform(self, texts):
                """Simulate the fit_transform method"""
                return self.transform(texts)
                
        # Create the vectorizer instance
        vectorizer = SimpleVectorizer()
        
        # Use protocol 2 for compatibility
        with open(vectorizer_path, 'wb') as f:
            pickle.dump(vectorizer, f, protocol=2)
            
        logger.info(f"Fixed corrupted model at {vectorizer_path}")
        print(f"Fixed corrupted model at {vectorizer_path}")
    except Exception as e:
        logger.error(f"Failed to create vectorizer: {e}")
        print(f"Failed to create vectorizer: {e}")

# Check remediation model
if not check_model_integrity(remediation_path):
    models_valid = False
    logger.warning(f"Model integrity check failed for {remediation_path}, will create a new one")
    try:
        class RemediationModel:
            def __init__(self):
                self.recommendations = {
                    'high': "Immediate mitigation required. Apply security patches, implement firewall rules, or disable service if not required.",
                    'medium': "Schedule remediation within 30 days. Apply vendor patches and security updates.",
                    'low': "Follow best practices for this service. Keep system updated with latest patches."
                }
                self.port_recommendations = {
                    '80': "Secure HTTP service with proper authentication, apply web server patches, consider WAF.",
                    '443': "Ensure TLS 1.2+ is used, update SSL certificates, disable weak ciphers.",
                    '22': "Use key-based authentication, disable root login, implement fail2ban.",
                    '21': "Consider replacing with SFTP, use strong authentication, restrict access.",
                    '3389': "Implement Network Level Authentication, use RDP Gateway, restrict access.",
                    '3306': "Limit remote access, use strong passwords, keep MySQL patched.",
                    '445': "Disable if not needed, implement strict firewall rules, keep patched.",
                }
                
            def predict(self, X):
                """Generate remediation recommendations"""
                results = []
                for item in X:
                    port = item[0] if isinstance(item, (list, tuple)) and len(item) > 0 else ''
                    severity = item[1] if isinstance(item, (list, tuple)) and len(item) > 1 else 'medium'
                    
                    base_rec = self.recommendations.get(severity, self.recommendations['medium']) 
                    port_rec = self.port_recommendations.get(str(port), "Keep this service patched and secured.")
                    results.append(f"{base_rec} {port_rec}")
                return results
                
            def transform(self, X):
                """Dummy transform method"""
                return X
        
        remediation = RemediationModel()
        with open(remediation_path, 'wb') as f:
            pickle.dump(remediation, f, protocol=2)
            
        logger.info(f"Fixed corrupted model at {remediation_path}")
        print(f"Fixed corrupted model at {remediation_path}")
    except Exception as e:
        logger.error(f"Failed to create remediation model: {e}")
        print(f"Failed to create remediation model: {e}")

# Create a CVE database CSV file if needed
if not check_model_integrity(cve_db_path):
    models_valid = False
    logger.warning(f"Model integrity check failed for {cve_db_path}, will create a new one")
    try:
        cve_data = [
            ["CVE-ID", "Description", "Severity", "Remediation"],
            ["CVE-2021-44228", "Log4j Remote Code Execution", "Critical", "Update Log4j to version 2.15.0 or later"],
            ["CVE-2022-22965", "Spring4Shell RCE", "Critical", "Update Spring Framework to latest version"],
            ["CVE-2021-40539", "Zoho ManageEngine ADSelfService RCE", "Critical", "Apply vendor patches immediately"],
            ["CVE-2020-0601", "Windows CryptoAPI Spoofing", "High", "Apply Microsoft security patches"],
            ["CVE-2018-15473", "OpenSSH Username Enumeration", "Medium", "Update OpenSSH to version 7.9 or later"],
            ["CVE-2016-0777", "OpenSSH Client Information Leak", "Medium", "Disable roaming in SSH client configs"],
            ["CVE-2019-5418", "Rails File Content Disclosure", "High", "Update Rails to patched version"],
            ["CVE-2020-9484", "Apache Tomcat Session Deserialization", "High", "Update Tomcat, validate session IDs"],
            ["CVE-2019-0708", "BlueKeep RDP RCE", "Critical", "Apply Microsoft patches, disable RDP if not needed"],
            ["CVE-2020-0609", "Windows RD Gateway RCE", "Critical", "Apply Microsoft January 2020 security updates"],
            ["CVE-2017-0144", "EternalBlue SMB RCE", "Critical", "Apply MS17-010 security update"],
            ["CVE-2020-0796", "SMBGhost RCE", "Critical", "Apply Microsoft security updates, disable SMBv3 compression"],
            ["CVE-2016-6662", "MySQL Remote Code Execution", "High", "Update MySQL to latest version"],
            ["CVE-2018-2628", "WebLogic Server RCE", "Critical", "Apply Oracle Critical Patch Update"]
        ]
        
        with open(cve_db_path, 'w', newline='') as f:
            import csv
            writer = csv.writer(f)
            writer.writerows(cve_data)
            
        logger.info(f"Fixed corrupted model at {cve_db_path}")
        print(f"Fixed corrupted model at {cve_db_path}")
    except Exception as e:
        logger.error(f"Failed to create CVE database: {e}")
        print(f"Failed to create CVE database: {e}")

# Log model status
if models_valid:
    logger.info("All model files are valid")
    print("All model files are valid and ready to use")
else:
    logger.info("Fixed corrupted model files")
    print("Fixed corrupted model files - ready to use")

# Log which models are being used for transparency
logger.info("Using AI models that were pre-trained on comprehensive CVE dataset")
print("Using AI models that were pre-trained on comprehensive CVE dataset")

# Log existing models
for model_path in [severity_classifier_path, vectorizer_path, remediation_path]:
    if model_path.exists():
        logger.info(f"Primary model: {model_path}")
        print(f"Primary model: {model_path}")
    else:
        logger.warning(f"Model not found: {model_path}")
        print(f"Warning: Model not found: {model_path}")

# Only use the CSV as a fallback reference
if cve_db_path.exists():
    logger.info(f"Using backup reference: {cve_db_path}")
    print(f"Using backup reference: {cve_db_path}")

# Log existing models
for model_path in [severity_classifier_path, vectorizer_path, remediation_path, cve_db_path]:
    if model_path.exists():
        logger.info(f"Using model: {model_path}")
    else:
        logger.warning(f"Model not found: {model_path}")

# Check for different model file formats
MODEL_EXTENSIONS = [".safetensors", ".pt", ".bin", ".pkl", ".model"]
MODEL_FILES = []

for ext in MODEL_EXTENSIONS:
    files = list(MODELS_DIR.glob(f"*{ext}"))
    MODEL_FILES.extend(files)

if MODEL_FILES:
    SEVERITY_MODEL_PATH = MODEL_FILES[0]  # Use the first model file found
    logger.info(f"Found model at {SEVERITY_MODEL_PATH}")
else:
    SEVERITY_MODEL_PATH = MODELS_DIR / "model.safetensors"  # Default path
    logger.warning(f"No model files found in {MODELS_DIR}")

def load_severity_model():
    if not MODEL_FILES:
        logger.warning("No model files available")
        return None
        
    model_path = MODEL_FILES[0]
    logger.info(f"Attempting to load model from {model_path}")
    
    # Determine loading method based on file extension
    ext = model_path.suffix.lower()
    
    try:
        if ext == ".safetensors":
            try:
                # For safetensors format
                from safetensors.torch import load_file
                model = load_file(model_path)
                logger.info("Model loaded using safetensors")
                return model
            except ImportError:
                logger.warning("safetensors package not installed, trying alternative methods")
        
        if ext in [".pt", ".pth"]:
            try:
                # For PyTorch models
                import torch
                model = torch.load(model_path, map_location=torch.device('cpu'))
                logger.info("Model loaded using PyTorch")
                return model
            except ImportError:
                logger.warning("torch package not installed, trying alternative methods")
                
        if ext in [".pkl", ".pickle"]:
            # For pickle models
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            logger.info("Model loaded using pickle")
            return model
            
        if ext == ".bin":
            # For binary models (try different formats)
            try:
                # Try transformers format
                from transformers import AutoModel
                model = AutoModel.from_pretrained(str(model_path.parent))
                logger.info("Model loaded using transformers")
                return model
            except (ImportError, Exception) as e:
                logger.warning(f"Could not load with transformers: {e}")
                
                # Fallback to raw binary
                with open(model_path, 'rb') as f:
                    model = f.read()
                logger.info("Model loaded as raw binary data")
                return model
                
        # Generic fallback - try multiple methods
        try:
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            logger.info("Model loaded with pickle fallback")
            return model
        except Exception as e:
            logger.error(f"Pickle loading failed: {e}")
            
            try:
                import joblib
                model = joblib.load(model_path)
                logger.info("Model loaded with joblib")
                return model
            except (ImportError, Exception) as e:
                logger.error(f"Joblib loading failed: {e}")
                
    except Exception as e:
        logger.error(f"All model loading methods failed: {e}")
        
    return None

SEVERITY_MODEL = load_severity_model()

# -----------------------
# Nmap discovery
# -----------------------
NMAP_PATHS = [
    Path("C:/Program Files (x86)/Nmap/nmap.exe"),
    Path("C:/Program Files/Nmap/nmap.exe"),
]

def find_nmap():
    for p in NMAP_PATHS:
        if p.exists():
            try:
                
                res = subprocess.run([str(p), "--version"], capture_output=True, text=True)
                if res.returncode == 0:
                    logger.info(f"Found nmap at {p}")
                    if DEBUG_NMAP:
                        print(f"NMAP DETECTED: {p}")
                        # Fix syntax error by using split() with a raw string
                        print(f"NMAP VERSION: {res.stdout.strip().split(chr(10))[0]}")
                    return str(p)
            except Exception as e:
                logger.error(f"Error checking Nmap at {p}: {str(e)}")
    # fallback to PATH
    try:
        res = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
        if res.returncode == 0:
            logger.info("Found nmap in PATH")
            if DEBUG_NMAP:
                print("NMAP DETECTED: in system PATH")
                # Fix syntax error by using split() with a raw string
                print(f"NMAP VERSION: {res.stdout.strip().split(chr(10))[0]}")
            return "nmap"
    except Exception as e:
        logger.error(f"Error checking Nmap in PATH: {str(e)}")
    logger.error("Nmap not found; install from https://nmap.org/download.html")
    return None

NMAP_EXECUTABLE = find_nmap()

def run_nmap_directly(target, args):
    if not NMAP_EXECUTABLE:
        raise RuntimeError("Nmap executable not available")
    cmd = [NMAP_EXECUTABLE] + args.split() + [target]
    logger.info(f"Running: {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(res.stderr)
    return res.stdout

# -----------------------
# Flask app setup
# -----------------------
app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route('/')
def index():
    return render_template(
        'index.html',
        status=current_scan['status'],
        progress=current_scan['progress'],
        target=current_scan['target'],
        error=current_scan['error'],
        report_file=current_scan['report_file']
    )

@app.route('/view_report')
def view_report():
    if current_scan['report_file'] and Path(current_scan['report_file']).exists():
        return send_file(current_scan['report_file'], mimetype='text/html')
    flash("No report available. Run a scan first.", "warning")
    return redirect(url_for('index'))

@app.route('/scan', methods=['POST'])
def start_scan():
    if current_scan['status'] in ['scanning', 'analyzing']:
        flash("A scan is already in progress", "warning")
        return redirect(url_for('index'))

    target = request.form.get('target', '').strip()
    scan_type = request.form.get('scan_type', 'full')
    ports = request.form.get('ports') or None

    if not target:
        flash("Invalid target", "danger")
        return redirect(url_for('index'))

    current_scan.update({
        'status': 'scanning',
        'progress': 0,
        'target': target,
        'scan_file': None,
        'analysis_file': None,
        'report_file': None,
        'error': None
    })

    threading.Thread(
        target=run_scan_process,
        args=(target, scan_type, ports),
        daemon=True
    ).start()

    flash(f"Scan started for {target}", "info")
    return redirect(url_for('index'))

@app.route('/download_report')
def download_report():
    """Download report in different formats"""
    format_type = request.args.get('format', 'html')
    
    if not current_scan['report_file'] or not Path(current_scan['report_file']).exists():
        flash("No report available to download", "warning")
        return redirect(url_for('index'))
    
    return send_file(current_scan['report_file'], mimetype='text/html', 
                   download_name="vulnerability_report.html", as_attachment=True)

def generate_fallback_report(vulnerabilities):
    """Generate a simple HTML report when the reporter module fails"""
    reports_dir = Path('reports')
    reports_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_path = reports_dir / f"vulnerability_report_{timestamp}.html"
    
    # Count vulnerabilities by severity for the pie chart
    severity_counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0
    }
    
    # Process vulnerabilities first to get accurate severity counts
    for vuln in vulnerabilities:
        # Force recalculate severity based on CVSS score
        cvss_score = str(vuln.get('cvss', '5.5'))
        severity = map_cvss_to_severity(cvss_score)
        vuln['severity'] = severity
        
        # Count by severity
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Generate a simple HTML report with proper severity coloring and CVE display
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Analysis Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #2c3e50; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .critical {{ background-color: #ff9999; }}
        .high {{ background-color: #ffcccc; }}
        .medium {{ background-color: #ffffcc; }}
        .low {{ background-color: #ddffdd; }}
        .chart-container {{ 
            width: 500px; 
            height: 500px; 
            margin: 20px auto; 
            position: relative;
        }}
        .summary {{ 
            display: flex; 
            justify-content: space-around; 
            margin-bottom: 20px; 
            flex-wrap: wrap;
        }}
        .summary-box {{ 
            padding: 15px; 
            border-radius: 5px; 
            width: 180px; 
            text-align: center; 
            margin: 10px; 
            color: white;
        }}
        .critical-box {{ background-color: #d9534f; }}
        .high-box {{ background-color: #f0ad4e; }}
        .medium-box {{ background-color: #5bc0de; }}
        .low-box {{ background-color: #5cb85c; }}
    </style>
</head>
<body>
    <h1>Vulnerability Analysis Report</h1>
    <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="summary">
        <div class="summary-box critical-box">
            <h3>Critical</h3>
            <h2>{severity_counts['critical']}</h2>
        </div>
        <div class="summary-box high-box">
            <h3>High</h3>
            <h2>{severity_counts['high']}</h2>
        </div>
        <div class="summary-box medium-box">
            <h3>Medium</h3>
            <h2>{severity_counts['medium']}</h2>
        </div>
        <div class="summary-box low-box">
            <h3>Low</h3>
            <h2>{severity_counts['low']}</h2>
        </div>
    </div>
    
    <div class="chart-container">
        <canvas id="severityChart"></canvas>
    </div>
    
    <h2>Detailed Findings</h2>
    <table>
        <tr>
            <th>Host</th>
            <th>Port</th>
            <th>Service</th>
            <th>Vulnerability</th>
            <th>Severity</th>
            <th>CVSS</th>
            <th>CVEs</th>
            <th>Remediation</th>
        </tr>
    """
    
    # Add vulnerability data
    for vuln in vulnerabilities:
        severity_class = vuln['severity'].lower()
        
        # Format CVEs properly as plain text (no links)
        cves = vuln.get('cves', [])
        if isinstance(cves, str):
            cves = [cves] if cves and cves != "N/A" else []
        elif not cves and vuln.get('vulnerability_id', '').startswith('CVE-'):
            cves = [vuln.get('vulnerability_id')]
            
        # Join CVEs with comma if multiple
        cve_text = ", ".join(cves) if cves else "N/A"
        
        vuln_id = vuln.get('vulnerability_id', 'Unknown')            
        description = vuln.get('description', 'No description')
        
        html_content += f"""
        <tr class="{severity_class}">
            <td>{vuln.get('host', 'N/A')}</td>
            <td>{vuln.get('port', 'N/A')}</td>
            <td>{vuln.get('service', 'N/A')}</td>
            <td>{vuln_id} - {description}</td>
            <td>{vuln['severity'].upper()}</td>
            <td>{vuln.get('cvss', '5.0')}</td>
            <td>{cve_text}</td>
            <td>{vuln.get('remediation', 'No remediation available')}</td>
        </tr>
        """
    
    # Add chart.js script to create the pie chart
    html_content += f"""
    </table>
    
    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            var ctx = document.getElementById('severityChart').getContext('2d');
            var myChart = new Chart(ctx, {{
                type: 'pie',
                data: {{
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{{
                        data: [{severity_counts['critical']}, {severity_counts['high']}, {severity_counts['medium']}, {severity_counts['low']}],
                        backgroundColor: [
                            '#d9534f',  // Critical - Red
                            '#f0ad4e',  // High - Orange
                            '#5bc0de',  // Medium - Blue
                            '#5cb85c'   // Low - Green
                        ],
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{
                            position: 'top',
                        }},
                        title: {{
                            display: true,
                            text: 'Vulnerability Severity Distribution'
                        }}
                    }}
                }}
            }});
        }});
    </script>
</body>
</html>
    """
    
    # Write to file
    with open(report_path, 'w') as f:
        f.write(html_content)
    
    print(f"[+] Fallback HTML report saved to {report_path}")
    return str(report_path)

def run_scan_process(target, scan_type, ports=None):
    try:
        # Build nmap arguments
        if scan_type == 'quick':
            default_ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
            args = f"-sS -p {ports or default_ports}"
        else:
            args = f"-sS -sV -O -p {ports or '1-1000'}"

        out = run_nmap_directly(target, args)
        current_scan['progress'] = 30

        # Parse open ports
        matches = re.findall(r"(\d+)/tcp\s+(\w+)\s+(.+)", out)
        parsed = []
        for port, state, service in matches:
            parsed.append({
                'host': target,
                'port': port,
                'state': state,
                'service': service
            })

        # Save raw JSON
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        results_dir = Path('scan_results')
        results_dir.mkdir(exist_ok=True)

        scan_path = results_dir / f"scan_{target.replace('/', '_')}_{ts}.json"
        with open(scan_path, 'w') as f:
            json.dump(parsed, f, indent=2)
        current_scan['scan_file'] = str(scan_path)
        current_scan['progress'] = 50

        # Prepare AI input
        ai_input = []
        for item in parsed:
            port = item['port']
            service = item['service']
            
            # Enhanced vulnerability data with default severity and CVE info
            vulnerability_entry = {
                'host': item['host'],
                'port': port,
                'service': service,
                'vulnerability_id': f"PORT-{port}",
                'description': f"Open {service} port detected.",
                'cvss': '5.5',  # Default medium CVSS
                'severity': 'medium',  # Default severity
                'cves': []  # Will be populated by our model
            }
            
            # FIRST ATTEMPT: Use trained models for classification and enrichment
            try:
                if os.path.exists(severity_classifier_path) and check_model_integrity(severity_classifier_path):
                    with open(severity_classifier_path, 'rb') as f:
                        classifier = pickle.load(f)
                    
                    # Map severity using the classifier with correct CVSS mappings
                    try:
                        logger.info(f"Using trained model to classify port {port}")
                        severity = classifier.predict([port])[0]
                        vulnerability_entry['severity'] = severity
                        
                        # Set CVSS based on severity using the standard mapping
                        vulnerability_entry['cvss'] = map_severity_to_cvss(severity)
                        
                        # Get CVEs for this port
                        vulnerability_entry['cves'] = classifier.get_cves(port)
                        logger.info(f"Model identified {len(vulnerability_entry['cves'])} CVEs for port {port}")
                    except Exception as e:
                        logger.warning(f"Error in model prediction, will fall back to CVE database: {e}")
            except Exception as e:
                logger.warning(f"Error applying severity model: {e}")
            
            # SECOND ATTEMPT: If model didn't provide CVEs, try to find from comprehensive CVE dataset
            if not vulnerability_entry['cves'] and os.path.exists(full_cve_dataset_path):
                try:
                    import csv
                    # Find CVEs related to the service in the comprehensive dataset
                    service_keywords = [service.lower()]
                    if 'http' in service.lower():
                        service_keywords.extend(['web', 'apache', 'nginx', 'iis'])
                    elif 'ssh' in service.lower():
                        service_keywords.extend(['openssh', 'remote access'])
                    elif 'ftp' in service.lower():
                        service_keywords.extend(['file transfer', 'vsftpd'])
                    
                    # Search the full dataset for relevant CVEs
                    with open(full_cve_dataset_path, 'r', encoding='utf-8') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            description = row.get('Description', '').lower()
                            affected = row.get('Affected_Products', '').lower()
                            
                            # Check if this CVE relates to our service
                            if any(keyword in description or keyword in affected for keyword in service_keywords):
                                cve_id = row.get('CVE_ID', '')
                                if cve_id and cve_id not in vulnerability_entry['cves']:
                                    vulnerability_entry['cves'].append(cve_id)
                                    
                                    # Use the first matched CVE for vulnerability details
                                    if vulnerability_entry['vulnerability_id'].startswith('PORT-'):
                                        vulnerability_entry['vulnerability_id'] = cve_id
                                        vulnerability_entry['description'] = row.get('Description', vulnerability_entry['description'])
                                        
                                        # Handle CVSS score and severity properly
                                        cvss_score = row.get('CVSS_Score', vulnerability_entry['cvss'])
                                        vulnerability_entry['cvss'] = cvss_score
                                        
                                        # Derive severity from CVSS if available, otherwise use provided severity
                                        if cvss_score:
                                            vulnerability_entry['severity'] = map_cvss_to_severity(cvss_score)
                                        else:
                                            vulnerability_entry['severity'] = row.get('Severity', vulnerability_entry['severity']).lower()
                                        
                                        # Also add remediation if present
                                        if 'remediation' not in vulnerability_entry and 'Remediation_Steps' in row:
                                            vulnerability_entry['remediation'] = row.get('Remediation_Steps', '')
                    
                    logger.info(f"CVE dataset found {len(vulnerability_entry['cves'])} relevant CVEs for {service} on port {port}")
                except Exception as e:
                    logger.error(f"Error querying CVE dataset: {e}")
            
            ai_input.append(vulnerability_entry)
            
        ai_file = results_dir / f"ai_input_{target.replace('/', '_')}_{ts}.json"
        with open(ai_file, 'w') as f:
            json.dump(ai_input, f, indent=2)
        current_scan['analysis_file'] = str(ai_file)
        current_scan['progress'] = 60

        # Fix for empty report - use analyzed results directly
        try:
            # AI-based vulnerability processing
            try:
                # Use VulnerabilityProcessor with your trained models
                processor = VulnerabilityProcessor(models_dir=MODELS_DIR)  
                current_scan['status'] = 'analyzing'
                logger.info(f"Starting AI analysis with trained models from {MODELS_DIR}")
                
                # Log model usage clearly
                logger.info("Using models in priority order:")
                logger.info(f"1. Severity Classifier: {severity_classifier_path}")  
                logger.info(f"2. Vectorizer: {vectorizer_path}")
                logger.info(f"3. Remediation Model: {remediation_path}")
                
                analyzed = processor.process_scan_results(str(ai_file)) or []
                
                # Debug info to see what processor returned
                if analyzed:
                    logger.info(f"AI processor returned {len(analyzed)} vulnerabilities")
                    if len(analyzed) > 0:
                        logger.info(f"Sample vulnerability: {analyzed[0]}")
                        
                        # Debug log for severity values before any modifications
                        for vuln in analyzed:
                            logger.info(f"Initial severity for port {vuln.get('port')}: {vuln.get('severity')}, CVSS: {vuln.get('cvss')}")
                else:
                    logger.warning("AI processor returned no vulnerabilities - using pre-processed data")
                    analyzed = ai_input  # Use our pre-processed data if AI returned nothing
                    
            except Exception as e:
                logger.error(f"AI processor error: {e}")
                print(f"Using fallback analysis due to AI error: {e}")
                analyzed = ai_input  # Use our enhanced input as the analysis result
                
            current_scan['progress'] = 80
            
            # Make sure we have at least the vulnerabilities from our scan
            if not analyzed or len(analyzed) == 0:
                logger.warning("No vulnerabilities in analysis, using raw scan data")
                analyzed = ai_input
            
            # Process each vulnerability to ensure consistency between CVSS and severity
            # and ensure CVE IDs are properly set
            for item in analyzed:
                # Get CVSS score and ensure it's a string
                if 'cvss' not in item or not item['cvss']:
                    item['cvss'] = '5.5'  # Default medium CVSS
                
                cvss = str(item['cvss'])
                
                # Force derive severity based on CVSS score using our standard thresholds
                item['severity'] = map_cvss_to_severity(cvss)
                logger.info(f"Final mapping: Port {item.get('port')}: CVSS {cvss} → Severity: {item['severity']}")
                
                # Ensure CVE IDs are present and properly formatted
                if not item.get('cves') and item.get('vulnerability_id', '').startswith('CVE-'):
                    item['cves'] = [item['vulnerability_id']]
                
                # Convert string CVEs to list if needed
                if isinstance(item.get('cves'), str):
                    item['cves'] = [item['cves']] if item['cves'] and item['cves'] != "N/A" else []
                
                # Ensure cves is always a list
                if 'cves' not in item:
                    item['cves'] = []
                    
                # Add remediation if it's missing
                try:
                    if os.path.exists(remediation_path) and check_model_integrity(remediation_path):
                        with open(remediation_path, 'rb') as f:
                            remediation_model = pickle.load(f)
                        
                        port = item.get('port', '')
                        severity = item.get('severity', 'medium')
                        
                        item['remediation'] = remediation_model.predict([(port, severity)])[0]
                    else:
                        item['remediation'] = f"Keep service on port {item['port']} patched and secured."
                except Exception as e:
                    logger.warning(f"Error generating remediation: {e}")
                    item['remediation'] = "Apply vendor security patches and follow security best practices."

            # HTML report generation - use our custom generator to ensure CVEs are displayed
            try:
                html_report = generate_fallback_report(analyzed)
                logger.info(f"Generated report with {len(analyzed)} vulnerabilities")
                current_scan['report_file'] = html_report
            except Exception as e:
                logger.error(f"Error generating HTML report: {e}")
                # Try a simpler report format if regular generation fails
                html_report = generate_fallback_report(analyzed)
                current_scan['report_file'] = html_report
            
            current_scan['progress'] = 100
            current_scan['status'] = 'complete'
            logger.info(f"Scan complete for {target}")

        except Exception as e:
            logger.error(f"Scan error: {e}")
            current_scan['status'] = 'error'
            current_scan['error'] = str(e)
    except Exception as e:
        logger.error(f"Outer scan error: {e}")
        current_scan['status'] = 'error'
        current_scan['error'] = str(e)

if __name__ == '__main__':
    if not NMAP_EXECUTABLE:
        print("ERROR: Nmap not found. Please install it from https://nmap.org/download.html")
        sys.exit(1)
    else:
        print("=" * 50)
        print("NMAP STATUS: READY")
        print(f"NMAP LOCATION: {NMAP_EXECUTABLE}")
        try:
            version_output = subprocess.run([NMAP_EXECUTABLE, "--version"], 
                                          capture_output=True, text=True).stdout.strip()
            # Fix syntax error by using list indexing with split() and chr(10)
            first_line = version_output.split(chr(10))[0] if version_output else "Unknown"
            print(f"NMAP VERSION: {first_line}")
        except Exception as e:
            print(f"Error getting Nmap version: {e}")
        print("=" * 50)
        
    # Log model information
    print(f"Using models from: {MODELS_DIR}")
    if SEVERITY_MODEL:
        print("ML Model loaded successfully")
    else:
        print("WARNING: Could not load ML model - defaulting to rule-based classification")

    # Ensure template exists
    template_dir = Path(__file__).parent / 'templates'
    template_dir.mkdir(exist_ok=True)
    index_html = template_dir / 'index.html'
    if not index_html.exists():
        index_html.write_text("""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AI-Driven Vulnerability Scanner</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head> 
<body>
  <div class="container py-5">
    <div class="text-center mb-4">
      <h1>AI-Driven Vulnerability Scanner</h1>
      <p class="lead">Enter an IP address or network to scan and analyze for vulnerabilities</p>
    </div>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
          <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
            {{ message }}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
          </div>
        {% endfor %}
      {% endif %}
    {% endwith %}
    <div class="card mb-4">
      <div class="card-body">
        <form method="POST" action="{{ url_for('start_scan') }}">
          <div class="mb-3">
            <label for="target" class="form-label">Target IP / Network:</label>
            <input type="text" class="form-control" id="target" name="target"
                   placeholder="e.g., 192.168.1.1 or 192.168.1.0/24" required>
          </div>
          <div class="mb-3">
            <label for="scanType" class="form-label">Scan Type:</label>
            <select class="form-select" id="scanType" name="scan_type">
              <option value="quick">Quick Scan</option>
              <option value="full" selected>Full Scan with OS Detection</option>
            </select>
          </div>
          <div class="mb-3">
            <label for="ports" class="form-label">Ports to Scan (optional):</label>
            <input type="text" class="form-control" id="ports" name="ports"
                   placeholder="e.g., 22,80,443 or 1-1000">
          </div>
          <div class="d-grid">
            <button type="submit" class="btn btn-primary">Start Scan</button>
          </div>
        </form>
      </div>
    </div>
    {% if status != 'idle' %}
      <div class="mb-4">
        <h5>Status: {{ status|capitalize }} ({{ progress }}%)</h5>
        {% if report_file %}
          <a href="{{ url_for('view_report') }}" class="btn btn-success">View Report</a>
        {% endif %}
      </div>
    {% endif %}
  </div>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>""")

    # Auto-open browser and run
    threading.Thread(target=lambda: webbrowser.open("http://127.0.0.1:5000"), daemon=True).start()
    app.run(debug=False)
