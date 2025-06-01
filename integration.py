#!/usr/bin/env python3
"""
Integration Module for Vulnerability Prioritization System

This module integrates Nmap scan results with AI models to:
1. Classify vulnerability severity
2. Generate remediation suggestions
"""

import json
import pandas as pd
import numpy as np
import os
import sys
from pathlib import Path
import pickle
import warnings
import logging
warnings.filterwarnings('ignore')

# Set up logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler("integration.log"), logging.StreamHandler()])
logger = logging.getLogger(__name__)

class VulnerabilityProcessor:
    def __init__(self, models_dir=None):
        """Initialize the processor with paths to AI model files"""
        # Use specified models directory or default to "models" subdirectory
        self.models_dir = Path(models_dir) if models_dir else Path("models")
        
        logger.info(f"Using models directory: {self.models_dir}")
        
        # Ensure models directory exists
        if not self.models_dir.exists():
            logger.warning(f"Models directory not found: {self.models_dir}. Creating directory.")
            self.models_dir.mkdir(exist_ok=True, parents=True)
        
        self.classifier = None
        self.remediation_model = None
        self.vectorizer = None
        self.cve_database = None
        
        try:
            self._load_models()
            self._load_cve_database()
        except Exception as e:
            logger.error(f"Error during initialization: {e}")
            print(f"Warning: Error initializing AI models: {e}")
            print("The application will use fallback classification based on CVSS scores")
    
    def _load_models(self):
        """Load the trained AI models"""
        try:
            # Load the severity classifier model
            classifier_path = self.models_dir / "severity_classifier.pkl"
            if classifier_path.exists():
                logger.info(f"Loading severity classifier from {classifier_path}")
                with open(classifier_path, 'rb') as f:
                    self.classifier = pickle.load(f)
                logger.info("Classifier loaded successfully")
            else:
                logger.warning(f"Classifier model not found at {classifier_path}")
                print(f"Warning: Classifier model not found at {classifier_path}")
            
            # Load the vectorizer used for text processing
            vectorizer_path = self.models_dir / "vectorizer.pkl"
            if vectorizer_path.exists():
                logger.info(f"Loading vectorizer from {vectorizer_path}")
                with open(vectorizer_path, 'rb') as f:
                    self.vectorizer = pickle.load(f)
                logger.info("Vectorizer loaded successfully")
            else:
                logger.warning(f"Vectorizer not found at {vectorizer_path}")
                print(f"Warning: Vectorizer not found at {vectorizer_path}")
            
            # Load the remediation model or database
            remediation_path = self.models_dir / "remediation_model.pkl"
            if remediation_path.exists():
                logger.info(f"Loading remediation model from {remediation_path}")
                with open(remediation_path, 'rb') as f:
                    self.remediation_model = pickle.load(f)
                logger.info("Remediation model loaded successfully")
            else:
                logger.warning(f"Remediation model not found at {remediation_path}")
                print(f"Warning: Remediation model not found at {remediation_path}")
                
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            raise Exception(f"Failed to load AI models: {e}")
    
    def _load_cve_database(self):
        """Load CVE database with remediation information"""
        try:
            # Try to load a CSV or JSON database of CVEs with remediation steps
            cve_paths = [
                self.models_dir / "cve_remediation_db.csv",
                self.models_dir / "cve_full_dataset.csv.csv",
                self.models_dir / "dataset.csv",
                Path("data/processed/New folder") / "cve_full_dataset.csv.csv",
                Path("data/processed/New folder") / "dataset.csv"
            ]
            
            for cve_path in cve_paths:
                if cve_path.exists():
                    logger.info(f"Loading CVE database from {cve_path}")
                    self.cve_database = pd.read_csv(cve_path)
                    logger.info(f"CVE database loaded successfully with {len(self.cve_database)} records")
                    return
            
            # Try JSON format if CSV wasn't found
            json_path = self.models_dir / "cve_remediation_db.json"
            if json_path.exists():
                logger.info(f"Loading CVE database from {json_path}")
                with open(json_path, 'r') as f:
                    self.cve_database = pd.DataFrame(json.load(f))
                logger.info(f"CVE database loaded successfully with {len(self.cve_database)} records")
                return
                
            logger.warning("CVE database not found. Remediation lookups will be limited.")
        except Exception as e:
            logger.error(f"Error loading CVE database: {e}")
            logger.info("Continuing with limited remediation functionality")
    
    def classify_severity(self, vulnerability_data):
        """Classify the severity of a vulnerability using the AI model"""
        # First log what we're processing
        vuln_id = vulnerability_data.get('vulnerability_id', 'unknown')
        logger.debug(f"Classifying severity for: {vuln_id}")
        
        if not self.classifier or not self.vectorizer:
            logger.info(f"Using CVSS-based classification for {vuln_id} (ML model not available)")
            # Fallback to CVSS-based classification if models aren't available
            cvss_str = vulnerability_data.get('cvss', 'N/A')
            if cvss_str != 'N/A':
                try:
                    cvss = float(cvss_str)
                    if cvss >= 9.0:
                        return "Critical"
                    elif cvss >= 7.0:
                        return "High"
                    elif cvss >= 4.0:
                        return "Medium"
                    else:
                        return "Low"
                except (ValueError, TypeError):
                    logger.warning(f"Could not convert CVSS to float: {cvss_str}")
                    return "Unknown"
            return "Unknown"
        
        # Use the ML model for classification
        try:
            # Prepare the text for classification
            description = vulnerability_data.get('description', '')
            features = self.vectorizer.transform([description])
            severity = self.classifier.predict(features)[0]
            logger.info(f"ML classified {vuln_id} as: {severity}")
            return severity
        except Exception as e:
            logger.error(f"Error during severity classification: {e}")
            logger.info("Falling back to CVSS-based classification")
            
            # Fallback to CVSS if ML fails
            cvss_str = vulnerability_data.get('cvss', 'N/A')
            if cvss_str != 'N/A':
                try:
                    cvss = float(cvss_str)
                    if cvss >= 9.0:
                        return "Critical"
                    elif cvss >= 7.0:
                        return "High"
                    elif cvss >= 4.0:
                        return "Medium"
                    else:
                        return "Low"
                except (ValueError, TypeError):
                    return "Unknown"
            return "Unknown"
    
    def get_remediation(self, vulnerability_data):
        """Generate or lookup remediation steps for a vulnerability"""
        vuln_id = vulnerability_data.get('vulnerability_id', 'unknown')
        
        # First try direct lookup in CVE database
        if self.cve_database is not None and vuln_id.startswith('CVE-'):
            matches = self.cve_database[self.cve_database['CVE_ID'] == vuln_id]
            if not matches.empty and 'Remediation_Steps' in matches.columns:
                remediation = matches.iloc[0]['Remediation_Steps']
                if remediation and str(remediation).strip() not in ('', 'N/A'):
                    return remediation
        
        # If no direct match or the remediation model is available, use it
        if self.remediation_model and self.vectorizer:
            try:
                description = vulnerability_data.get('description', '')
                # This assumes your remediation model can generate text
                # The actual implementation would depend on your model type
                features = self.vectorizer.transform([description])
                remediation = self.remediation_model.predict(features)[0]
                return remediation
            except Exception as e:
                logger.error(f"Error generating remediation: {e}")
        
        # Fallback to generic remediation based on service and vulnerability type
        service = vulnerability_data.get('service', '').lower()
        product = vulnerability_data.get('product', '').lower()
        
        # Generic remediations based on service type
        if 'ssh' in service:
            return "Update SSH server to the latest version. Configure proper authentication and disable root login."
        elif any(x in service for x in ['http', 'https']):
            return "Update web server software. Apply security patches. Enable HTTPS with modern cipher suites."
        elif 'smb' in service:
            return "Update SMB to the latest version. Disable SMBv1. Enable proper authentication and restrict access."
        elif 'ftp' in service:
            return "Consider replacing FTP with SFTP. Update FTP server software and enable encryption."
        elif 'database' in service or any(db in service for db in ['mysql', 'mariadb', 'postgres', 'oracle']):
            return "Update database server to latest version. Configure proper authentication and restrict network access."
        
        # Default generic remediation
        return "Update the affected software to the latest version. Apply security patches as released by the vendor."
    
    def process_scan_results(self, scan_results_file):
        """Process scan results and add AI-based analysis"""
        try:
            logger.info(f"Processing scan results from: {scan_results_file}")
            
            # Load scan results
            with open(scan_results_file, 'r') as f:
                scan_data = json.load(f)
            
            analyzed_results = []
            
            for vuln_data in scan_data:
                # Classify severity
                severity = self.classify_severity(vuln_data)
                vuln_data['severity'] = severity
                
                # Get remediation steps
                remediation = self.get_remediation(vuln_data)
                vuln_data['remediation'] = remediation
                
                analyzed_results.append(vuln_data)
            
            # Sort by severity (Critical, High, Medium, Low, Unknown)
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
            analyzed_results.sort(key=lambda x: severity_order.get(x.get('severity', 'Unknown'), 999))
            
            logger.info(f"Processed {len(analyzed_results)} vulnerabilities")
            return analyzed_results
            
        except Exception as e:
            logger.error(f"Error processing scan results: {e}")
            return []

def main():
    if len(sys.argv) < 2:
        print("Usage: python integration.py <scan_results_file.json>")
        sys.exit(1)
    
    scan_file = Path(sys.argv[1])
    if not scan_file.exists():
        print(f"[!] Error: Scan results file not found: {scan_file}")
        sys.exit(1)
    
    # Use models from standard location
    models_dir = Path("C:\\Users\\ibtih\\OneDrive\\Desktop\\mario 2\\models")
    processor = VulnerabilityProcessor(models_dir=models_dir)
    analyzed_results = processor.process_scan_results(scan_file)
    
    if analyzed_results:
        output_file = scan_file.parent / f"analyzed_{scan_file.name}"
        with open(output_file, 'w') as f:
            json.dump(analyzed_results, f, indent=2)
        print(f"[+] Analysis complete. Results saved to {output_file}")
        print(f"[+] Found {len(analyzed_results)} vulnerabilities:")
        
        # Count by severity
        severity_counts = {}
        for result in analyzed_results:
            severity = result.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Print summary
        for severity in ["Critical", "High", "Medium", "Low", "Unknown"]:
            if severity in severity_counts:
                print(f"  - {severity}: {severity_counts[severity]}")
    else:
        print("[!] No vulnerabilities found or analysis failed")

if __name__ == "__main__":
    main()
