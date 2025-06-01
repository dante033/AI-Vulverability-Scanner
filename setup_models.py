#!/usr/bin/env python3
"""
Setup script for AI models

This script checks for required model files and creates placeholder ones if needed.
"""

import os
import sys
import pickle
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import json

# Define models directory
MODELS_DIR = Path("C:\\Users\\ibtih\\OneDrive\\Desktop\\mario 2\\models")

def create_directory():
    """Create models directory if it doesn't exist"""
    if not MODELS_DIR.exists():
        print(f"Creating models directory: {MODELS_DIR}")
        MODELS_DIR.mkdir(parents=True, exist_ok=True)
    else:
        print(f"Models directory already exists: {MODELS_DIR}")

def create_placeholder_classifier():
    """Create a placeholder classifier if one doesn't exist"""
    classifier_path = MODELS_DIR / "severity_classifier.pkl"
    
    if classifier_path.exists():
        print(f"Classifier already exists: {classifier_path}")
    else:
        print("Creating placeholder severity classifier...")
        
        # Create a simple classifier that uses CVSS scores for prediction
        classifier = RandomForestClassifier(n_estimators=10)
        
        # Train with some placeholder data
        X = np.array([[0.1], [3.5], [5.5], [8.0], [9.5]])
        y = np.array(["Low", "Low", "Medium", "High", "Critical"])
        classifier.fit(X, y)
        
        # Save the model
        with open(classifier_path, 'wb') as f:
            pickle.dump(classifier, f)
        
        print(f"Placeholder classifier saved to: {classifier_path}")

def create_placeholder_vectorizer():
    """Create a placeholder vectorizer if one doesn't exist"""
    vectorizer_path = MODELS_DIR / "vectorizer.pkl"
    
    if vectorizer_path.exists():
        print(f"Vectorizer already exists: {vectorizer_path}")
    else:
        print("Creating placeholder vectorizer...")
        
        # Create a simple TF-IDF vectorizer
        vectorizer = TfidfVectorizer(max_features=100)
        
        # Fit with placeholder data
        texts = [
            "buffer overflow vulnerability",
            "cross-site scripting attack",
            "SQL injection vulnerability",
            "remote code execution",
            "privilege escalation flaw"
        ]
        vectorizer.fit(texts)
        
        # Save the vectorizer
        with open(vectorizer_path, 'wb') as f:
            pickle.dump(vectorizer, f)
        
        print(f"Placeholder vectorizer saved to: {vectorizer_path}")

def create_placeholder_cve_database():
    """Create a placeholder CVE database if one doesn't exist"""
    cve_path = MODELS_DIR / "cve_remediation_db.csv"
    
    if cve_path.exists():
        print(f"CVE database already exists: {cve_path}")
    else:
        print("Creating placeholder CVE database...")
        
        # Create placeholder data for some common vulnerabilities
        data = {
            'CVE_ID': [
                'CVE-2021-4034',
                'CVE-2022-0847',
                'CVE-2022-22965',
                'CVE-2023-23397',
                'PORT-INFO'
            ],
            'Description': [
                'Polkit pkexec privilege escalation',
                'Dirty Pipe vulnerability in Linux kernel',
                'Spring4Shell vulnerability in Spring Framework',
                'Microsoft Outlook elevation of privilege vulnerability',
                'Open port detected'
            ],
            'CVSS': [7.8, 7.0, 9.8, 9.8, 3.0],
            'Remediation_Steps': [
                'Update the polkit package to the latest version',
                'Apply kernel patches or upgrade to kernel version 5.16.11+ or 5.15.25+',
                'Upgrade to Spring Framework 5.3.18 or 5.2.20',
                'Apply Microsoft security updates for Outlook',
                'Check if this port exposure is necessary and apply appropriate firewall rules'
            ]
        }
        
        df = pd.DataFrame(data)
        df.to_csv(cve_path, index=False)
        
        print(f"Placeholder CVE database saved to: {cve_path}")

def create_placeholder_remediation_model():
    """Create a placeholder remediation model if one doesn't exist"""
    remediation_path = MODELS_DIR / "remediation_model.pkl"
    
    if remediation_path.exists():
        print(f"Remediation model already exists: {remediation_path}")
    else:
        print("Creating placeholder remediation model...")
        
        # Simple dictionary-based remediation model
        remediation_model = {
            'buffer overflow': 'Apply latest security patches and enable DEP/ASLR',
            'cross-site scripting': 'Implement proper input validation and output encoding',
            'sql injection': 'Use parameterized queries and input validation',
            'remote code execution': 'Apply security patches and restrict execution permissions',
            'privilege escalation': 'Apply principle of least privilege and keep systems updated',
            'default': 'Update the affected software and apply security best practices'
        }
        
        with open(remediation_path, 'wb') as f:
            pickle.dump(remediation_model, f)
        
        print(f"Placeholder remediation model saved to: {remediation_path}")

def main():
    print("=" * 50)
    print("Setting up AI models for Vulnerability Scanner")
    print("=" * 50)
    
    # Create models directory
    create_directory()
    
    # Check and create model files
    create_placeholder_classifier()
    create_placeholder_vectorizer()
    create_placeholder_cve_database()
    create_placeholder_remediation_model()
    
    print("\nSetup complete! You can now run the vulnerability scanner.")
    print("For better results, replace these placeholder models with your trained models.")

if __name__ == "__main__":
    main()
