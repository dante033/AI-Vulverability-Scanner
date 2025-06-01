#!/usr/bin/env python3
"""
Report Generator Module for Vulnerability Prioritization System

This module generates user-friendly reports from analyzed vulnerability data.
"""

import json
import sys
import os
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
from datetime import datetime
import webbrowser
import tempfile

class VulnerabilityReporter:
    def __init__(self, output_dir=Path("reports")):
        """Initialize the reporter with output directory"""
        self.output_dir = output_dir
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_csv_report(self, analyzed_data, output_file=None):
        """Generate a CSV report from analyzed vulnerability data"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = self.output_dir / f"vulnerability_report_{timestamp}.csv"
        
        # Convert list to DataFrame for easier CSV generation
        df = pd.DataFrame(analyzed_data)
        
        # Ensure we have all necessary columns
        for col in ['host', 'port', 'service', 'product', 'version', 
                   'vulnerability_id', 'severity', 'cvss', 'description', 'remediation']:
            if col not in df.columns:
                df[col] = "N/A"
        
        # Save to CSV
        df.to_csv(output_file, index=False)
        print(f"[+] CSV report saved to {output_file}")
        return output_file
    
    def generate_html_report(self, analyzed_data, output_file=None):
        """Generate an HTML report from analyzed vulnerability data"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = self.output_dir / f"vulnerability_report_{timestamp}.html"
        
        # Create severity-based CSS classes
        severity_classes = {
            "Critical": "table-danger",
            "High": "table-warning",
            "Medium": "table-info",
            "Low": "table-success",
            "Unknown": "table-secondary"
        }
        
        # Count by severity for charts
        severity_counts = {}
        for item in analyzed_data:
            severity = item.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Create HTML content
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Vulnerability Analysis Report</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body { padding: 20px; }
                .vulnerability-table { margin-top: 30px; }
                .summary-section { margin-bottom: 30px; }
                .chart-container { 
                    width: 500px;
                    height: 400px;
                    margin: 0 auto;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1 class="mb-4">Vulnerability Analysis Report</h1>
                <p>Generated on: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
                
                <div class="row summary-section">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h3>Summary</h3>
                            </div>
                            <div class="card-body">
                                <p>Total vulnerabilities found: """ + str(len(analyzed_data)) + """</p>
                                <table class="table table-sm">
                                    <thead>
                                        <tr>
                                            <th>Severity</th>
                                            <th>Count</th>
                                        </tr>
                                    </thead>
                                    <tbody>
        """
        
        # Add severity counts to the summary table
        for severity in ["Critical", "High", "Medium", "Low", "Unknown"]:
            if severity in severity_counts:
                html_content += f"""
                                        <tr class="{severity_classes.get(severity, 'table-secondary')}">
                                            <td>{severity}</td>
                                            <td>{severity_counts[severity]}</td>
                                        </tr>
                """
        
        html_content += """
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h3>Distribution</h3>
                            </div>
                            <div class="card-body">
                                <div class="chart-container">
                                    <canvas id="severityChart"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <h2>Detailed Findings</h2>
                <div class="table-responsive vulnerability-table">
                    <table class="table table-bordered table-hover">
                        <thead class="table-dark">
                            <tr>
                                <th>Host</th>
                                <th>Port</th>
                                <th>Service</th>
                                <th>Vulnerability ID</th>
                                <th>Severity</th>
                                <th>CVSS</th>
                                <th>Description</th>
                                <th>Remediation</th>
                            </tr>
                        </thead>
                        <tbody>
        """
        
        # Add vulnerability details
        for item in analyzed_data:
            severity = item.get('severity', 'Unknown')
            html_content += f"""
                            <tr class="{severity_classes.get(severity, 'table-secondary')}">
                                <td>{item.get('host', 'N/A')}</td>
                                <td>{item.get('port', 'N/A')}</td>
                                <td>{item.get('service', 'N/A')} {item.get('product', '')} {item.get('version', '')}</td>
                                <td>{item.get('vulnerability_id', 'Unknown')}</td>
                                <td>{severity}</td>
                                <td>{item.get('cvss', 'N/A')}</td>
                                <td>{item.get('description', 'No description')}</td>
                                <td>{item.get('remediation', 'No remediation available')}</td>
                            </tr>
            """
        
        # Complete the HTML document with Chart.js initialization
        html_content += """
                        </tbody>
                    </table>
                </div>
            </div>
            
            <script>
                // Initialize chart
                document.addEventListener('DOMContentLoaded', function() {
                    const ctx = document.getElementById('severityChart').getContext('2d');
                    const severityChart = new Chart(ctx, {
                        type: 'pie',
                        data: {
                            labels: [""" + ", ".join([f"'{severity}'" for severity in severity_counts.keys()]) + """],
                            datasets: [{
                                data: [""" + ", ".join([str(count) for count in severity_counts.values()]) + """],
                                backgroundColor: [
                                    '#dc3545', // Critical - danger
                                    '#ffc107', // High - warning
                                    '#17a2b8', // Medium - info
                                    '#28a745', // Low - success
                                    '#6c757d'  // Unknown - secondary
                                ]
                            }]
                        },
                        options: {
                            responsive: true,
                            plugins: {
                                legend: {
                                    position: 'bottom'
                                },
                                title: {
                                    display: true,
                                    text: 'Vulnerabilities by Severity'
                                }
                            }
                        }
                    });
                });
            </script>
        </body>
        </html>
        """
        
        # Save the HTML file
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        print(f"[+] HTML report saved to {output_file}")
        return output_file
    
    def open_report(self, report_file):
        """Open the generated report in the default web browser"""
        if report_file and report_file.exists():
            report_url = f"file://{report_file.absolute()}"
            print(f"[+] Opening report: {report_url}")
            webbrowser.open(report_url)
        else:
            print(f"[!] Report file not found: {report_file}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python report_generator.py <analyzed_results.json> [--show]")
        sys.exit(1)
    
    analyzed_file = Path(sys.argv[1])
    if not analyzed_file.exists():
        print(f"[!] Error: Analysis results file not found: {analyzed_file}")
        sys.exit(1)
    
    show_report = "--show" in sys.argv
    
    try:
        with open(analyzed_file, 'r') as f:
            analyzed_data = json.load(f)
        
        reporter = VulnerabilityReporter()
        
        # Generate CSV report
        csv_report = reporter.generate_csv_report(analyzed_data)
        
        # Generate HTML report
        html_report = reporter.generate_html_report(analyzed_data)
        
        if show_report:
            reporter.open_report(html_report)
    
    except Exception as e:
        print(f"[!] Error generating report: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
