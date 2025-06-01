#!/usr/bin/env python3
"""
Network Scanner Module for Vulnerability Detection System

This module uses Nmap to scan targets for:
- Open ports
- Service detection
- OS detection
- Vulnerabilities (using NSE scripts)
"""

import nmap
import json
import xml.etree.ElementTree as ET
from datetime import datetime
import os
import sys
import subprocess
from pathlib import Path
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler("network_scanner.log"), logging.StreamHandler()])
logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self, nmap_path=None):
        """Initialize the scanner with optional path to nmap binary"""
        self.nmap_path = nmap_path
        self.results_dir = Path("scan_results")
        self.results_dir.mkdir(exist_ok=True)
        
        try:
            # Check if nmap_path is provided and valid
            if nmap_path:
                if os.path.exists(nmap_path) or nmap_path == "nmap":
                    logger.info(f"Initializing Nmap scanner with path: {nmap_path}")
                    self.nm = nmap.PortScanner(nmap_search_path=nmap_path)
                else:
                    logger.warning(f"Specified Nmap path does not exist: {nmap_path}")
                    logger.info("Falling back to default Nmap path")
                    self.nm = nmap.PortScanner()
            else:
                logger.info("Initializing Nmap scanner with default path")
                self.nm = nmap.PortScanner()
                
            # Test Nmap functionality with a minimal scan
            test_result = self.nm.scan('127.0.0.1', '22', arguments='-sV')
            logger.info("Nmap scanner initialized successfully")
            
        except nmap.PortScannerError as e:
            logger.error(f"Nmap error: {e}")
            # Try to get more information about the error
            if "command not found" in str(e).lower():
                logger.error("Nmap executable not found. Please install Nmap: https://nmap.org/download.html")
            elif "permission denied" in str(e).lower():
                logger.error("Permission denied. Try running as administrator/root or check Nmap installation")
            raise Exception(f"Failed to initialize Nmap: {e}")
        except Exception as e:
            logger.error(f"Error initializing Nmap scanner: {e}")
            raise Exception(f"Failed to initialize Nmap scanner: {e}")
    
    def basic_scan(self, target, ports=None):
        """Perform a basic scan for open ports"""
        logger.info(f"Starting basic scan of {target} with ports: {ports if ports else 'default'}")
        
        try:
            if ports:
                scan_args = f'-sS -p {ports}'
            else:
                scan_args = '-sS -p 1-1000'  # Default scan top 1000 ports
                
            self.nm.scan(hosts=target, arguments=scan_args)
            
            # Check if any hosts were found
            if not self.nm.all_hosts():
                logger.warning(f"No hosts found at {target}. The target might be down or not responding")
                return None
            
            logger.info(f"Basic scan completed successfully for {target}")
            return self.nm
        except Exception as e:
            logger.error(f"Error during basic scan: {e}")
            return None
    
    def full_scan(self, target, ports=None):
        """Perform a comprehensive scan with OS and version detection"""
        logger.info(f"Starting comprehensive scan of {target} with ports: {ports if ports else 'default'}")
        
        try:
            if ports:
                scan_args = f'-sS -sV -O -p {ports} --script=vuln'
            else:
                scan_args = '-sS -sV -O --script=vuln'  # OS detection, version detection, and vulnerability scripts
                
            self.nm.scan(hosts=target, arguments=scan_args)
            
            # Check if any hosts were found
            if not self.nm.all_hosts():
                logger.warning(f"No hosts found at {target}. The target might be down or not responding")
                return None
            
            logger.info(f"Comprehensive scan completed successfully for {target}")
            return self.nm
        except Exception as e:
            logger.error(f"Error during comprehensive scan: {e}")
            return None
    
    def parse_results(self):
        """Parse scan results into a structured format for the AI models"""
        try:
            if not self.nm or not self.nm.all_hosts():
                logger.warning("No scan results to parse. Run a scan first.")
                return []
                
            results = []
            
            for host in self.nm.all_hosts():
                host_info = {
                    'host': host,
                    'status': self.nm[host].state(),
                    'os_detection': self.nm[host].get('osmatch', []),
                    'ports': []
                }
                
                if 'tcp' in self.nm[host]:
                    for port, port_info in self.nm[host]['tcp'].items():
                        port_data = {
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info['name'],
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', ''),
                            'vulnerabilities': []
                        }
                        
                        if 'script' in port_info:
                            for script_name, output in port_info['script'].items():
                                if script_name.startswith('vuln'):
                                    vuln_data = self._parse_vulnerability_output(script_name, output)
                                    port_data['vulnerabilities'].extend(vuln_data)
                        
                        host_info['ports'].append(port_data)
                
                results.append(host_info)
            
            return results
            
        except Exception as e:
            logger.error(f"Error parsing scan results: {e}")
            return []
    
    def _parse_vulnerability_output(self, script_name, output):
        """Parse vulnerability output from NSE scripts"""
        vulnerabilities = []
        
        if script_name == 'vulners':
            lines = output.split('\n')
            current_vuln = {}
            
            for line in lines:
                if line.startswith('CVE-'):
                    if current_vuln and 'id' in current_vuln:
                        vulnerabilities.append(current_vuln)
                    cve_parts = line.split('\t')
                    if len(cve_parts) >= 2:
                        current_vuln = {
                            'id': cve_parts[0].strip(),
                            'cvss': cve_parts[1].strip() if len(cve_parts) > 1 else "N/A",
                            'description': ' '.join(cve_parts[2:]) if len(cve_parts) > 2 else "No description available"
                        }
            
            if current_vuln and 'id' in current_vuln:
                vulnerabilities.append(current_vuln)
        else:
            vulnerabilities.append({
                'script': script_name,
                'output': output,
                'id': 'unknown',
                'description': output
            })
        
        return vulnerabilities
    
    def save_results(self, results, target):
        """Save scan results to JSON file"""
        if not results:
            logger.warning("No results to save.")
            results = [{"host": target, "status": "down", "message": "Target unreachable or no open ports found"}]
            
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = self.results_dir / f"scan_{target.replace('/', '_')}_{timestamp}.json"
        
        serializable_results = []
        for host_result in results:
            if isinstance(host_result.get('os_detection'), list):
                host_result['os_detection'] = [dict(match) for match in host_result['os_detection']]
            
            serializable_results.append(host_result)
        
        with open(filename, 'w') as f:
            json.dump(serializable_results, f, indent=2)
        
        logger.info(f"Scan results saved to {filename}")
        return filename
    
    def export_for_ai(self, results):
        """Format results specifically for the AI models"""
        ai_data = []
        
        if not results or not any(host.get('ports') for host in results):
            logger.warning("No open ports or vulnerabilities found. Creating placeholder data for demonstration.")
            return [{
                "host": results[0]['host'] if results else "unknown",
                "port": "N/A",
                "service": "N/A", 
                "product": "N/A",
                "version": "N/A",
                "vulnerability_id": "EXAMPLE-001",
                "cvss": "N/A",
                "description": "No vulnerabilities were found. This is a placeholder entry for demonstration purposes.",
                "severity": "Low"
            }]
        
        for host in results:
            for port_info in host.get('ports', []):
                if port_info.get('vulnerabilities'):
                    for vuln in port_info['vulnerabilities']:
                        vuln_entry = {
                            'host': host['host'],
                            'port': port_info['port'],
                            'service': port_info['service'],
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'vulnerability_id': vuln.get('id', 'unknown'),
                            'cvss': vuln.get('cvss', 'N/A'),
                            'description': vuln.get('description', 'No description available'),
                        }
                        ai_data.append(vuln_entry)
                else:
                    ai_data.append({
                        'host': host['host'],
                        'port': port_info['port'],
                        'service': port_info['service'],
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'vulnerability_id': 'PORT-INFO',
                        'cvss': 'N/A',
                        'description': f"Open {port_info['service']} port detected.",
                    })
        
        return ai_data

def main():
    if len(sys.argv) < 2:
        print("Usage: python network_scanner.py <target_ip_or_network> [nmap_path]")
        sys.exit(1)
    
    target = sys.argv[1]
    
    nmap_path = None
    if len(sys.argv) > 2:
        nmap_path = sys.argv[2]
    
    if not nmap_path:
        common_paths = [
            "C:\\Program Files (x86)\\Nmap\\nmap.exe",
            "C:\\Program Files\\Nmap\\nmap.exe",
            "nmap"
        ]
        
        for path in common_paths:
            try:
                if path == "nmap":
                    subprocess.run(["nmap", "--version"], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, 
                                  check=True)
                    nmap_path = "nmap"
                    break
                elif os.path.exists(path):
                    nmap_path = path
                    break
            except Exception:
                continue
    
    try:
        scanner = NetworkScanner(nmap_path=nmap_path)
        
        print(f"[*] Scanning {target}...")
        scan_result = scanner.full_scan(target)
        
        if scan_result:
            parsed_results = scanner.parse_results()
            scanner.save_results(parsed_results, target)
            ai_data = scanner.export_for_ai(parsed_results)
            
            if not ai_data:
                print("[!] No vulnerabilities found or failed to parse results")
            else:
                print(f"[+] Found {len(ai_data)} potential vulnerabilities")
                
                ai_data_file = scanner.results_dir / f"ai_input_{target.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(ai_data_file, 'w') as f:
                    json.dump(ai_data, f, indent=2)
                print(f"[+] AI input data saved to {ai_data_file}")
        else:
            print("[!] Scan failed - target might be unreachable or no open ports found")
    
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
