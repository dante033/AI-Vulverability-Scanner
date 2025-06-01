#!/usr/bin/env python3
"""
Test script to check if Nmap is working correctly
"""

import nmap
import sys
import os

def test_nmap():
    """Test if Nmap is installed and working"""
    print("Testing Nmap installation...")
    
    try:
        # Try to create the scanner object
        nm = nmap.PortScanner()
        print("✓ Successfully created Nmap scanner object")
        
        # Try to scan localhost (should always be available)
        print("\nScanning localhost (127.0.0.1) - this may take a few seconds...")
        nm.scan('127.0.0.1', '22-80')
        
        # Check if scan returned results
        hosts = nm.all_hosts()
        if hosts:
            print(f"✓ Scan completed successfully, found {len(hosts)} host(s)")
            print("\nScan results:")
            for host in hosts:
                print(f"  Host: {host} ({nm[host].hostname() if nm[host].hostname() else 'No hostname'})")
                print(f"  State: {nm[host].state()}")
                
                if 'tcp' in nm[host]:
                    print("  Open ports:")
                    for port in nm[host]['tcp']:
                        service = nm[host]['tcp'][port]
                        print(f"    {port}/{service['name']} - {service['state']}")
                else:
                    print("  No open TCP ports found in the specified range")
        else:
            print("✗ Scan completed but found no hosts. This is unusual for localhost.")
        
        print("\nNmap seems to be working correctly!")
        return True
        
    except ImportError:
        print("✗ Failed to import python-nmap. Install it with: pip install python-nmap")
        return False
    except nmap.PortScannerError as e:
        print(f"✗ Error with Nmap scanner: {e}")
        print("Make sure Nmap is installed and in your PATH.")
        print("You can download Nmap from: https://nmap.org/download.html")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    test_nmap()
