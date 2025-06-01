#!/usr/bin/env python3
"""
Test script to directly call Nmap and verify it works
"""

import subprocess
import os
import sys

def test_direct_nmap():
    """Test if we can directly call Nmap executable"""
    
    # Define paths to check
    nmap_paths = [
        "C:\\Program Files (x86)\\Nmap\\nmap.exe",
        "C:\\Program Files\\Nmap\\nmap.exe",
        "nmap"  # Try PATH
    ]
    
    # Try running each path
    for path in nmap_paths:
        try:
            print(f"Testing path: {path}")
            if path == "nmap":
                cmd = ["nmap", "--version"]
            else:
                if not os.path.exists(path):
                    print(f"  Path does not exist: {path}")
                    continue
                cmd = [path, "--version"]
            
            print(f"  Running command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"  SUCCESS! Nmap found at {path}")
                print(f"  Version: {result.stdout.splitlines()[0]}")
                
                # Try a simple scan to fully verify
                print("\nTesting scan of localhost (127.0.0.1)...")
                scan_cmd = cmd[0:-1] + ["-F", "127.0.0.1"]
                print(f"  Running: {' '.join(scan_cmd)}")
                scan_result = subprocess.run(scan_cmd, capture_output=True, text=True)
                
                if scan_result.returncode == 0:
                    print("  Scan successful!")
                    return True
                else:
                    print(f"  Scan failed: {scan_result.stderr}")
            else:
                print(f"  Failed with: {result.stderr}")
        
        except Exception as e:
            print(f"  Error testing {path}: {e}")
    
    print("\nUnable to find a working Nmap installation.")
    print("Please ensure Nmap is installed and accessible.")
    return False

if __name__ == "__main__":
    print("=" * 60)
    print("Nmap Direct Call Test")
    print("=" * 60)
    success = test_direct_nmap()
    
    if not success:
        print("\nTroubleshooting tips:")
        print("1. Reinstall Nmap from https://nmap.org/download.html")
        print("2. Make sure the installation path is in your system PATH")
        print("3. Try running as administrator")
        print("4. Check Windows Defender or antivirus settings")
        sys.exit(1)
    else:
        print("\nNmap test successful. You can use it in your application.")
