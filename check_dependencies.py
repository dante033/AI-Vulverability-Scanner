#!/usr/bin/env python3
"""
Dependency Checker for Vulnerability Scanner

This script checks if all required dependencies are properly installed.
"""

import subprocess
import sys
import importlib
import os

def check_nmap():
    """Check if nmap is installed and available"""
    print("Checking Nmap installation...")
    
    try:
        # Try to run nmap with version flag
        result = subprocess.run(['nmap', '-V'], capture_output=True, text=True)
        
        if result.returncode == 0:
            version_line = result.stdout.splitlines()[0]
            print(f"✅ Nmap is installed: {version_line}")
            return True
        else:
            print("❌ Nmap seems to be installed but returned an error:")
            print(result.stderr)
            return False
    except FileNotFoundError:
        print("❌ Nmap is not installed or not in your PATH.")
        print("Please install Nmap from https://nmap.org/download.html")
        return False
    except Exception as e:
        print(f"❌ Error checking Nmap installation: {e}")
        return False

def check_python_package(package_name):
    """Check if a Python package is installed"""
    print(f"Checking for Python package: {package_name}...")
    
    try:
        module = importlib.import_module(package_name)
        print(f"✅ {package_name} is installed.")
        return True
    except ImportError:
        print(f"❌ {package_name} is not installed.")
        return False
    except Exception as e:
        print(f"❌ Error checking {package_name}: {e}")
        return False

def check_local_modules():
    """Check for required local modules"""
    print("Checking for local modules...")
    
    modules = ['network_scanner', 'integration', 'report_generator']
    all_found = True
    
    for module_name in modules:
        module_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{module_name}.py")
        if os.path.exists(module_path):
            print(f"✅ {module_name}.py exists.")
        else:
            print(f"❌ {module_name}.py is missing!")
            all_found = False
    
    return all_found

def main():
    """Main function to check all dependencies"""
    print("=" * 60)
    print("Vulnerability Scanner Dependency Checker")
    print("=" * 60)
    
    # Check for nmap
    nmap_ok = check_nmap()
    
    # Check for required Python packages
    print("\nChecking for required Python packages...")
    packages_to_check = ['flask', 'pandas', 'matplotlib', 'numpy', 'nmap']
    packages_ok = all(check_python_package(pkg) for pkg in packages_to_check)
    
    # Check local modules
    print("\nChecking for required local modules...")
    modules_ok = check_local_modules()
    
    # Summary
    print("\n" + "=" * 60)
    if all([nmap_ok, packages_ok, modules_ok]):
        print("✅ All dependencies are installed correctly!")
        print("You can run the application with: python app.py")
    else:
        print("❌ Some dependencies are missing. Please fix the issues above.")
    print("=" * 60)
    
    return 0 if all([nmap_ok, packages_ok, modules_ok]) else 1

if __name__ == "__main__":
    sys.exit(main())
