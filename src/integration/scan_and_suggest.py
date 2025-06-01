import nmap
import pandas as pd

scanner = nmap.PortScanner()

def scan_services(ip):
    res = scanner.scan(ip, arguments='-sV')
    rows=[]
    for h,hd in res.get('scan',{}).items():
        for p,svc in hd.get('tcp',{}).items():
            desc=f"{svc.get('name','')} {svc.get('version','')}".strip()
            rows.append({'Port':p,'Description':desc})
    return pd.DataFrame(rows)