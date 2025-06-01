import pandas as pd
import requests
from bs4 import BeautifulSoup
from pathlib import Path
import time
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# Paths
root = Path(__file__).parents[2]
data_dir = root / 'data' / 'processed'
master_file = data_dir / 'cve_master.csv'
df = pd.read_csv(master_file)

# Helper to safely fetch URLs with timeout and error handling

def safe_get(url, timeout=1):
    try:
        return requests.get(url, timeout=timeout)
    except requests.RequestException as e:
        logging.warning(f"Request failed for {url}: {e}")
        return None

# Scrape MITRE for remediation steps
def fetch_mitre_remediation(cve_id):
    url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
    resp = safe_get(url)
    if not resp or resp.status_code != 200:
        return None
    soup = BeautifulSoup(resp.text, 'html.parser')
    refs = soup.find('table', {'id': 'GeneratedTable'})
    if not refs:
        return None
    steps = []
    for row in refs.find_all('tr'):
        cols = row.find_all('td')
        if len(cols) >= 2:
            text = cols[1].get_text(strip=True)
            if 'fix' in text.lower() or 'patch' in text.lower():
                steps.append(text)
    return '; '.join(steps) if steps else None

# Only using MITRE for speed; skip ExploitDB to avoid long timeouts

rem_steps = []
patch_flags = []
for cve in df['CVE_ID']:
    logging.info(f"Fetching remediation for {cve}")
    steps = fetch_mitre_remediation(cve) or 'N/A'
    rem_steps.append(steps)
    patch_flags.append('Yes' if steps != 'N/A' else 'No')
    time.sleep(0.5)  # brief pause to avoid hammering MITRE

# Populate DataFrame
df['Remediation_Steps'] = rem_steps
df['Patch_Availability'] = patch_flags
df['Exploit_Availability'] = 'N/A'

# Save dataset with remediations for training
output = data_dir / 'cve_full_dataset.csv'
df.to_csv(output, index=False)
logging.info(f"Saved {output} with {len(df)} records containing remediation steps.")