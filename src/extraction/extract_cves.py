import json, gzip, requests
import pandas as pd
from pathlib import Path

data_dir = Path(__file__).parents[2] / 'data'
raw = data_dir / 'raw'
proc = data_dir / 'processed'
raw.mkdir(parents=True, exist_ok=True)
proc.mkdir(parents=True, exist_ok=True)

years = [2023, 2024, 2025]
records = []
for y in years:
    url = f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{y}.json.gz'
    resp = requests.get(url)
    gz_path = raw / f'nvdcve-{y}.json.gz'
    gz_path.write_bytes(resp.content)
    with gzip.open(gz_path, 'rt', encoding='utf-8') as f:
        items = json.load(f)['CVE_Items']
    for item in items:
        meta = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {})
        records.append({
            'CVE_ID': item['cve']['CVE_data_meta']['ID'],
            'Description': item['cve']['description']['description_data'][0]['value'],
            'CVSS_Score': meta.get('baseScore'),
            'Attack_Vector': meta.get('attackVector')
        })

df = pd.DataFrame(records)
df.to_csv(proc / 'cve_master.csv', index=False)
print(f"Saved cve_master.csv with {len(df)} entries.")