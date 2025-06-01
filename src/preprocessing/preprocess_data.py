import pandas as pd
from pathlib import Path

def map_severity(score):
    if pd.isna(score): return 'UNKNOWN'
    if score < 4: return 'LOW'
    if score < 7: return 'MEDIUM'
    if score < 9: return 'HIGH'
    return 'CRITICAL'

data_dir = Path(__file__).parents[2] / 'data' / 'processed'
df = pd.read_csv(data_dir / 'cve_master.csv')
df['Severity'] = df['CVSS_Score'].apply(map_severity)
df.to_csv(data_dir / 'cve_master.csv', index=False)
print("Updated cve_master.csv with severity labels.")