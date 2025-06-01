#!/usr/bin/env python3
"""
replace_missing_remediations.py

Reads two CSVs:
  1. output_master.csv   – your current master list (with Remediation_Steps column)
  2. dataset.csv         – a dataset containing CVE details (including Remediation_Steps)

It will:
  - Remove all rows from output_master.csv where Remediation_Steps is blank, “N/A”, or null.
  - Replace them by pulling the same number of new, non-duplicated CVEs from dataset.csv.
  - Preserve all original columns of output_master.csv.
  - Write the result to output_master_filled.csv (or a name you choose).

Usage:
    python replace_missing_remediations.py output_master.csv dataset.csv output_master_filled.csv
"""

import pandas as pd
import sys
from pathlib import Path

def replace_missing_remediations(
    master_path: Path,
    dataset_path: Path,
    output_path: Path,
    key: str = "CVE_ID",
    remediation_col: str = "Remediation_Steps"
):
    # Load inputs
    df_master = pd.read_csv(master_path)
    df_dataset = pd.read_csv(dataset_path)

    # Identify rows with missing remediation
    missing_mask = (
        df_master[remediation_col].isna()
        | (df_master[remediation_col].astype(str).str.strip() == "")
        | (df_master[remediation_col].astype(str).str.upper() == "N/A")
    )
    num_missing = missing_mask.sum()
    print(f"Found {num_missing} rows with missing {remediation_col}.")

    # Keep only rows with filled remediation
    df_filled = df_master[~missing_mask].copy()

    if num_missing == 0:
        print("No missing remediation steps to replace. Writing original master.")
        df_master.to_csv(output_path, index=False)
        return

    # Select replacement rows from dataset.csv:
    # those whose CVE_ID is not already in df_filled
    df_candidates = df_dataset[~df_dataset[key].isin(df_filled[key])]
    df_replacements = df_candidates.head(num_missing).copy()
    print(f"Selected {len(df_replacements)} replacement rows from dataset.csv.")

    # Ensure the replacements have the same columns as master
    for col in df_master.columns:
        if col not in df_replacements.columns:
            df_replacements[col] = pd.NA
    df_replacements = df_replacements[df_master.columns]

    # Combine
    df_new_master = pd.concat([df_filled, df_replacements], ignore_index=True)

    # Write out
    df_new_master.to_csv(output_path, index=False)
    print(f"Wrote {len(df_new_master)} rows to {output_path}.")

def main():
    if len(sys.argv) != 4:
        print(
            "Usage: python replace_missing_remediations.py "
            "<output_master.csv> <dataset.csv> <output_master_filled.csv>",
            file=sys.stderr
        )
        sys.exit(1)

    master_csv = Path(sys.argv[1])
    dataset_csv = Path(sys.argv[2])
    output_csv = Path(sys.argv[3])

    for p in (master_csv, dataset_csv):
        if not p.exists():
            print(f"Error: file not found: {p}", file=sys.stderr)
            sys.exit(1)

    replace_missing_remediations(master_csv, dataset_csv, output_csv)

if __name__ == "__main__":
    main()
