import pandas as pd
from pathlib import Path

import sys

INPUT = sys.argv[1]   # change this
OUTPUT_CLEAN = "benign_ls_clean.csv"

HEADER = [
    "COMM","PID","EXEC","OPEN","REN","DEL","CONN","UNIQIP","UNIQPRT",
    "TOTAL_SYSCALLS","UNIQUE_SYSCALLS","ENTROPY","TOP_SYSCALL_FREQ",
    "AVG_RUN_LENGTH","MAX_RUN_LENGTH","TRANSITION_COUNT",
    "RARE_SYSCALL_RATIO","FIRST50_UNIQUE","FIRST100_UNIQUE"
]

def load_hostmon_csv(path: str) -> pd.DataFrame:
    rows = []

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue
            if line.startswith("==== HOST WINDOW"):
                continue
            if line.startswith("COMM,PID,EXEC"):
                continue

            parts = [x.strip() for x in line.split(",")]
            if len(parts) != len(HEADER):
                continue

            rows.append(parts)

    df = pd.DataFrame(rows, columns=HEADER)

    numeric_cols = [c for c in HEADER if c not in ["COMM"]]
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.dropna().reset_index(drop=True)
    return df


def summarize(df: pd.DataFrame, title: str):
    print(f"\n=== {title} ===")
    print(f"Rows: {len(df)}")
    print(f"Processes: {df['COMM'].nunique()}")
    print("\nTop processes by TOTAL_SYSCALLS:")
    print(
        df.groupby("COMM")["TOTAL_SYSCALLS"]
          .sum()
          .sort_values(ascending=False)
          .head(10)
          .to_string()
    )

    print("\nTop processes by OPEN:")
    print(
        df.groupby("COMM")["OPEN"]
          .sum()
          .sort_values(ascending=False)
          .head(10)
          .to_string()
    )

    print("\nTop processes by REN:")
    print(
        df.groupby("COMM")["REN"]
          .sum()
          .sort_values(ascending=False)
          .head(10)
          .to_string()
    )

    print("\nTop processes by DEL:")
    print(
        df.groupby("COMM")["DEL"]
          .sum()
          .sort_values(ascending=False)
          .head(10)
          .to_string()
    )

    print("\nTop processes by CONN:")
    print(
        df.groupby("COMM")["CONN"]
          .sum()
          .sort_values(ascending=False)
          .head(10)
          .to_string()
    )

    print("\nFeature means:")
    cols = [
        "TOTAL_SYSCALLS","UNIQUE_SYSCALLS","ENTROPY","TOP_SYSCALL_FREQ",
        "AVG_RUN_LENGTH","MAX_RUN_LENGTH","TRANSITION_COUNT",
        "RARE_SYSCALL_RATIO","FIRST50_UNIQUE","FIRST100_UNIQUE"
    ]
    print(df[cols].mean().round(4).to_string())


def process_level_summary(df: pd.DataFrame) -> pd.DataFrame:
    agg = df.groupby("COMM", as_index=False).agg({
        "EXEC": "sum",
        "OPEN": "sum",
        "REN": "sum",
        "DEL": "sum",
        "CONN": "sum",
        "UNIQIP": "sum",
        "UNIQPRT": "sum",
        "TOTAL_SYSCALLS": "sum",
        "UNIQUE_SYSCALLS": "mean",
        "ENTROPY": "mean",
        "TOP_SYSCALL_FREQ": "mean",
        "AVG_RUN_LENGTH": "mean",
        "MAX_RUN_LENGTH": "max",
        "TRANSITION_COUNT": "sum",
        "RARE_SYSCALL_RATIO": "mean",
        "FIRST50_UNIQUE": "mean",
        "FIRST100_UNIQUE": "mean",
    })
    return agg.sort_values("TOTAL_SYSCALLS", ascending=False)


if __name__ == "__main__":
    df = load_hostmon_csv(INPUT)
    df.to_csv(OUTPUT_CLEAN, index=False)

    summarize(df, INPUT)

    proc_df = process_level_summary(df)
    print("\n=== Process-level summary ===")
    print(proc_df.head(15).to_string(index=False))

    proc_df.to_csv("process_summary.csv", index=False)
    print(f"\nSaved cleaned rows to: {OUTPUT_CLEAN}")
    print("Saved process summary to: process_summary.csv")