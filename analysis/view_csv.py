#!/usr/bin/env python3
import csv
import sys
from pathlib import Path


def print_vertical(rows):
    if not rows:
        print("No data")
        return

    for i, r in enumerate(rows):
        print("=" * 60)
        print(f"ROW {i}")
        print("=" * 60)

        max_key = max(len(k) for k in r.keys())

        for k, v in r.items():
            print(f"{k.ljust(max_key)} : {v}")

        print()


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 view_csv_vertical.py file.csv")
        return

    path = Path(sys.argv[1])

    if not path.exists():
        print("File not found:", path)
        return

    with open(path) as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    print_vertical(rows)


if __name__ == "__main__":
    main()