#!/usr/bin/env python3
"""Generate domain_categories.json from one or more CSV source files.

CSV format: domain,category
Lines starting with # are treated as comments and ignored.
Later files override earlier files for the same domain.

Usage:
    python seed_categories.py seed_domains.csv [extra.csv ...] --output domain_categories.json
"""

import argparse
import csv
import json
import sys


def main():
    parser = argparse.ArgumentParser(
        description="Merge domain category CSVs into domain_categories.json"
    )
    parser.add_argument("csvfiles", nargs="+", help="CSV files to merge (domain,category)")
    parser.add_argument(
        "--output", default="domain_categories.json", help="Output JSON file (default: domain_categories.json)"
    )
    args = parser.parse_args()

    categories = {}
    for path in args.csvfiles:
        count_before = len(categories)
        try:
            with open(path, newline="") as f:
                reader = csv.reader(f)
                for row in reader:
                    if not row or row[0].strip().startswith("#"):
                        continue
                    if len(row) >= 2:
                        domain = row[0].strip().lower()
                        category = row[1].strip()
                        if domain and category:
                            categories[domain] = category
        except FileNotFoundError:
            print(f"Error: {path} not found", file=sys.stderr)
            sys.exit(1)
        added = len(categories) - count_before
        print(f"Loaded {path}: {added} new entries")

    with open(args.output, "w") as f:
        json.dump(categories, f, indent=2, sort_keys=True)
        f.write("\n")

    print(f"Wrote {len(categories)} total entries to {args.output}")


if __name__ == "__main__":
    main()
