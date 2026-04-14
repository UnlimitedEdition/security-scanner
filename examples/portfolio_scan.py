#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Example: Portfolio Security Scanner

Scans a list of domains and generates a summary report.
Useful for monitoring the security posture of all company web properties.

Usage:
    python portfolio_scan.py

Configuration:
    Edit the DOMAINS list below or pass a file:
    python portfolio_scan.py --domains domains.txt

Requirements:
    pip install requests tabulate
"""

import argparse
import json
import sys
import time
from datetime import datetime
from typing import List, Dict

try:
    import requests
except ImportError:
    print("Error: 'requests' package required. Install with: pip install requests")
    sys.exit(1)

try:
    from tabulate import tabulate
except ImportError:
    tabulate = None

# ─── Configuration ────────────────────────────────────────────────────

SCANNER_URL = "https://security-skener.gradovi.rs"

# Edit this list with your domains
DOMAINS = [
    "example.com",
    "app.example.com",
    "docs.example.com",
    "status.example.com",
]

# Minimum grade to consider "passing"
PASS_THRESHOLD = "C"

# ─── Core Logic ───────────────────────────────────────────────────────


def scan_domain(domain: str, scanner_url: str) -> Dict:
    """Scan a single domain and return the result."""
    url = f"https://{domain}" if not domain.startswith("http") else domain

    try:
        resp = requests.post(
            f"{scanner_url}/scan",
            json={"url": url, "consent_accepted": True, "strictness": "standard"},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()

        # Handle async scan (poll for completion)
        scan_id = data.get("scan_id")
        if scan_id and data.get("status") != "completed":
            for _ in range(60):
                time.sleep(5)
                status_resp = requests.get(
                    f"{scanner_url}/scan/{scan_id}", timeout=10
                )
                status = status_resp.json()
                if status.get("status") == "completed":
                    data = status
                    break
                elif status.get("status") == "error":
                    return {
                        "domain": domain,
                        "grade": "ERR",
                        "score": 0,
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "error": status.get("error", "Unknown error"),
                    }

        result = data.get("result", {})
        score = result.get("score", {})
        counts = score.get("counts", {})

        return {
            "domain": domain,
            "grade": score.get("grade", "N/A"),
            "score": score.get("score", 0),
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "error": None,
        }

    except Exception as e:
        return {
            "domain": domain,
            "grade": "ERR",
            "score": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "error": str(e)[:100],
        }


def grade_passes(grade: str, threshold: str) -> bool:
    """Check if a grade meets the minimum threshold."""
    order = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1, "ERR": 0, "N/A": 0}
    return order.get(grade, 0) >= order.get(threshold, 3)


def main():
    parser = argparse.ArgumentParser(
        description="Scan a portfolio of domains for security issues"
    )
    parser.add_argument(
        "--domains",
        type=str,
        help="Path to a text file with one domain per line",
    )
    parser.add_argument(
        "--scanner-url",
        type=str,
        default=SCANNER_URL,
        help=f"Scanner API URL (default: {SCANNER_URL})",
    )
    parser.add_argument(
        "--threshold",
        type=str,
        default=PASS_THRESHOLD,
        choices=["A", "B", "C", "D", "F"],
        help=f"Minimum passing grade (default: {PASS_THRESHOLD})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    args = parser.parse_args()

    domains = DOMAINS
    if args.domains:
        with open(args.domains) as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"🛡️  Portfolio Security Scanner")
    print(f"   Scanner: {args.scanner_url}")
    print(f"   Domains: {len(domains)}")
    print(f"   Threshold: {args.threshold}")
    print()

    results: List[Dict] = []
    for i, domain in enumerate(domains, 1):
        print(f"[{i}/{len(domains)}] Scanning {domain}...", end=" ", flush=True)
        result = scan_domain(domain, args.scanner_url)
        results.append(result)

        if result["error"]:
            print(f"❌ Error: {result['error']}")
        else:
            icon = "✅" if grade_passes(result["grade"], args.threshold) else "⚠️"
            print(f"{icon} Grade: {result['grade']} ({result['score']}/100)")

        # Rate limit — be respectful to the scanner
        if i < len(domains):
            time.sleep(2)

    # ─── Output ───────────────────────────────────────────────────────

    if args.json:
        output = {
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "threshold": args.threshold,
            "total": len(results),
            "passing": sum(1 for r in results if grade_passes(r["grade"], args.threshold)),
            "failing": sum(1 for r in results if not grade_passes(r["grade"], args.threshold)),
            "results": results,
        }
        print(json.dumps(output, indent=2))
    else:
        print()
        print("=" * 70)
        print("PORTFOLIO SECURITY REPORT")
        print(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
        print("=" * 70)
        print()

        if tabulate:
            headers = ["Domain", "Grade", "Score", "CRIT", "HIGH", "MED", "LOW"]
            rows = [
                [
                    r["domain"],
                    r["grade"],
                    f"{r['score']}/100",
                    r["critical"] or "-",
                    r["high"] or "-",
                    r["medium"] or "-",
                    r["low"] or "-",
                ]
                for r in results
            ]
            print(tabulate(rows, headers=headers, tablefmt="grid"))
        else:
            for r in results:
                status = "PASS" if grade_passes(r["grade"], args.threshold) else "FAIL"
                print(
                    f"  [{status}] {r['domain']:30s}  "
                    f"Grade: {r['grade']}  Score: {r['score']:3d}/100  "
                    f"C:{r['critical']} H:{r['high']} M:{r['medium']} L:{r['low']}"
                )

        print()
        passing = sum(1 for r in results if grade_passes(r["grade"], args.threshold))
        failing = len(results) - passing
        print(f"Summary: {passing} passing, {failing} failing (threshold: {args.threshold})")

        if failing > 0:
            print()
            print("⚠️  Failing domains:")
            for r in results:
                if not grade_passes(r["grade"], args.threshold):
                    print(f"   - {r['domain']} (Grade: {r['grade']}, Score: {r['score']})")
            sys.exit(1)


if __name__ == "__main__":
    main()
