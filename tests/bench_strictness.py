"""
V4 benchmark — one real scan of gradovi.rs, then compute_score() replayed
across all four profiles on the same result set. Produces the matrix that
goes into PRIRUCNIK-V4.md §5 and the blog post.

Why replay instead of 4 full scans:
- compute_score() is a pure function of the result list, so replaying
  gives identical numbers to re-running the scan with each strictness.
- 1 scan (~90s) + 4 score computations (~ms) vs 4 × 90s = ~6 min saved.
- Also insulates the benchmark from flaky target-side variance between
  scans (cache state, CDN edges, timing jitter).

Usage:
    cd security-scanner
    python tests/bench_strictness.py [url]

Defaults to https://gradovi.rs. Pass any URL as arg to benchmark another
site. Prints a table + writes benchmark_results.json for the blog post.
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import scan, compute_score, STRICTNESS_PROFILES


def run_bench(url: str) -> dict:
    print(f"Scanning {url} (single pass, ~90s)...")
    t0 = time.time()
    result = scan(url, mode="safe", strictness="standard")
    elapsed = round(time.time() - t0, 1)
    print(f"  done in {elapsed}s — {result.get('total_checks', 0)} checks, "
          f"{result.get('failed_checks', 0)} failures")

    all_results = result.get("results", [])

    matrix = {}
    for level in ("basic", "standard", "strict", "paranoid"):
        s = compute_score(all_results, strictness=level)
        matrix[level] = {
            "score": s["score"],
            "grade": s["grade"],
            "counts": s["counts"],
        }

    return {
        "url": url,
        "scan_duration_s": elapsed,
        "total_checks": result.get("total_checks", 0),
        "failed_checks": result.get("failed_checks", 0),
        "matrix": matrix,
    }


def main() -> int:
    url = sys.argv[1] if len(sys.argv) > 1 else "https://gradovi.rs"
    bench = run_bench(url)

    print("\n" + "=" * 70)
    print(f"Benchmark: {bench['url']}")
    print(f"Checks: {bench['total_checks']} | Failures: {bench['failed_checks']}")
    print("-" * 70)
    print(f"{'Profile':<12} {'Score':>7} {'Grade':>7}  "
          f"{'CRIT':>5} {'HIGH':>5} {'MED':>5} {'LOW':>5}")
    print("-" * 70)
    for level in ("basic", "standard", "strict", "paranoid"):
        m = bench["matrix"][level]
        c = m["counts"]
        print(f"{level:<12} {m['score']:>7} {m['grade']:>7}  "
              f"{c['critical']:>5} {c['high']:>5} {c['medium']:>5} {c['low']:>5}")
    print("=" * 70)

    out_path = Path(__file__).parent / "benchmark_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(bench, f, indent=2, ensure_ascii=False)
    print(f"\nWritten: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
