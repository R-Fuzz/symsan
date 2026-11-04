#!/usr/bin/env python3
"""Load unique_gcov/*.info (lcov) and report exclusive / shared covered lines."""
from __future__ import annotations
import csv
import os
from pathlib import Path
from collections import defaultdict

# UNIQUE_GCOV_DIR, else eval/runs/unique_gcov next to this script.
OUT = Path(os.environ.get("UNIQUE_GCOV_DIR",
                          Path(__file__).resolve().parent.parent / "runs" / "unique_gcov"))
# also accept container path remap when run inside docker
if not OUT.exists():
    OUT = Path("/workspace/concollmic-eval/runs/unique_gcov")

FUZZERS = ["i2s", "cm", "cmo", "rq", "lafl-i2"]


def covered_lines(path: Path) -> set[tuple[str, int]]:
    s: set[tuple[str, int]] = set()
    cur = None
    for ln in path.read_text(errors="replace").splitlines():
        if ln.startswith("SF:"):
            cur = ln[3:]
        elif ln.startswith("DA:") and cur is not None:
            # DA:line,count[,...]
            parts = ln[3:].split(",")
            if len(parts) >= 2:
                try:
                    line_no = int(parts[0])
                    count = int(float(parts[1]))
                except ValueError:
                    continue
                if count > 0:
                    s.add((cur, line_no))
        elif ln.strip() == "end_of_record":
            cur = None
    return s


def main() -> None:
    by_subj: dict[str, dict[str, set]] = defaultdict(dict)
    for p in sorted(OUT.glob("*.info")):
        if "__" not in p.stem:
            continue
        subj, fk = p.stem.split("__", 1)
        by_subj[subj][fk] = covered_lines(p)

    print("=== UNIQUE gcov lines (median trial, lcov) ===")
    print(
        f"{'subject':12s} "
        + " ".join(f"{fk:>8s}" for fk in FUZZERS)
        + " | "
        + " ".join(f"U{fk:>7s}" for fk in FUZZERS)
        + "  shared_all"
    )

    agg_u = {fk: 0 for fk in FUZZERS}
    agg_cov = {fk: 0 for fk in FUZZERS}
    pair_rows = []
    n_subj = 0

    for subj in sorted(by_subj):
        sets = by_subj[subj]
        if len(sets) < 2:
            print(f"{subj}: incomplete {list(sets)}")
            continue
        n_subj += 1
        excl = {}
        for fk, s in sets.items():
            others: set = set()
            for fk2, s2 in sets.items():
                if fk2 != fk:
                    others |= s2
            excl[fk] = s - others
            if fk in agg_u:
                agg_u[fk] += len(excl[fk])
                agg_cov[fk] += len(s)
        inter = None
        for s in sets.values():
            inter = s if inter is None else (inter & s)

        row = f"{subj:12s}"
        for fk in FUZZERS:
            row += f" {len(sets[fk]):8d}" if fk in sets else f" {'—':>8s}"
        row += " |"
        for fk in FUZZERS:
            row += f" {len(excl[fk]):8d}" if fk in excl else f" {'—':>8s}"
        row += f"  {len(inter or [])}"
        print(row)

        for a, b in [("i2s", "cm"), ("i2s", "cmo"), ("cmo", "rq"), ("i2s", "lafl-i2"), ("cm", "lafl-i2")]:
            if a in sets and b in sets:
                only_a = len(sets[a] - sets[b])
                only_b = len(sets[b] - sets[a])
                both = len(sets[a] & sets[b])
                print(f"    {a} vs {b}: only_{a}={only_a} only_{b}={only_b} both={both}")
                pair_rows.append(
                    dict(subject=subj, a=a, b=b, only_a=only_a, only_b=only_b, both=both,
                         cov_a=len(sets[a]), cov_b=len(sets[b]))
                )

    print(f"\n=== SUM exclusive lines over {n_subj} subjects (vs all others present) ===")
    for fk in FUZZERS:
        print(f"  {fk:8s}  covered_sum={agg_cov.get(fk, 0):6d}  exclusive_sum={agg_u.get(fk, 0):6d}")

    with open(OUT / "unique_pairwise.csv", "w", newline="") as f:
        if pair_rows:
            w = csv.DictWriter(f, fieldnames=list(pair_rows[0]))
            w.writeheader()
            w.writerows(pair_rows)

    with open(OUT / "unique_exclusive.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["subject", "fuzzer", "covered", "exclusive"])
        for subj in sorted(by_subj):
            sets = by_subj[subj]
            for fk, s in sets.items():
                others: set = set()
                for fk2, s2 in sets.items():
                    if fk2 != fk:
                        others |= s2
                w.writerow([subj, fk, len(s), len(s - others)])


if __name__ == "__main__":
    main()
