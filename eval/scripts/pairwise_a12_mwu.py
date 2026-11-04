#!/usr/bin/env python3
"""Pairwise Vargha-Delaney A12 + Mann-Whitney U on gcov l_abs (5×1h cells).

Reads eval/runs/<prefix>-r{1..5}/<subj>-<suffix>/coverage_final.csv
(or, from a results directory, the same rows flattened by collect_results.py
into its coverage_final.csv and fuzzer_stats.csv)
Writes (into --out, default the directory read):
  eval/runs/pairwise_a12_mwu.csv
  eval/runs/pairwise_aggregate.csv
  eval/runs/per_trial_labs.csv

Note: with n=5, MWU p-values are weak evidence; prefer A12 / median ranks.
"""
from __future__ import annotations

import argparse
import csv
import math
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

SUBJECTS = [
    "libyaml",
    "libmatheval",
    "bc",
    "confetti",
    "krep",
    "woff2",
    "oggenc",
    "libxml2",
    "libexpat",
    "sqlite",
    "unqlite",
    "mujs",
    "quickjs",
    "json-c",
    "jansson",
]

FUZZERS = {
    "lafl-h": ("tier1", "libafl-havoc"),
    "lafl-i2": ("tier1", "libafl-i2s"),
    "lafl-jg": ("tier1", "libafl-jig"),
    "cm": ("cmplog", "afl-cmplog"),
    "i2s": ("aflpp-i2s", "aflpp-i2s"),
    "cmo": ("cmo-i2s", "cmo-i2s"),
    "rq": ("rq-only", "afl-rq-only"),
}
ORDER = list(FUZZERS)


def load_cells(runs: Path) -> dict:
    """(run, cell) -> [l_abs text, execs_done text or None], from either layout."""
    cells = {}
    flat = runs / "coverage_final.csv"
    if flat.is_file():
        with open(flat, newline="") as f:
            for row in csv.DictReader(f):
                cells[(row["run"], row["cell"])] = [row["l_abs"], None]
        stats = runs / "fuzzer_stats.csv"
        if stats.is_file():
            with open(stats, newline="") as f:
                for row in csv.DictReader(f):
                    if (row["run"], row["cell"]) in cells:
                        cells[(row["run"], row["cell"])][1] = row["execs_done"]
        return cells
    for cov in runs.glob("*/*/coverage_final.csv"):
        cell = cov.parent
        line = cov.read_text().strip().splitlines()[-1]
        parts = line.split(",")
        execs = None
        fs = cell / "out/default/fuzzer_stats"
        if fs.exists():
            for ln in fs.read_text().splitlines():
                if ln.startswith("execs_done"):
                    execs = ln.split(":")[1].strip()
        cells[(cell.parent.name, cell.name)] = [parts[1] if len(parts) >= 2 else "", execs]
    return cells


def read_labs(cells: dict, subj: str, prefix: str, suffix: str):
    vals, meta = [], []
    for r in range(1, 6):
        c = cells.get((f"{prefix}-r{r}", f"{subj}-{suffix}"))
        if c is None:
            continue
        labs_s, execs_s = c
        if labs_s.strip() == "":
            meta.append({"r": r, "labs": None, "execs": None, "bad": True})
            continue
        labs = float(labs_s)
        execs = int(execs_s) if execs_s else None
        vals.append(labs)
        meta.append({"r": r, "labs": labs, "execs": execs, "bad": False})
    return vals, meta


def a12(xs, ys):
    n, m = len(xs), len(ys)
    if n == 0 or m == 0:
        return float("nan")
    gt = eq = 0
    for x in xs:
        for y in ys:
            if x > y:
                gt += 1
            elif x == y:
                eq += 1
    return (gt + 0.5 * eq) / (n * m)


def mannwhitney_u_pvalue(xs, ys):
    """Two-sided MWU via normal approx + tie correction. Weak with n=5."""
    n1, n2 = len(xs), len(ys)
    if n1 == 0 or n2 == 0:
        return float("nan"), float("nan")
    combined = [(v, 0) for v in xs] + [(v, 1) for v in ys]
    combined.sort(key=lambda t: t[0])
    ranks = [0.0] * len(combined)
    i = 0
    while i < len(combined):
        j = i
        while j + 1 < len(combined) and combined[j + 1][0] == combined[i][0]:
            j += 1
        avg = 0.5 * (i + 1 + j + 1)
        for k in range(i, j + 1):
            ranks[k] = avg
        i = j + 1
    R1 = sum(ranks[k] for k, (_, g) in enumerate(combined) if g == 0)
    U1 = R1 - n1 * (n1 + 1) / 2.0
    U = min(U1, n1 * n2 - U1)
    n = n1 + n2
    ties = Counter(v for v, _ in combined)
    tie_term = sum(t * t * t - t for t in ties.values())
    if n < 2:
        return U1, float("nan")
    sigma2 = n1 * n2 / 12.0 * ((n + 1) - tie_term / (n * (n - 1)))
    if sigma2 <= 0:
        return U1, 1.0
    mu = n1 * n2 / 2.0
    z = (U - mu + 0.5) / math.sqrt(sigma2) if U < mu else (U - mu - 0.5) / math.sqrt(sigma2)
    p = math.erfc(abs(z) / math.sqrt(2))
    return U1, max(0.0, min(1.0, p))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--runs",
        type=Path,
        default=None,
        help="eval/runs directory, or a results directory holding "
        "collect_results.py's coverage_final.csv (default: <repo>/eval/runs)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="where to write the CSVs (default: the --runs directory)",
    )
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()
    script = Path(__file__).resolve()
    runs = args.runs or (script.parent.parent / "runs")
    if not runs.is_dir():
        print(f"runs dir missing: {runs}", file=sys.stderr)
        return 1
    cells = load_cells(runs)
    out = args.out or runs
    out.mkdir(parents=True, exist_ok=True)

    data, meta_all = {}, {}
    for fk, (prefix, suffix) in FUZZERS.items():
        data[fk], meta_all[fk] = {}, {}
        for s in SUBJECTS:
            vals, meta = read_labs(cells, s, prefix, suffix)
            data[fk][s] = vals
            meta_all[fk][s] = meta

    med = {fk: {} for fk in ORDER}
    if not args.quiet:
        print("=== MEDIAN l_abs ===")
        print(f"{'subject':12s}" + "".join(f"{fk:>9s}" for fk in ORDER) + f"{'best':>8s}")
    for s in SUBJECTS:
        best_fk, best_v = None, -1.0
        row = f"{s:12s}"
        for fk in ORDER:
            vs = data[fk][s]
            if not vs:
                med[fk][s] = None
                row += f"{'—':>9s}"
                continue
            m = statistics.median(vs)
            med[fk][s] = m
            row += f"{m:9.0f}"
            if m > best_v:
                best_v, best_fk = m, fk
        if not args.quiet:
            print(row + f"{best_fk:>8s}")

    pairs_detail = []
    sig_wins = defaultdict(lambda: defaultdict(int))
    a12_gt = defaultdict(lambda: defaultdict(int))
    a12_ge71 = defaultdict(lambda: defaultdict(int))
    a12_mean = defaultdict(lambda: defaultdict(list))
    n_subj = defaultdict(lambda: defaultdict(int))

    for s in SUBJECTS:
        for a in ORDER:
            for b in ORDER:
                if a == b:
                    continue
                xa, xb = data[a][s], data[b][s]
                if len(xa) < 2 or len(xb) < 2:
                    continue
                A = a12(xa, xb)
                _, p = mannwhitney_u_pvalue(xa, xb)
                pairs_detail.append(
                    dict(
                        subject=s,
                        row=a,
                        col=b,
                        A12=round(A, 4),
                        p=round(p, 6),
                        n_row=len(xa),
                        n_col=len(xb),
                        med_row=statistics.median(xa),
                        med_col=statistics.median(xb),
                    )
                )
                n_subj[a][b] += 1
                a12_mean[a][b].append(A)
                if A > 0.5:
                    a12_gt[a][b] += 1
                if A >= 0.71:
                    a12_ge71[a][b] += 1
                if p < 0.05 and A > 0.5:
                    sig_wins[a][b] += 1

    with open(out / "pairwise_a12_mwu.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(pairs_detail[0]))
        w.writeheader()
        w.writerows(pairs_detail)

    with open(out / "per_trial_labs.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["fuzzer", "subject", "repeat", "l_abs", "execs"])
        for fk in ORDER:
            for s in SUBJECTS:
                for m in meta_all[fk][s]:
                    if m.get("bad") or m["labs"] is None:
                        continue
                    w.writerow(
                        [
                            fk,
                            s,
                            m["r"],
                            m["labs"],
                            m["execs"] if m["execs"] is not None else "",
                        ]
                    )

    with open(out / "pairwise_aggregate.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "row",
                "col",
                "n_subj",
                "n_A12_gt_0.5",
                "n_sig_win",
                "n_A12_ge_0.71",
                "mean_A12",
            ]
        )
        for a in ORDER:
            for b in ORDER:
                if a == b or n_subj[a][b] == 0:
                    continue
                w.writerow(
                    [
                        a,
                        b,
                        n_subj[a][b],
                        a12_gt[a][b],
                        sig_wins[a][b],
                        a12_ge71[a][b],
                        round(statistics.mean(a12_mean[a][b]), 4),
                    ]
                )

    if not args.quiet:
        print("\n=== AGGREGATE #A12>0.5 / #sig / meanA12 ===")
        print(f"{'':8s}" + "".join(f"{b:>14s}" for b in ORDER))
        for a in ORDER:
            row = f"{a:8s}"
            for b in ORDER:
                if a == b:
                    row += f"{'·':>14s}"
                    continue
                if n_subj[a][b] == 0:
                    row += f"{'n/a':>14s}"
                    continue
                cell = f"{a12_gt[a][b]:2d}/{sig_wins[a][b]:2d}/{statistics.mean(a12_mean[a][b]):4.2f}"
                row += cell.rjust(14)
            print(row)
        print(f"\nWrote {out}/pairwise_a12_mwu.csv")
        print(f"Wrote {out}/pairwise_aggregate.csv")
        print(f"Wrote {out}/per_trial_labs.csv")
        print("Caveat: n=5 → MWU p-values are weak; prefer A12 / median ranks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
