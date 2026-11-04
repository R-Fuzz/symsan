#!/usr/bin/env python3
"""Median gcov l_abs per (subject, fuzzer) plus FuzzBench-style aggregates.

Reads per_trial_labs.csv (written by pairwise_a12_mwu.py) and prints
compare_all_fuzzers.csv:

  subject,<fuzzer...>,best      median l_abs over the valid trials
  # fuzzbench_avg_rank          mean over subjects of the rank of each
                                fuzzer's median (1 = best, ties averaged)
  # fuzzbench_avg_norm_score    mean over subjects of 100 * median / best median

A median over an even number of trials is the mean of the middle two, so a
cell with a failed trial can print as e.g. 1918.0.
"""
from __future__ import annotations

import argparse
import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

ORDER = ["lafl-h", "lafl-i2", "lafl-jg", "cm", "i2s", "cmo", "rq"]


def fmt(v: float, n: int) -> str:
    # The table this reproduces printed an odd-n median as an int and an
    # even-n one (mean of two floats) as a float.
    return str(int(v)) if n % 2 == 1 else repr(float(v))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("per_trial", type=Path, help="per_trial_labs.csv")
    args = ap.parse_args()

    labs: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    subjects: list[str] = []
    with open(args.per_trial, newline="") as f:
        for row in csv.DictReader(f):
            if row["l_abs"] == "":
                continue
            if row["subject"] not in subjects:
                subjects.append(row["subject"])
            labs[row["subject"]][row["fuzzer"]].append(float(row["l_abs"]))

    out = csv.writer(sys.stdout, lineterminator="\n")
    out.writerow(["subject", *ORDER, "best"])
    med: dict[str, dict[str, float]] = {}
    for s in subjects:
        med[s] = {fk: statistics.median(labs[s][fk]) for fk in ORDER if labs[s][fk]}
        best = max(med[s], key=lambda fk: med[s][fk])
        out.writerow([s, *(fmt(med[s][fk], len(labs[s][fk])) for fk in ORDER), best])

    ranks: dict[str, list[float]] = defaultdict(list)
    norms: dict[str, list[float]] = defaultdict(list)
    for s in subjects:
        vals = sorted(med[s].values(), reverse=True)
        top = vals[0]
        for fk, v in med[s].items():
            first = vals.index(v) + 1
            ties = vals.count(v)
            ranks[fk].append(first + (ties - 1) / 2.0)
            norms[fk].append(100.0 * v / top)
    # statistics.mean rounds once, so the result does not depend on the
    # order the subjects were summed in.
    print("\n# fuzzbench_avg_rank")
    for fk in ORDER:
        print(f"{fk},{statistics.mean(ranks[fk])}")
    print("\n# fuzzbench_avg_norm_score")
    for fk in ORDER:
        print(f"{fk},{statistics.mean(norms[fk])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
