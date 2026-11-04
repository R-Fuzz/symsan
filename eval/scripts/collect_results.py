#!/usr/bin/env python3
"""Flatten a runs tree into the few files a results directory keeps.

A campaign leaves three small files per cell (RUNS/<campaign>-rN/<cell>/...)
and a summary per repeat.  This gathers them, verbatim, into:

  OUT/coverage_final.csv   run,cell,l_per,l_abs,b_per,b_abs,x
  OUT/coverage_series.csv  run,cell,time,l_per,l_abs,b_per,b_abs,x
  OUT/fuzzer_stats.csv     run,cell,<every fuzzer_stats key>  (AFL++ arms only)
  OUT/summaries.txt        each <campaign>-rN/summary.txt under a "== run ==" line

`run` is the repeat's directory (e.g. tier1-r1), `cell` the cell's (e.g.
bc-libafl-havoc), so a row names the path it came from.  Values are copied as
text, never re-parsed as numbers.  pairwise_a12_mwu.py reads OUT directly.

  collect_results.py RUNS OUT
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path


def last_rows(path: Path) -> tuple[list[str], list[list[str]]]:
    rows = list(csv.reader(path.read_text().splitlines()))
    return rows[0], rows[1:]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", type=Path, help="runs tree: <campaign>-rN/<cell>/coverage_final.csv")
    ap.add_argument("out", type=Path, help="results directory to write")
    a = ap.parse_args()

    cells = sorted(p.parent for p in a.runs.glob("*/*/coverage_final.csv"))
    if not cells:
        print(f"no */*/coverage_final.csv under {a.runs}", file=sys.stderr)
        return 1
    a.out.mkdir(parents=True, exist_ok=True)

    def key(cell: Path) -> list[str]:
        return [cell.parent.name, cell.name]

    for name in ("coverage_final.csv", "coverage_series.csv"):
        header, out_rows = None, []
        for cell in cells:
            f = cell / name
            if not f.exists():
                continue
            h, rows = last_rows(f)
            if header is None:
                header = h
            elif h != header:
                print(f"{f}: header {h} != {header}", file=sys.stderr)
                return 1
            out_rows += [key(cell) + r for r in rows]
        with open(a.out / name, "w", newline="") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerow(["run", "cell"] + (header or []))
            w.writerows(out_rows)

    keys: list[str] = []
    stats = []
    for cell in cells:
        f = cell / "out/default/fuzzer_stats"
        if not f.exists():
            continue
        d = {}
        for ln in f.read_text().splitlines():
            k, sep, v = ln.partition(":")
            if not sep:
                continue
            k, v = k.strip(), v.strip()
            d[k] = v
            if k not in keys:
                keys.append(k)
        stats.append((key(cell), d))
    with open(a.out / "fuzzer_stats.csv", "w", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["run", "cell"] + keys)
        for k, d in stats:
            w.writerow(k + [d.get(x, "") for x in keys])

    with open(a.out / "summaries.txt", "w") as fh:
        for s in sorted(a.runs.glob("*/summary.txt")):
            fh.write(f"== {s.parent.name} ==\n")
            fh.write(s.read_text())
            if not s.read_text().endswith("\n"):
                fh.write("\n")

    print(f"{len(cells)} cells, {len(stats)} fuzzer_stats -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
