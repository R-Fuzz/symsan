# Hybrid-fuzzing baseline, 2026-11-03

Seven fuzzer configurations ("arms") × 15 subjects × 5 trials × 1 hour,
measured as **gcov line coverage** (`l_abs`, absolute lines covered) of each
trial's final queue.  These are the numbers to compare against when you
change SymSan's hybrid-fuzzing path; `../../README.md` covers how to rerun
them.

## What ran

| | |
|---|---|
| SymSan | `55715b5`, tag `eval-baseline-2026-11-03`: `main` plus the tokens (7a24ce8), apply-at-site (ba1abfa) and AFL++ auto-extras (55715b5) commits.  **Not** the commits after it: the struct-field table-lookup change in TaintPass, and the LibAFL stage fix that drains apply-at-site inputs from a trace that queued no task (so the `lafl-*` arms lost those). |
| AFL++ | v4.31c, unpatched (`eval/docker/Dockerfile`) |
| LibAFL | the rev `bindings/rust/Cargo.toml` pins at that commit (`2120857e`) |
| Solvers | i2s, plus JIGSAW in the `*-jig` arm.  Z3 was never enabled. |
| Subjects | seven from the [ConcoLLMic artifact](https://github.com/ConcoLLMic/ConcoLLMic-artifact) (seeds, coverage script) and eight Cottontail subjects with reconstructed drivers (`eval/cottontail/`).  Versions are pinned in `eval/scripts/build_*.sh`. |
| Host | AMD Threadripper 2950X (16 cores / 32 threads), 128 GiB RAM, Ubuntu 26.04.1, Linux 7.0.0-42, Docker 29 |
| Pinning | one fuzzer per **physical** core, core 0 and the HT siblings (16–31) left idle.  At most 3–4 trials at once (`EVAL_CORES="1 2 3 4"`/`EVAL_MAX_FUZZ=4`, then `1 2 3`/`3` after a reboot), container `--memory=48g`, no trial started below 8 GiB free RAM. |

### Arms

| key | campaign dir | what it is |
|---|---|---|
| `lafl-h` | `tier1-rN/*-libafl-havoc` | `symsan-fuzz` with no `--symsan`: LibAFL havoc only |
| `lafl-i2` | `tier1-rN/*-libafl-i2s` | `symsan-fuzz` + SymSan, i2s only, `--symsan-tokens`, `--symsan-timeout 200` |
| `lafl-jg` | `tier1-rN/*-libafl-jig` | as `lafl-i2`, solver ladder i2s → JIGSAW |
| `cm` | `cmplog-rN/*-afl-cmplog` | AFL++ havoc + CmpLog/RedQueen (`-c <cmplog build> -l 2AT`) |
| `i2s` | `aflpp-i2s-rN/*-aflpp-i2s` | AFL++ havoc + `libSymSanMutator.so`, i2s only, `SYMSAN_TOKENS=1` |
| `cmo` | `cmo-i2s-rN/*-cmo-i2s` | `i2s` with `AFL_CUSTOM_MUTATOR_ONLY=1 AFL_DISABLE_TRIM=1`: SymSan only, no havoc |
| `rq` | `rq-only-rN/*-afl-rq-only` | `cm` with `AFL_CUSTOM_MUTATOR_ONLY=1 AFL_DISABLE_TRIM=1`: RedQueen only, no havoc |

The exact command line for each arm is `eval/scripts/run_one.sh`.  `cmo` vs `rq`
is the no-havoc pair, i.e. SymSan's i2s against RedQueen with nothing else
mutating.  `i2s` vs `cm` is the same comparison with havoc on.  The `lafl-*`
arms use a different fuzzer core from the AFL++ arms, so compare them with
each other rather than with `cm` or `i2s`.

## Results

Median `l_abs` over 5 trials (`tables/compare_all_fuzzers.csv`; **best** per
row in bold):

| subject | lafl-h | lafl-i2 | lafl-jg | cm | i2s | cmo | rq |
|---|---:|---:|---:|---:|---:|---:|---:|
| libyaml | 1789 | 1890 | 1890 | 1857 | **1922** | 1809 | 723 |
| libmatheval | 710 | 697 | 697 | **883** | 881 | 668 | 504 |
| bc | 1918¹ | 1893 | 1902 | **2171** | 2111 | 1701 | 1074 |
| confetti | 613 | 606 | 606 | **614** | 606 | 600 | 519 |
| krep | **417** | **417** | **417** | **417** | **417** | 398 | 407 |
| woff2 | 1911 | 1962 | 2037 | 2150 | **2187** | 1813 | 1891 |
| oggenc | 327 | **350** | **350** | 342 | 342 | 332 | 316 |
| libxml2 | 6765¹ | **7833** | 7467 | 7115 | 7824 | 6789 | 5771 |
| libexpat | 2650 | 2741 | 2799 | 2871 | **2906** | 1953 | 2045 |
| sqlite | 13461 | 14523 | 14603 | **15742** | 15199 | 12947 | 10792 |
| unqlite | 4648 | 5091 | 5148 | 5178 | **5246** | 5091 | 4019 |
| mujs | 4522 | 4682 | 4703 | 4886 | **4952** | 4389 | 3176 |
| quickjs | 13406 | 12416 | 12439 | 14242 | **14706** | 12813 | 7878 |
| json-c | 1095 | 1093 | 1095 | **1109** | 1102 | 1018 | 864 |
| jansson | 1176 | 1200 | 1188 | 1200 | **1209** | 1067 | 972 |
| **avg rank** (FuzzBench) | 4.43 | 3.70 | 3.33 | 2.13 | **1.83** | 5.77 | 6.80 |
| **avg normalized score** | 91.5 | 94.2 | 94.4 | 98.4 | **99.3** | 87.2 | 71.2 |

¹ 4 valid trials: the gcov replay of `tier1-r3/bc-libafl-havoc` and of
`tier1-r1/libxml2-libafl-havoc` produced no number (empty
`coverage_final.csv`), so the median is the mean of the middle two.

Pairwise (`tables/pairwise_aggregate.csv`, over the 15 subjects; A12 is
Vargha–Delaney, "sig" is Mann–Whitney p < 0.05 with A12 > 0.5):

| row vs col | A12 > 0.5 | sig wins | mean A12 |
|---|---:|---:|---:|
| `i2s` vs `cm` | 8 | 3 | 0.58 |
| `cm` vs `i2s` | 6 | 2 | 0.42 |
| `cmo` vs `rq` | 12 | 11 | 0.79 |
| `rq` vs `cmo` | 3 | 3 | 0.21 |
| `lafl-i2` vs `lafl-h` | 9 | 8 | 0.70 |
| `lafl-jg` vs `lafl-i2` | 8 | 2 | 0.57 |

With n = 5 the smallest two-sided Mann–Whitney p (no ties) is about 0.008,
so weight A12 and median ranks over p-values.

Median executions per trial: `i2s` 6.8 M, `cm` 5.5 M, `cmo` 175 k, `rq` 18 k.
The no-havoc arms often run out of work within minutes and then cycle an
empty queue for the rest of the hour.

## Files

| path | contents |
|---|---|
| `coverage_final.csv` | one row per trial (`run`, `cell` = `<campaign>-rN`, `<subject>-<mode>`): `l_per,l_abs,b_per,b_abs,x` after replaying seeds + final queue |
| `coverage_series.csv` | the same, every ≥ 60 s of queue mtime (`time` column) |
| `fuzzer_stats.csv` | AFL++'s final `fuzzer_stats`, one column per key (AFL++ arms only) |
| `summaries.txt` | `summarize.sh` per repeat: coverage + the fuzzer's last status line |
| `tables/per_trial_labs.csv`, `pairwise_a12_mwu.csv`, `pairwise_aggregate.csv` | `pairwise_a12_mwu.py --runs .` (byte-identical regeneration) |
| `tables/compare_all_fuzzers.csv` | `compare_fuzzers.py tables/per_trial_labs.csv` (byte-identical) |
| `tables/compare_nohavoc_vs_hybrid.csv` | per subject: `l`, `b`, `execs_done`, `corpus_count` medians for `cm`/`i2s`/`cmo`/`rq` |
| `tables/unique_plan.tsv` | the median trial picked per (subject, fuzzer) for the unique-lines replay |
| `unique_lines/` | `unique_lines_analyze.py` over lcov dumps of those median trials |

`unique_lines/` is **partial**: the replay batch stopped before finishing.
bc, confetti, jansson, json-c, krep, libmatheval, oggenc and woff2 have all
five fuzzers; libexpat, libxml2, libyaml, mujs, quickjs, sqlite and unqlite
have only some.  The lcov dumps behind it (17 MB) are not in the repository.

Not here: queues, crash files and fuzzer logs (too large).  To get them,
rerun the campaign.

## Regenerate the tables

The first four files are a campaign's runs tree flattened by
`collect_results.py`: each row is one per-trial file
(`<run>/<cell>/coverage_final.csv`, …), copied as text.
`pairwise_a12_mwu.py` reads either form; `--out` keeps it from writing
next to its input:

```bash
S=/some/scratch
python3 eval/scripts/pairwise_a12_mwu.py --runs eval/results/2026-11-03 --out $S
python3 eval/scripts/compare_fuzzers.py $S/per_trial_labs.csv > $S/compare_all_fuzzers.csv
diff -r $S eval/results/2026-11-03/tables/ | grep -v '^Only in'
```

The same two scripts read a fresh campaign's runs directory
(`$SYMSAN_EVAL_RUNS`) directly, and
`collect_results.py $SYMSAN_EVAL_RUNS <dir>` turns it into files laid out
like these.
