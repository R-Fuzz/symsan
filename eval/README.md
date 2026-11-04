# Hybrid-fuzzing evaluation

A self-contained Docker setup that builds SymSan, its two hybrid front ends
(the LibAFL fuzzer `symsan-fuzz` and the AFL++ plugin `libSymSanMutator.so`),
AFL++ 4.31c, and 15 C/C++ subjects. It then runs fuzzing campaigns and
measures each trial's gcov line coverage.

- **To reproduce the 2026-11-03 baseline**, follow steps 1–4 below; the
  results and what each arm means are in
  [`results/2026-11-03/`](results/2026-11-03/README.md).
- **To measure a change**, build the image from your revision (step 5) and
  run the arm(s) it affects.
- **To fuzz your own target**, the how-tos are
  [`bindings/rust/HYBRID_FUZZING.md`](../bindings/rust/HYBRID_FUZZING.md)
  (LibAFL) and [`driver/aflpp/README.md`](../driver/aflpp/README.md) (AFL++).
  `scripts/run_one.sh` shows complete, working command lines for both.

## Requirements

- Docker ≥ 23 (BuildKit: the image takes the SymSan source as a named build
  context), and network access during the build.
- About 7 GB of disk for the image (6.6 GB), plus room for the queues under
  `$SYMSAN_EVAL_RUNS`.
- Physical cores to pin trials to.  A 1-hour trial occupies one core for the
  hour, plus a few minutes of gcov replay.

## 1. Build the image

```bash
eval/docker/build-image.sh                 # SymSan = tag eval-baseline-2026-11-03
```

This takes about 20 minutes (18 on a 36-thread host), most of it the 15
subjects × 4 builds.  The script exports that SymSan revision with
`git archive`, so uncommitted changes never get into the image.  The image
contains:

| path in the image | what |
|---|---|
| `/opt/aflpp-4.31c` | AFL++ v4.31c, built with LLVM 18 |
| `/workspace/symsan-main` | SymSan at the chosen revision, built and installed to `install/`; `symsan-fuzz` in `bindings/rust/target/release/` |
| `/workspace/ConcoLLMic-artifact` | seeds, `coverage.sh`, `test.c` and `krep` patches from [ConcoLLMic-artifact](https://github.com/ConcoLLMic/ConcoLLMic-artifact) @ `2fce97b` |
| `/workspace/concollmic-eval/src/<subject>/{symsan,afl,cmplog,gcov}` | each subject built four ways (see below) |
| `/workspace/concollmic-eval/{scripts,jobs,cottontail}` | this directory |

The four builds of each subject are:

| role | compiler | used for |
|---|---|---|
| `symsan` | `ko-clang` (SymSan) | the concolic tracer: `--symsan` / `SYMSAN_TARGET` |
| `afl` | `afl-clang-fast`, cmplog **off** | the fuzzing target |
| `cmplog` | `afl-clang-fast`, `AFL_LLVM_CMPLOG=1` | AFL++'s `-c` (only the `cm`/`rq` arms) |
| `gcov` | `gcc --coverage` | measuring coverage after the run, never fuzzed |

`docker run --rm symsan-eval /workspace/concollmic-eval/docker/setup.sh status`
lists them.

## 2. Smoke-test one trial

`enter.sh` runs everything as your uid.  Its only bind mount is
`$SYMSAN_EVAL_RUNS` (default `~/symsan-eval/runs`), which appears in the
container as `/workspace/concollmic-eval/runs`.

```bash
# libyaml, AFL++ + SymSan, 5 minutes, pinned to core 1
eval/enter.sh /workspace/concollmic-eval/scripts/run_one.sh \
    libyaml aflpp-i2s 300 1 /workspace/concollmic-eval/runs/smoke
cat ~/symsan-eval/runs/smoke/libyaml-aflpp-i2s/coverage_final.csv
```

`run_one.sh SUBJECT MODE SECONDS CORE OUTROOT` fuzzes for `SECONDS` and then
replays the seeds and final queue on the gcov build.  It writes the following
to `OUTROOT/SUBJECT-MODE/`:

- `coverage_final.csv`: line %, **lines**, branch %, branches
- `coverage_series.csv`
- `out/` (the queue)
- `fuzz.log`
- `replay.log`

## 3. Run the campaigns

The baseline is five campaigns, each 5 repeats × 1 hour over the jobs in
`jobs/<name>.txt` (one `SUBJECT MODE` per line):

| campaign | jobs | arms |
|---|---|---|
| `tier1` | 45 | `libafl-havoc`, `libafl-i2s`, `libafl-jig` |
| `cmplog` | 15 | `afl-cmplog` |
| `aflpp-i2s` | 15 | `aflpp-i2s` |
| `cmo-i2s` | 15 | `cmo-i2s` |
| `rq-only` | 15 | `afl-rq-only` |

```bash
EVAL_CORES="1 2 3 4" EVAL_MAX_FUZZ=4 SYMSAN_EVAL_CAMPAIGN_NAME=symsan-eval-tier1 \
  eval/enter.sh campaign 5 3600 tier1
docker logs -f --tail 50 symsan-eval-tier1
```

That writes `~/symsan-eval/runs/tier1-r{1..5}/<subject>-<mode>/`, plus a
`summary.txt` per repeat.  Run the other four the same way, one after
another or on disjoint cores.  Give each its own `SYMSAN_EVAL_CAMPAIGN_NAME`
and `EVAL_SLOTS_DIR`.

A job file of your own can live in the runs directory, e.g.
`eval/enter.sh campaign 1 600 /workspace/concollmic-eval/runs/mine.txt`
reads `~/symsan-eval/runs/mine.txt` and writes `~/symsan-eval/runs/mine-r1/`.

These knobs are read by `scripts/env.sh`:

| env | default | |
|---|---|---|
| `EVAL_CORES` | `1 … 12` | cores to pin trials to, round-robin; keep to physical cores |
| `EVAL_MAX_FUZZ` | 6 | trials (and replays) at once |
| `EVAL_MIN_AVAIL_MB` | 8192 | don't start a trial below this much free RAM |
| `LIBAFL_TIMEOUT` | 200 | `--symsan-timeout` (ms) for the `libafl-*` modes |
| `SYMSAN_EVAL_MEMORY` | `48g` | campaign container's `--memory` (enter.sh) |
| `SYMSAN_EVAL_RUNS` | `~/symsan-eval/runs` | host side of `runs/` (enter.sh) |

The baseline used `EVAL_CORES="1 2 3 4" EVAL_MAX_FUZZ=4`, then `"1 2 3"`/`3`
after a reboot.  So the full baseline is 525 trial-hours: about 5½ days at 4
in parallel.

## 4. Compare with the baseline

```bash
R=~/symsan-eval/runs
python3 eval/scripts/pairwise_a12_mwu.py --runs $R       # per_trial_labs, pairwise_*.csv in $R
python3 eval/scripts/compare_fuzzers.py $R/per_trial_labs.csv
```

Then compare against `results/2026-11-03/tables/`.  These two scripts
regenerate that directory's tables byte for byte from its
`coverage_final.csv` and `fuzzer_stats.csv`.  To keep a run in the same form,
`python3 eval/scripts/collect_results.py $R <dir>` flattens the runs tree into
those files plus `coverage_series.csv` and `summaries.txt`.
They expect all seven arms.  For a partial rerun, compare the
`coverage_final.csv` medians directly.

## 5. Measure a change

```bash
git commit ...                                   # the image only sees committed code
SYMSAN_EVAL_IMAGE=symsan-eval:mine eval/docker/build-image.sh HEAD
SYMSAN_EVAL_IMAGE=symsan-eval:mine SYMSAN_EVAL_RUNS=~/symsan-eval/mine \
  EVAL_CORES="1 2 3 4" EVAL_MAX_FUZZ=4 eval/enter.sh campaign 5 3600 cmo-i2s
```

A change to the SymSan source rebuilds SymSan and the subjects' `symsan`
role; the other three roles stay cached.  Changes under `eval/scripts` other
than the build scripts only re-copy the scripts.

Pick the arm that isolates your change:

- `cmo-i2s` runs SymSan alone, with no havoc to mask a regression.
- `aflpp-i2s` / `libafl-*` show whether it still matters with havoc on.

`run_one.sh` also has modes the baseline did not run: `aflpp-jig`, `cmo-jig`,
`afl-plain`, `libafl-dflt`.

## What to know about the setup

- **ko-clang optimization differs between the two subject sets.**  The eight
  Cottontail subjects' `symsan` builds are `-O0`: `build_ct.sh` sets
  `KO_DONT_OPTIMIZE=0`, and ko-clang only checks whether the variable is set.
  The seven ConcoLLMic subjects get ko-clang's default `-O3`.  The `afl` and
  `cmplog` builds are `-O2` throughout.  The baseline ran this way, so it is
  left as is.
- **Coverage is measured two ways.**  ConcoLLMic subjects use the artifact's
  `coverage.sh` (lcov).  Cottontail subjects use `scripts/coverage_ct.sh`
  (gcovr 8.3, built `-O0 -fsanitize=address`).  Compare numbers within a
  subject, not across subjects.
- **The no-havoc modes (`cmo-*`, `afl-rq-only`) send `fuzz.log` to
  `/dev/null`.**  Once the queue is exhausted, AFL++ prints a line per empty
  cycle, which once reached hundreds of GB.  Use `out/default/fuzzer_stats`
  instead.
- **Unpinned:** the Ubuntu 24.04 packages, and the Rust compiler
  (`--build-arg RUST_TOOLCHAIN=...` pins it; crates are pinned by
  `Cargo.lock`).  Everything else is pinned: AFL++, LibAFL, Z3, gcovr, the
  ConcoLLMic artifact, and each subject's source.
- **The baseline predates two fixes on this branch**: TaintPass's
  struct-field table lookups, and the LibAFL stage draining apply-at-site
  inputs when a trace queued no task.  An image built from `HEAD` has both,
  so its `lafl-*` and SymSan arms are not a like-for-like rerun of the
  baseline.
- **oggenc is slow.**  It does about 120–150 k execs/hour under AFL++ CmpLog
  and about 25 k under LibAFL.

## Files

| | |
|---|---|
| `docker/Dockerfile`, `build-image.sh` | the image (stages `toolchain`, `eval`) |
| `docker/enter.sh`, `run-as-host.sh` | run a shell, a command, or a detached campaign as your uid |
| `docker/setup.sh` | in-image builder: `symsan`, `rust`, `subjects`, `status`, `verify` |
| `scripts/env.sh`, `subjects.sh` | paths, roles, CPU/RAM gating; per-subject binary/args/seeds |
| `scripts/build_subject.sh`, `build_ct.sh`, `build_libyaml.sh`, `build_libmatheval.sh` | fetch (pinned) and build the subjects |
| `scripts/run_one.sh` | one trial: fuzz, then gcov replay |
| `scripts/batch.sh`, `campaign.sh`, `summarize.sh` | a job list over cores; N repeats; a per-repeat table |
| `scripts/replay_cov.sh`, `coverage.sh`, `coverage_ct.sh` | the coverage measurement |
| `scripts/pairwise_a12_mwu.py`, `compare_fuzzers.py` | the tables |
| `scripts/collect_results.py` | flatten a runs tree into the files `results/` keeps |
| `scripts/unique_lines_*.py/.sh`, `run_unique_batch.sh` | lines covered by only one fuzzer (median trials) |
| `cottontail/` | drivers and seeds for the eight Cottontail subjects |
| `jobs/` | the five campaigns' job lists |
| `results/2026-11-03/` | the baseline |
