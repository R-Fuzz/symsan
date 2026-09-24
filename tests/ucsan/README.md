# UCSan tests

These are not lit tests and will not become lit tests by being moved here: a
lit test is one compile and one run with its answer checked by `FileCheck`,
while the UCSan suite explores paths -- it drives the engine round a scheduler
with a termination policy and a seed corpus, and judges the set of paths and
reports that come out.  It has its own Python harness (`test.py`), which
depends on `fuzzer/thoroupy` (`UcsanManager`) and a build installed under
`b4/` (see the top-level `CLAUDE.md`).

`lit.local.cfg` empties `config.suffixes` for this directory, so `lit tests`
walks past it rather than trying to run its contents as lit tests.

## Running

```bash
cd tests/ucsan
python3 test.py list              # list available tests
python3 test.py test <test_name>  # run one or more tests
python3 test.py                   # run the whole suite
```

`test/*.c`/`test/*.cpp` are the test sources, each annotated with a
`// METADATA:`/`// ENV:`/`// FLAG:`/`// DISCARD:`/`// ABSENT:` header consumed by
`test.py`; `metadata/*.yaml` are the referenced UCSan entry/scope configs.
`ABSENT` asserts that an exit status is never observed during exploration.
`EVENT: <id>...` asserts that the target reports each event (`PIPE_EVENT_TYPE`,
e.g. 106 for a kernel WARN) at least once.
`SOLVER-ERROR-ABSENT` asserts that the manager reports no solver parse error;
pair it with `DISCARD` when an exit status may be reached but is not the
property under test.
`seeds/create_*_seed.py` are standalone generators for concrete seed files
used with `test.py run_seed` to reproduce a specific path. `ll/` and
`binary/` are build outputs (`test.py clean` removes them).
