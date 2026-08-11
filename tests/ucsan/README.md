# UCSan tests

Reserved.  The UCSan tests are not part of this tree yet.

They are also not lit tests and will not become lit tests by being moved here: a
lit test is one compile and one run with its answer checked by `FileCheck`,
while the UCSan suite explores paths -- it drives the engine round a scheduler
with a termination policy and a seed corpus, and judges the set of paths and
reports that come out.  It has its own Python harness, and whatever lands here
will bring that harness with it.

`lit.local.cfg` empties `config.suffixes` for this directory, so `lit tests`
walks past it rather than trying to run its contents as lit tests.
