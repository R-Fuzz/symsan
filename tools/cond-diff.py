#!/usr/bin/env python3
"""Join two parse-only condition dumps on (input, label) and cross-tabulate.

Both afltest (the RGD parser) and fgtest (the z3 parser) replay a corpus
through the same instrumented binary and see the same trace, so the label the
runtime assigned to a condition is the same number in both processes.  That
makes (input, label) a key naming one constraint, and the two parsers'
outcomes for it joinable.

Why not just diff the PARSE-REASON histograms the two drivers already print:
they are aggregates.  On libpng z3 folds roughly nine times as many conditions
to constants as RGD does, and totals alone cannot say whether RGD's are a
subset of z3's -- which is the actual question, because RGD's folding is
syntactic (find_roots) while z3 runs a real simplifier, so anything RGD can
fold z3 should fold too.  The converse is not expected to hold.

One confound to hold fixed before reading any of that, because it dominates
everything else: RGD's "cond folded to constant" is *not* only a fold.  When an
operand's AST exceeds max_ast_size (default 200) the parser concretizes it
(rgd-parser.cpp:1654), and a comparison with both operands concretized takes the
same `set_kind(rgd::Bool)` path a genuinely constant one does.  On the 836-seed
libpng corpus that is 21,923 of the 22,043 fold events -- 99.5% -- and z3 has no
equivalent, so comparing the two at the default cap compares a size limit
against a simplifier.  Run the RGD arm with SYMSAN_MAX_AST_SIZE raised (it
converges by 5e5, at +4% parse time) to see the folds that are really folds.

Two denominators, both reported, because they answer different questions.
*Constraints* is distinct (input, label) pairs -- one per condition the parser
had to reason about, which is what a claim about parser capability is over.
*Events* is trace events, which is what PARSE-REASON counts: a label repeats
whenever the same branch is executed on the same operands, since the union
table caches by AST.  A fold concentrated in a hot loop is a rounding error by
the first measure and a large bucket by the second.

Usage:
    cond-diff.py <rgd.dump> <z3.dump> [--implies A=>B] [--examples N]
                 [--cid-ge N] [--cid-lt N] [--intersect]

--cid-ge/--cid-lt restrict to a range of branch ids.  The one split that
matters on a two-stage build is the runtime's own UB checks, whose cids fall in
the range reserved below AFL_ID_BASE=4096 (include/branch_id.h), against the
real branches at or above it.  They are different populations and mixing them
hides both -- see --cid-lt 4096 / --cid-ge 4096.

Input format (driver/sweep.h):
    # parser <tag>
    I <input path>
    C <label> <cid> <addr> <o|e|f> <reason...>
    L                       -- a loop-exit event, no condition

Exit status is 1 if the two dumps do not describe the same traces, or if a
--implies check has counterexamples; 0 otherwise.  So this is usable as a
regression gate, not only as a report.
"""

import sys
from collections import Counter, defaultdict, OrderedDict
import os


class Dump:
    def __init__(self, path):
        self.path = path
        self.tag = None
        # input basename -> OrderedDict(label -> (outcome, reason, cid, addr))
        self.inputs = OrderedDict()
        # (input, label) -> how many trace events carried it
        self.hits = Counter()
        # input basename -> [event...] in trace order, for the sequence check.
        # A loop exit is None; a condition is its label.
        self.seq = defaultdict(list)
        self._load()

    def _load(self):
        cur = None
        with open(self.path) as f:
            for lineno, line in enumerate(f, 1):
                if line.startswith('#'):
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] == 'parser':
                        self.tag = parts[2]
                    continue
                if line.startswith('I '):
                    # basename, not the path: the two arms may have been
                    # pointed at the same seeds through different paths
                    cur = os.path.basename(line[2:].strip())
                    self.inputs.setdefault(cur, OrderedDict())
                    continue
                if line.startswith('L'):
                    if cur is not None:
                        self.seq[cur].append(None)
                    continue
                if line.startswith('C '):
                    if cur is None:
                        die(f"{self.path}:{lineno}: condition before any input")
                    # reason is last and may contain spaces
                    _, label, cid, addr, outcome, reason = line.split(' ', 5)
                    label = int(label)
                    self.seq[cur].append(label)
                    # A label can legitimately repeat within one input: the
                    # union table caches by AST, so two executions of the same
                    # branch on the same operands reuse the label.  The parser
                    # is deterministic and caches too, so the outcome is the
                    # same every time -- assert that rather than assume it, and
                    # keep one row per distinct (input, label).
                    rec = (outcome, reason.strip(), int(cid), addr)
                    prev = self.inputs[cur].get(label)
                    if prev is not None and prev[:2] != rec[:2]:
                        die(f"{self.path}:{lineno}: label {label} of {cur} "
                            f"got two outcomes: {prev[:2]} then {rec[:2]}")
                    self.inputs[cur][label] = rec
                    self.hits[(cur, label)] += 1
                    continue

    def conds(self):
        return sum(len(v) for v in self.inputs.values())

    def events(self):
        return sum(self.hits.values())


def die(msg):
    print(f"cond-diff: {msg}", file=sys.stderr)
    sys.exit(1)


OUTCOME = {'o': 'ok', 'e': 'empty', 'f': 'failed'}


def key_of(rec):
    """How an outcome is named in the cross-tab: ok, or the reason it was not."""
    outcome, reason = rec[0], rec[1]
    if outcome == 'o':
        return 'ok'
    return f"{OUTCOME[outcome]}: {reason}"


def main(argv):
    args, implies, examples = [], [], 3
    cid_ge, cid_lt, intersect = None, None, False
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == '--implies':
            i += 1
            implies.append(argv[i])
        elif a == '--examples':
            i += 1
            examples = int(argv[i])
        elif a == '--cid-ge':
            i += 1
            cid_ge = int(argv[i])
        elif a == '--cid-lt':
            i += 1
            cid_lt = int(argv[i])
        elif a == '--intersect':
            intersect = True
        elif a in ('-h', '--help'):
            print(__doc__)
            return 0
        else:
            args.append(a)
        i += 1
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    a, b = Dump(args[0]), Dump(args[1])
    ta, tb = a.tag or 'A', b.tag or 'B'
    for t, d, p in ((ta, a, args[0]), (tb, b, args[1])):
        print(f"DUMP {t} inputs={len(d.inputs)} conds={d.conds()} "
              f"events={d.events()} file={p}")

    # ---- denominator check -------------------------------------------------
    # The join is only meaningful if the two arms saw the same trace.  Matching
    # totals is the weak version of that and is what the PARSE-SUMMARY lines
    # already gave us; the ordered label sequence is the strong version, and it
    # is free here.  A mismatch means something made the target execute
    # differently under the two drivers, and every number below would be
    # comparing unrelated conditions.
    bad = 0
    common = [k for k in a.inputs if k in b.inputs]
    only_a = [k for k in a.inputs if k not in b.inputs]
    only_b = [k for k in b.inputs if k not in a.inputs]
    if intersect:
        # The z3 arm has to be run per seed with a timeout on a real corpus --
        # some inputs cost it minutes -- so one side legitimately covers fewer
        # seeds.  Restricting to the overlap is fine for a conditional claim
        # ("given RGD folded it, did z3?") and not fine for a marginal one, so
        # the drop is printed rather than absorbed.
        if only_a or only_b:
            print(f"INTERSECT dropping {len(only_a)} inputs only in {ta}, "
                  f"{len(only_b)} only in {tb}; {len(common)} remain")
    else:
        for k in only_a + only_b:
            print(f"SEQ-MISMATCH input {k} appears in only one dump")
            bad += 1
    for k in common:
        if a.seq[k] != b.seq[k]:
            sa, sb = a.seq[k], b.seq[k]
            n = min(len(sa), len(sb))
            at = next((j for j in range(n) if sa[j] != sb[j]), n)
            print(f"SEQ-MISMATCH input {k}: {len(sa)} vs {len(sb)} events, "
                  f"first difference at {at}")
            bad += 1
    print(f"SEQ-CHECK inputs={len(common)} mismatched={bad}")
    if bad:
        print("SEQ-CHECK FAIL -- the two arms did not see the same traces; "
              "the cross-tab below is meaningless")
        return 1

    # ---- cross-tab ---------------------------------------------------------
    cross = Counter()        # distinct (input, label) pairs
    cross_ev = Counter()     # the same, weighted by trace events
    per_pair_examples = defaultdict(list)
    filtered = 0
    for k in common:
        ra, rb = a.inputs[k], b.inputs[k]
        for label, va in ra.items():
            vb = rb.get(label)
            if vb is None:
                # cannot happen once the sequence check passes, but a label
                # present in one and not the other would silently shrink the
                # denominator, so say so rather than skip
                die(f"input {k}: label {label} missing from {tb}")
            cid = va[2]
            if (cid_ge is not None and cid < cid_ge) or \
               (cid_lt is not None and cid >= cid_lt):
                filtered += 1
                continue
            pair = (key_of(va), key_of(vb))
            cross[pair] += 1
            cross_ev[pair] += a.hits[(k, label)]
            if len(per_pair_examples[pair]) < examples:
                per_pair_examples[pair].append((k, label, cid, va[3]))

    total = sum(cross.values())
    total_ev = sum(cross_ev.values())
    if cid_ge is not None or cid_lt is not None:
        lo = cid_ge if cid_ge is not None else 0
        hi = cid_lt if cid_lt is not None else '-'
        print(f"\nFILTER cid in [{lo}, {hi}) -- {filtered} conditions excluded")
    if not total:
        print("\nJOINED nothing (the filter excluded every condition)")
        return 0
    print(f"\nJOINED conds={total} events={total_ev}")
    rows = sorted(cross.items(), key=lambda kv: -kv[1])
    wa = max([len(p[0][0]) for p in rows] + [len(ta)])
    print(f"\n{'conds':>9} {'events':>10}  {ta:<{wa}}  {tb}")
    for (ka, kb), n in rows:
        print(f"{n:>9} {cross_ev[(ka, kb)]:>10}  {ka:<{wa}}  {kb}")

    # marginals, so the table reads against the PARSE-SUMMARY numbers -- which
    # are per event, hence the second column
    ma, mb = Counter(), Counter()
    mae, mbe = Counter(), Counter()
    for (ka, kb), n in cross.items():
        ma[ka] += n
        mb[kb] += n
        mae[ka] += cross_ev[(ka, kb)]
        mbe[kb] += cross_ev[(ka, kb)]
    for tag, m, me in ((ta, ma, mae), (tb, mb, mbe)):
        print(f"\nMARGINAL {tag}")
        for k, n in sorted(m.items(), key=lambda kv: -kv[1]):
            print(f"{n:>9} ({100.0*n/total:6.2f}%) "
                  f"{me[k]:>10} ({100.0*me[k]/total_ev:6.2f}%)  {k}")

    # ---- directional checks ------------------------------------------------
    # "A=>B": every condition whose A-side key contains the substring left of
    # => must have a B-side key containing the substring right of it.  Written
    # as substrings because the two parsers name the same thing differently --
    # RGD says "cond folded to constant", z3 says "constant condition" -- and
    # the claim is about the class, not the wording.
    #
    # The right side may list alternatives separated by "|", which is how a
    # condition the other parser never reached is excused rather than counted
    # as a counterexample: z3's "value mismatch for ICmp" is thrown inside
    # serialize(), before the simplifier ever runs, so such a condition has no
    # opinion about whether it was constant and refuting the implication with
    # it would be wrong.
    rc = 0
    for spec in implies:
        if '=>' not in spec:
            die(f"--implies wants LEFT=>RIGHT, got {spec!r}")
        left, rights = (s.strip() for s in spec.split('=>', 1))
        right = [s.strip() for s in rights.split('|')]
        hits = viol = 0
        shown = 0
        for (ka, kb), n in sorted(cross.items(), key=lambda kv: -kv[1]):
            if left not in ka:
                continue
            hits += n
            if not any(r in kb for r in right):
                viol += n
                if shown < examples:
                    shown += 1
                    ex = per_pair_examples[(ka, kb)]
                    where = ', '.join(f"{k}:{lab} cid={cid} @{addr}"
                                      for k, lab, cid, addr in ex)
                    print(f"\nIMPLIES-VIOLATION {n:>8}  {ka}  ->  {kb}")
                    print(f"    e.g. {where}")
        pct = 100.0 * (hits - viol) / hits if hits else 100.0
        print(f"\nIMPLIES {ta}[{left}] => {tb}[{' | '.join(right)}]: "
              f"{hits-viol}/{hits} hold ({pct:.2f}%), {viol} violations")
        if viol:
            rc = 1
    return rc


if __name__ == '__main__':
    sys.exit(main(sys.argv))
