#!/usr/bin/env python3
"""Mutation-test union_folds.c against the folds it claims to cover.

Usage:  tests/symsan/union_folds_mutations.py [--build-dir b4] [--only SUBSTR]
        tests/symsan/union_folds_mutations.py --check-anchors   (fast, no build)

union_folds.c asserts the *label* __taint_union() hands back for a synthetic
operand triple, which is the only way to see a fold at all: every other test in
the suite observes one through the inputs a solver eventually generates, and
disabling a correct fold is semantics-preserving -- the branch still gets a
node, the solver still answers, the input is unchanged.  Measured on the
149-test suite, restoring the historical `1 << 64` width_mask bug, deleting the
Trunc(ZExt) fold and disabling the saturated compare each changed *zero* test
results.  The width_mask bug is the one that actually shipped.

So a green union_folds.c proves nothing on its own -- the assertions have to be
shown to bite.  This script breaks one fold at a time in
runtime/dfsan/dfsan.cpp, rebuilds, and reruns the test, and it is the thing to
run after touching that fold block.  It is not a lit test: it edits the tree and
rebuilds the runtime for every mutation, so it must never run concurrently with
lit, and at ~1 min per mutation the whole matrix is 20-30 minutes.

Two things make the results trustworthy, both learned the hard way:

  * The unmutated tree is in the matrix as a control.  The first version of this
    harness decided a mutation was CAUGHT when stdout lacked `Passed:`, and
    `lit -q` prints no `Passed:` line on success -- so all 16 mutations *and* the
    clean tree read as CAUGHT.  The `RESTORE -> CAUGHT` row is what exposed it.
    Detection here is lit's exit code, and a control that does not SURVIVE is a
    hard failure of the harness, not of the code.

  * Every anchor is checked for exactly one occurrence before anything is built.
    An anchor that no longer matches means the fold block moved and this script
    is silently testing less than it says; that aborts rather than skips.

The source is backed up before the first mutation and restored (and rebuilt) on
any exit, including Ctrl-C.  The backup path is printed at the start; if the
process is hard-killed, `cp` it back by hand.

EXPECT_SURVIVE rows are the honest gaps -- mutations union_folds.c cannot see,
each with the reason.  They are reported but do not fail the run.  A row that
flips from SURVIVED to CAUGHT is good news and says so.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

CAUGHT, SURVIVED, BUILD_FAIL = "CAUGHT", "SURVIVED", "BUILD-FAIL"

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(REPO, "runtime", "dfsan", "dfsan.cpp")
TEST = "tests/symsan/union_folds.c"

# (name, find, replace, expected, why)
#
# `find` must occur exactly once in dfsan.cpp.  Prefer anchoring on a whole
# `case`/`if` line over a fragment: a fragment can drift into matching something
# else, and the uniqueness check would not notice.
MUTATIONS = [
    # --- the commutative swap: what puts a constant operand in l1 at all ------
    ("commutative swap disabled",
     "  if (l1 > l2 && is_commutative(op)) {",
     "  if (false && l1 > l2 && is_commutative(op)) {",
     CAUGHT, None),
    ("swap labels but not values",
     "    Swap(l1, l2);\n    Swap(op1, op2);\n",
     "    Swap(l1, l2);\n",
     CAUGHT, None),

    # --- the early-outs ------------------------------------------------------
    ("both-concrete early-out disabled",
     "  if (l1 == 0 && l2 < CONST_OFFSET &&",
     "  if (false && l1 == 0 && l2 < CONST_OFFSET &&",
     CAUGHT, None),
    ("wide zero-label guard disabled",
     "  if (size > 64 && wide_op_reads_op2(op) && (l1 == 0 || l2 == 0))",
     "  if (false && size > 64 && wide_op_reads_op2(op) && (l1 == 0 || l2 == 0))",
     CAUGHT, None),

    # --- width_mask: the bug that shipped ------------------------------------
    ("width_mask back to (1 << size) - 1",
     "      size >= 64 ? ~(uint64_t)0 : (((uint64_t)1 << size) - 1);",
     "      (((uint64_t)1 << size) - 1);",
     CAUGHT, None),

    # --- op1_is_zero ---------------------------------------------------------
    ("0&x / 0*x return l2",
     "      case __dfsan::And: // 0 & x = 0\n"
     "      case __dfsan::Mul: // 0 * x = 0\n"
     "        return 0;",
     "      case __dfsan::And: // 0 & x = 0\n"
     "      case __dfsan::Mul: // 0 * x = 0\n"
     "        return l2;",
     CAUGHT, None),
    ("0&x not folded",
     "      case __dfsan::And: // 0 & x = 0\n", "", CAUGHT, None),
    ("0|x not folded",
     "      case __dfsan::Or: // 0 | x = x\n", "", CAUGHT, None),
    ("0^x not folded",
     "      case __dfsan::Xor: // 0 ^ x = x\n", "", CAUGHT, None),
    ("0+x not folded",
     "      case __dfsan::Add: // 0 + x = x\n", "", CAUGHT, None),
    ("0|x / 0^x / 0+x return 0",
     "      case __dfsan::Add: // 0 + x = x\n        return l2;",
     "      case __dfsan::Add: // 0 + x = x\n        return 0;",
     CAUGHT, None),

    # --- the shifts of zero, and their UB gate -------------------------------
    # The gate is the whole point: a shift of 0 is 0, but the exponent is
    # symbolic and shifting by >= the width is UB, so folding unconditionally
    # swallows the shift-exponent check.  Both directions have to bite.
    ("shifts of 0 never fold",
     "        if (!flags().solve_ub || !ub_width_ok) return 0;",
     "        if (false) return 0;",
     CAUGHT, None),
    ("shifts of 0 fold unconditionally (ignore UB)",
     "        if (!flags().solve_ub || !ub_width_ok) return 0;\n        break;",
     "        return 0;",
     CAUGHT, None),
    ("0 >> x dropped from the fold",
     "      case __dfsan::LShr: // 0 >>u x = 0\n"
     "      case __dfsan::AShr: // 0 >>s x = 0, the sign bit being shifted in is 0 too\n",
     "", CAUGHT, None),

    # --- op1_is_all_one ------------------------------------------------------
    ("ones&x not folded",
     "    if (op == __dfsan::And) return l2; // 0b11..1 & x = x",
     "    if (false) return l2; // 0b11..1 & x = x",
     CAUGHT, None),
    ("ones|x not folded",
     "    else if (op == __dfsan::Or) return 0; // 0b11..1 | x = 11..1b",
     "    else if (false) return 0; // 0b11..1 | x = 11..1b",
     CAUGHT, None),
    ("1^x -> Not disabled",
     "    else if (op == __dfsan::Xor && size == 1) op = __dfsan::Not;",
     "    else if (false) op = __dfsan::Not;",
     CAUGHT, None),

    # --- op2_is_zero ---------------------------------------------------------
    ("x-0 not folded",
     "    if (op == __dfsan::Sub) return l1; // x - 0 = x",
     "    if (false) return l1; // x - 0 = x",
     CAUGHT, None),
    ("x<<0 not folded",
     "    else if (op == __dfsan::Shl) return l1; // x << 0 = x",
     "    else if (false) return l1; // x << 0 = x",
     CAUGHT, None),
    ("x>>0 not folded",
     "    else if (op == __dfsan::LShr) return l1; // x >> 0 = x\n"
     "    else if (op == __dfsan::AShr) return l1; // x >> 0 = x",
     "    else if (false) return l1; // x >> 0 = x\n"
     "    else if (false) return l1; // x >> 0 = x",
     CAUGHT, None),

    # --- the saturated compare -----------------------------------------------
    ("saturated compare disabled",
     "  if ((op & 0xff) == __dfsan::ICmp && size <= 64 && (l1 == 0) != (l2 == 0)) {",
     "  if (false && (op & 0xff) == __dfsan::ICmp && size <= 64 && (l1 == 0) != (l2 == 0)) {",
     CAUGHT, None),
    ("saturated compare: predicate not swapped",
     "    if (l1 == 0) {\n      switch (pred) {",
     "    if (false) {\n      switch (pred) {",
     CAUGHT, None),
    # #133: AOUT is the *sanitizer's* Printf -- no '#' flag, and an unsupported
    # directive is a Die().  Only the debug=1 RUN line can see this, because
    # with debug off the format string is compiled in but never evaluated.
    ("saturated compare AOUT back to %#lx",
     r'AOUT("simplify saturated cmp: pred %d vs 0x%lx at %d bits\n"',
     r'AOUT("simplify saturated cmp: pred %d vs %#lx at %d bits\n"',
     CAUGHT, None),

    # --- same label on both sides --------------------------------------------
    ("x^x / x-x not folded",
     "  } else if ((op == __dfsan::Xor || op == __dfsan::Sub) && l1 == l2) {",
     "  } else if (false) {",
     CAUGHT, None),
    ("icmp x,x not folded",
     "  } else if ((op & 0xff) == __dfsan::ICmp && l1 == l2 && l1 != 0) {",
     "  } else if (false) {",
     CAUGHT, None),

    # --- Trunc(ZExt/SExt) ----------------------------------------------------
    ("Trunc(ZExt(x)) not folded",
     "      if (size == __dfsan_label_info[base].size) return base;",
     "      if (false) return base;",
     CAUGHT, None),
    ("Trunc folds at any width",
     "      if (size == __dfsan_label_info[base].size) return base;",
     "      if (true) return base;",
     CAUGHT, None),

    # --- known gaps ----------------------------------------------------------
    ("ub_width_ok per-operand clauses removed",
     "  const bool ub_width_ok = size <= 64 &&\n"
     "                           (l1 == 0 || get_label_info(l1)->size <= 64) &&\n"
     "                           (l2 == 0 || get_label_info(l2)->size <= 64);",
     "  const bool ub_width_ok = size <= 64;",
     SURVIVED,
     "LLVM forces both shift operands to the same type and size > 64 is already "
     "caught by the wide-op guard, so the per-operand clauses are only reachable "
     "from a direct dfsan_union() caller passing mismatched widths.  Kept as "
     "cheap defence; nothing in-tree exercises them."),
    ("PtrToInt(string_op) - base not folded",
     "        AOUT(\"simplify ptr2int(string_op) - base: %d\\n\", l1);\n"
     "        return l1;",
     "        AOUT(\"simplify ptr2int(string_op) - base: %d\\n\", l1);",
     SURVIVED,
     "needs an l1 that is PtrToInt over an fstr_op node; dfsan_union() cannot "
     "build one from synthetic operands, so this fold is covered only by the "
     "string tests, which see it the weak (semantics-preserving) way."),
]


def check_anchors(text):
    """Every `find` must match exactly once, or this script is testing less
    than it claims.  Checked up front so drift costs a second, not a matrix."""
    bad = []
    for name, find, _, _, _ in MUTATIONS:
        n = text.count(find)
        if n != 1:
            bad.append("  %-46s %d occurrences" % (name, n))
    if bad:
        sys.stderr.write(
            "anchor mismatch in %s -- the fold block moved and these mutations\n"
            "would test nothing.  Update this script:\n%s\n"
            % (os.path.relpath(SRC, REPO), "\n".join(bad)))
        return False
    return True


def build(bd, jobs):
    for cmd in (["make", "-j%d" % jobs], ["make", "install"]):
        if subprocess.run(cmd, cwd=bd, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode:
            return False
    return True


def run_test(bd):
    """CAUGHT/SURVIVED from lit's exit code -- never from its stdout, which
    prints no `Passed:` line under -q and reads as failure for every run."""
    lit = os.path.join(bd, "tests", "lit", "bin", "lit")
    r = subprocess.run([lit, "-q", TEST], cwd=bd,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return CAUGHT if r.returncode else SURVIVED


def main():
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build-dir", default="b4",
                    help="build directory, relative to the repo root (default: b4)")
    ap.add_argument("--jobs", "-j", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--only", metavar="SUBSTR",
                    help="run only mutations whose name contains SUBSTR")
    ap.add_argument("--list", action="store_true", help="list mutations and exit")
    ap.add_argument("--check-anchors", action="store_true",
                    help="verify every anchor still matches, then exit")
    args = ap.parse_args()

    if args.list:
        for name, _, _, expect, why in MUTATIONS:
            print("%-46s expect %s" % (name, expect))
            if why:
                print("    %s" % why)
        return 0

    orig = open(SRC).read()
    if not check_anchors(orig):
        return 2
    if args.check_anchors:
        print("all %d anchors match" % len(MUTATIONS))
        return 0

    bd = os.path.join(REPO, args.build_dir)
    if not os.path.isdir(bd):
        sys.stderr.write("no such build directory: %s\n" % bd)
        return 2

    todo = [m for m in MUTATIONS if not args.only or args.only in m[0]]
    if not todo:
        sys.stderr.write("no mutation matches %r\n" % args.only)
        return 2

    fd, backup = tempfile.mkstemp(prefix="dfsan.cpp.", suffix=".orig")
    os.close(fd)
    shutil.copy(SRC, backup)
    print("source backed up to %s" % backup)
    print("%d mutations plus the control, ~1 min each\n" % len(todo))

    results, harness_broken = [], False
    try:
        # The control runs first: if the clean tree does not pass, every CAUGHT
        # below would be meaningless and there is no point spending the matrix.
        if not build(bd, args.jobs):
            sys.stderr.write("clean tree does not build\n")
            return 2
        got = run_test(bd)
        print("%-46s %s" % ("(control) unmutated tree", got))
        if got != SURVIVED:
            sys.stderr.write(
                "\nthe clean tree FAILS union_folds.c -- fix that first; every\n"
                "mutation below would read as CAUGHT for the wrong reason.\n")
            return 2

        for name, find, repl, expect, _ in todo:
            open(SRC, "w").write(orig.replace(find, repl, 1))
            got = BUILD_FAIL if not build(bd, args.jobs) else run_test(bd)
            results.append((name, got, expect))
            flag = "" if got == expect else "   <-- expected %s" % expect
            print("%-46s %s%s" % (name, got, flag), flush=True)
    finally:
        open(SRC, "w").write(orig)
        if not build(bd, args.jobs):
            sys.stderr.write("WARNING: rebuild after restore failed; source is "
                             "back but the build dir is stale\n")
            harness_broken = True
        else:
            os.unlink(backup)

    missed = [n for n, got, exp in results if exp == CAUGHT and got != CAUGHT]
    newly = [n for n, got, exp in results if exp == SURVIVED and got == CAUGHT]
    print()
    for n in newly:
        print("now caught (was a known gap): %s -- update MUTATIONS" % n)
    if missed:
        print("NOT CAUGHT by union_folds.c:")
        for n in missed:
            print("  %s" % n)
        return 1
    print("all %d mutations behaved as expected" % len(results))
    return 1 if harness_broken else 0


if __name__ == "__main__":
    sys.exit(main())
