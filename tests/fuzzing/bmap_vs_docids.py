#!/usr/bin/env python3
"""Cross-check a TaintPass branch map against AFL++'s own id listing.

Usage: bmap_vs_docids.py <target.bmap> <docids.txt>

Both come out of the *same* afl-clang-lto link -- the `.bmap` from TaintPass
running on `<out>.0.5.precodegen.bc`, the listing from AFL_LLVM_DOCUMENT_IDS --
so they are two independent readings of one numbering and have to agree
exactly.  covcheck already checks the map against what a run actually walks;
this checks it against what the *compiler* recorded, which catches a map that
is wrong in a way no single input happens to execute.

AFL++ writes one line per numbered *block*, and how much it says about a block
is what decides how much can be checked:

    edgeID=N dir=D src=...            a branch direction  -> map `C` line
    edgeID=N dir=1 case=V src=...     a switch case       -> map `S` line
    edgeID=N                          a numbered block reached some other way:
                                      the one behind a switch default, and the
                                      several hundred that are no branch's
                                      target at all

The first two are required to agree in both directions, keyed on the edge id
because that is what is unique -- two switches in one module can share a case
value.  The third can only be checked one way, since a bare id says nothing
about which of the map's lines, if any, should be reaching it.

A select gets no line at all, and so no check beyond the range one: AFL++ emits
its two ids inline as the arms of `select i1 %cond, i32 trueID, i32 falseID`,
which is not a block and has no counter to document.  This is the one part of
the map nothing outside TaintPass can confirm.  (Measured on libpng: exactly
the 12 select ids are undocumented and nothing else is, so the exemption below
is narrow -- if a *branch* target ever went missing it would still be caught.)
"""

import re
import sys


def die(msg):
    print("bmap_vs_docids: " + msg, file=sys.stderr)
    sys.exit(1)


def read_bmap(path):
    """-> (base, edges, {edge: dir}, {edge: case value}, mentioned, selects)

    `mentioned` is every id the map names; `selects` is the subset AFL++ cannot
    have documented, which is exactly the ids on `X` lines.
    """
    base = edges = None
    dirs, cases, mentioned, selects = {}, {}, set(), set()

    def claim(where, edge, key, value):
        if edge in where and where[edge] != value:
            die("edge %d is %s=%s on one line and %s on another; an edge id "
                "belongs to one branch direction" % (edge, key, where[edge], value))
        where[edge] = value

    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                m = re.match(r"# symsan branch map v1 base=(\d+) edges=(\d+)$", line)
                if not m:
                    die("%s:%d: unrecognized header %r" % (path, lineno, line))
                base, edges = int(m.group(1)), int(m.group(2))
                continue
            p = line.split()
            kind = p[0]
            if kind in ("C", "X"):
                cid, t, f_ = int(p[1]), int(p[2]), int(p[3])
                ids = [cid] + [e for e in (t, f_) if e != -1]
                mentioned.update(ids)
                # A select's ids are not branch directions to AFL++ and carry no
                # dir=, so only C lines go in for the two-way check.
                if kind == "C":
                    for edge, direction in ((t, 1), (f_, 0)):
                        if edge != -1:
                            claim(dirs, edge, "dir", direction)
                else:
                    selects.update(ids)
            elif kind == "D":
                cid, d = int(p[1]), int(p[2])
                mentioned.update([cid] + ([d] if d != -1 else []))
            elif kind == "S":
                cid, value, e = int(p[1]), int(p[2]), int(p[3])
                mentioned.update([cid] + ([e] if e != -1 else []))
                if e != -1:
                    claim(cases, e, "case", value)
            else:
                die("%s:%d: unrecognized line %r" % (path, lineno, line))

    if base is None:
        die("%s has no `# symsan branch map v1` header" % path)
    return base, edges, dirs, cases, mentioned, selects


def read_docids(path):
    """-> ({edge: dir}, {edge: case value}, {every edge documented}, {shared})

    AFL++ *appends*, and every link numbers from AFL_LLVM_LTO_STARTID, so a
    listing that outlived more than one link holds more than one numbering --
    and they overlap at the bottom.  A target whose build runs configure is the
    ordinary case: libpng's link tests contribute seven records under ids
    4097-4101, which the real link also assigned to real branches.

    An id claimed by two records is therefore not a contradiction to report but
    an id this file cannot answer for, and it comes back in the fourth value so
    the caller can leave it out of the comparison.  The `.bmap` has no such
    problem -- TaintPass writes it once, over one module.
    """
    dirs, cases, seen, shared = {}, {}, set(), set()
    with open(path) as f:
        for line in f:
            m = re.search(r"edgeID=(\d+)", line)
            if not m:
                continue
            edge = int(m.group(1))
            if edge in seen:
                shared.add(edge)
            seen.add(edge)
            d = re.search(r"\bdir=([01])\b", line)
            c = re.search(r"\bcase=(\d+)\b", line)
            if c:
                cases[edge] = int(c.group(1))
            elif d:
                dirs[edge] = int(d.group(1))
    return dirs, cases, seen, shared


def compare(what, mine, theirs, reverse):
    """Both directions where the listing describes one link, else the forward
    one only.  Forward -- everything the map claims is something AFL++ recorded,
    on the side AFL++ recorded it -- is what catches a wrong or swapped target,
    and holds however many links the listing accumulated: a stray link can only
    add ids the map does not name.  The reverse direction catches a *dropped*
    entry, and cannot tell one it dropped from one another link contributed.
    """
    for edge in sorted(set(mine) | set(theirs)):
        if edge not in theirs:
            die("the map has edge %d as %s %s, and AFL++ documented no such "
                "%s there" % (edge, what, mine[edge], what))
        if edge not in mine:
            if not reverse:
                continue
            die("AFL++ documented edge %d as %s %s, and the map names nothing "
                "reaching it" % (edge, what, theirs[edge]))
        elif mine[edge] != theirs[edge]:
            die("edge %d is %s %s in the map and %s to AFL++"
                % (edge, what, mine[edge], theirs[edge]))


def main():
    if len(sys.argv) != 3:
        die("usage: bmap_vs_docids.py <bmap> <docids>")

    base, edges, my_dirs, my_cases, mentioned, selects = read_bmap(sys.argv[1])
    doc_dirs, doc_cases, documented, shared = read_docids(sys.argv[2])

    if not documented:
        die("%s documented no edge ids; the link did not run with "
            "AFL_LLVM_DOCUMENT_IDS" % sys.argv[2])
    if not my_dirs and not my_cases:
        die("%s describes no branch direction, so there is nothing here to "
            "check" % sys.argv[1])

    for edge in sorted(mentioned):
        if not base <= edge < edges:
            die("id %d is outside the range the header declares "
                "(base=%d edges=%d)" % (edge, base, edges))
        if edge not in documented and edge not in selects:
            die("the map mentions id %d, which AFL++ never numbered" % edge)

    # An id two links both claimed says nothing about either of them, so it is
    # dropped from the comparison rather than compared against whichever record
    # happened to come last.  It keeps its range check above.
    for d in (my_dirs, my_cases, doc_dirs, doc_cases):
        for edge in shared:
            d.pop(edge, None)

    compare("dir", my_dirs, doc_dirs, not shared)
    compare("case", my_cases, doc_cases, not shared)

    print("bmap_vs_docids: %d branch directions and %d switch cases agree with "
          "AFL++'s listing (%d select ids range-checked only%s)"
          % (len(my_dirs), len(my_cases), len(selects),
             "" if not shared else
             "; %d ids skipped, the listing outlived more than one link"
             % len(shared)))


if __name__ == "__main__":
    main()
