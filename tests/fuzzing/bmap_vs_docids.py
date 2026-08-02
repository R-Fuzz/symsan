#!/usr/bin/env python3
"""Cross-check a TaintPass branch map against AFL++'s own id listing.

Usage: bmap_vs_docids.py <target.bmap> <docids.txt>

Both come out of the *same* afl-clang-lto link -- the `.bmap` from TaintPass
running on `<out>.0.5.precodegen.bc`, the listing from AFL_LLVM_DOCUMENT_IDS --
so they are two independent readings of one numbering and have to agree
exactly.  covcheck already checks the map against what a run actually walks;
this checks it against what the *compiler* recorded, which catches a map that
is wrong in a way no single input happens to execute.

AFL++ writes one line per numbered block, and how much it says about a block is
what decides how much can be checked:

    edgeID=N dir=D src=...            a branch direction  -> map `C` line
    edgeID=N dir=1 case=V src=...     a switch case       -> map `S` line
    edgeID=N                          everything else: the block behind a
                                      switch default, a select's two ids

The first two are required to agree in both directions, keyed on the edge id
because that is what is unique -- two switches in one module can share a case
value.  The third can only be checked one way, since a bare id says nothing
about which of the map's lines, if any, should be reaching it.
"""

import re
import sys


def die(msg):
    print("bmap_vs_docids: " + msg, file=sys.stderr)
    sys.exit(1)


def read_bmap(path):
    """-> (base, edges, {edge: dir}, {edge: case value}, {every id mentioned})"""
    base = edges = None
    dirs, cases, mentioned = {}, {}, set()

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
                mentioned.update([cid] + [e for e in (t, f_) if e != -1])
                # A select's ids are not branch directions to AFL++ and carry no
                # dir=, so only C lines go in for the two-way check.
                if kind == "C":
                    for edge, direction in ((t, 1), (f_, 0)):
                        if edge != -1:
                            claim(dirs, edge, "dir", direction)
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
    return base, edges, dirs, cases, mentioned


def read_docids(path):
    """-> ({edge: dir}, {edge: case value}, {every edge documented})"""
    dirs, cases, seen = {}, {}, set()
    with open(path) as f:
        for line in f:
            m = re.search(r"edgeID=(\d+)", line)
            if not m:
                continue
            edge = int(m.group(1))
            seen.add(edge)
            d = re.search(r"\bdir=([01])\b", line)
            c = re.search(r"\bcase=(\d+)\b", line)
            if c:
                cases[edge] = int(c.group(1))
            elif d:
                dirs[edge] = int(d.group(1))
    return dirs, cases, seen


def compare(what, mine, theirs):
    for edge in sorted(set(mine) | set(theirs)):
        if edge not in theirs:
            die("the map has edge %d as %s %s, and AFL++ documented no such "
                "%s there" % (edge, what, mine[edge], what))
        if edge not in mine:
            die("AFL++ documented edge %d as %s %s, and the map names nothing "
                "reaching it" % (edge, what, theirs[edge]))
        if mine[edge] != theirs[edge]:
            die("edge %d is %s %s in the map and %s to AFL++"
                % (edge, what, mine[edge], theirs[edge]))


def main():
    if len(sys.argv) != 3:
        die("usage: bmap_vs_docids.py <bmap> <docids>")

    base, edges, my_dirs, my_cases, mentioned = read_bmap(sys.argv[1])
    doc_dirs, doc_cases, documented = read_docids(sys.argv[2])

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
        if edge not in documented:
            die("the map mentions id %d, which AFL++ never numbered" % edge)

    compare("dir", my_dirs, doc_dirs)
    compare("case", my_cases, doc_cases)

    print("bmap_vs_docids: %d branch directions and %d switch cases agree with "
          "AFL++'s listing" % (len(my_dirs), len(my_cases)))


if __name__ == "__main__":
    main()
