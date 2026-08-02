/*
  rgd::BranchMap -- which edge each side of a branch reaches, in the fuzzer's
  own numbering.

  TaintPass writes this file beside the instrumented binary
  (-taint-branch-map=, instrumentation/TaintPass.cpp), reading AFL++'s edge ids
  straight out of the module it is instrumenting:

      # symsan branch map v1 base=<reserved> edges=<count>
      C <cid> <true edge> <false edge>      conditional branch
      X <cid> <true edge> <false edge>      select-lowered branch
      D <cid> <default edge>                switch, no case matched
      S <cid> <case value> <case edge>      switch, one line per case

  There is no join to perform.  Both arms of the build are derived from one
  AFL++-instrumented module, so a branch's cid *is* one of the edge ids around
  it, and all this file has to say is which edges are on which side.

  Its predecessor met AFL++'s AFL_LLVM_DOCUMENT_IDS output halfway by hashing
  source locations, and that cost precision which had nothing to do with the
  question being asked: clang gives every branch a macro or a && / || chain
  expands to the location of the expression it started from, so libpng's
  `isnonalpha(c)` -- four comparisons -- was four branches at pngerror.c:445:11,
  and one (cid, direction) resolved to a *list* of unrelated edges.  A cid taken
  from the module names one branch, so the answer here is one edge.

  -1 for a direction is an answer rather than a gap.  AFL++ numbers only the
  blocks its coverage needs, pruning any block that dominates all its successors
  or that post-dominates them with more than one predecessor -- the latter being
  the join an `if` with no `else` falls through to.  Reaching such a block is
  implied by reaching the branch at all, so there is no coverage to be had by
  flipping towards it, and lookup() says exactly that with kPruned instead of
  declining to answer.

  A case has only a true direction.  "Take this case" is a block; "do not take
  this case" is not one edge but everywhere else the switch could go, so that
  side stays unmapped and falls back to what this process has seen itself.

  (c) 2026 by Chengyu Song <csong@cs.ucr.edu>
  License: Apache 2.0
*/

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <unordered_map>

namespace rgd {

class BranchMap {
public:
  /// A direction AFL++ assigned no edge id to, because reaching the block
  /// behind it is already implied by coverage it does record.
  ///
  /// A real answer -- "this side is never interesting" -- and deliberately
  /// distinct from lookup() returning nullptr, which means the map has never
  /// heard of the branch and the caller should fall back to its own history.
  static const uint32_t kPruned = UINT32_MAX;

  /// Parse @p path.
  ///
  /// @return the number of (cid, direction) pairs read, or -1 if the file
  /// cannot be read.  Zero is not an error condition here but is certainly a
  /// symptom: it is what a map in some other format parses to.
  int load(const std::string &path);

  /// Which edge taking @p cid in @p direction reaches: an edge id, kPruned, or
  /// nullptr when this branch direction is not in the map at all.
  ///
  /// Not in the map means one of three things: a branch in code AFL++ never
  /// instrumented (an instrumented archive linked in separately, libc++ being
  /// the one every C++ target pulls in), one of SymSan's own checks, which is
  /// not an edge and holds an id below base(), or the false side of a switch
  /// case, which is not one edge.
  const uint32_t *lookup(uint32_t cid, bool direction) const {
    auto itr = targets_.find(key(cid, direction));
    return itr == targets_.end() ? nullptr : &itr->second;
  }

  /// How far AFL++'s numbering went in the module this map describes, from the
  /// `edges=` header -- which is also how big a coverage map has to be for
  /// every counter in the binary to have somewhere to land.  Zero if the file
  /// carried no header.
  uint32_t edges() const { return edges_; }

  /// The first id AFL++ was allowed to use, from the `base=` header
  /// (symsan::AFL_ID_BASE).  Ids below it name SymSan's own branches -- a UB
  /// check, a bounds check, a libc-wrapper size constraint -- which exist only
  /// in the instrumented build and appear in no coverage map.
  uint32_t base() const { return base_; }

  /// Number of (cid, direction) pairs known.
  size_t size() const { return targets_.size(); }
  /// Lines naming an edge at or beyond edges(), which a coverage map of the
  /// size the header asks for cannot index.  Expected to be zero: the same pass
  /// wrote both numbers.  Anything else means the map and the binary it
  /// describes have come apart, so those lines are left out rather than
  /// answered with an index nobody can use.
  size_t dropped() const { return dropped_; }
  /// Lines that did not parse -- an unknown record type, or too few fields.
  size_t skipped() const { return skipped_; }
  bool empty() const { return targets_.empty(); }

private:
  static uint64_t key(uint32_t cid, bool direction) {
    return ((uint64_t)cid << 1) | (direction ? 1u : 0u);
  }

  std::unordered_map<uint64_t, uint32_t> targets_;
  uint32_t base_ = 0;
  uint32_t edges_ = 0;
  size_t dropped_ = 0;
  size_t skipped_ = 0;
};

} // namespace rgd
