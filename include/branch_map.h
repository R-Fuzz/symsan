/*
  rgd::BranchMap -- the join between SymSan's branch ids and the fuzzer's edge
  ids.

  A patched AFL++ (see patches/aflpp-document-ids.patch) writes one line per
  instrumented edge when AFL_LLVM_DOCUMENT_IDS is set:

      ModuleID=<n> Function=<name> edgeID=<n> dir=<0|1> src=<file>:<line>:<col>

  and, for a switch case block, one line per case value landing there:

      ModuleID=<n> Function=<name> edgeID=<n> dir=1 case=<v> src=<switch loc>

  The src/dir fields are present only for edges that come out of a conditional
  branch or a switch, which is exactly the set SymSan also names.  Hashing src
  with symsan::branch_cid() (include/branch_id.h) -- then, for a case, mixing in
  the value with symsan::switch_case_cid() -- gives the same number SymSan's
  instrumentation baked into the binary, so the two toolchains end up talking
  about the same branch without either having to know about the other.

  Both directions of the relation are many-to-one, so one (cid, direction) maps
  to a *list*, for two different reasons.  Inlining duplicates a source branch
  into N copies, each with its own edge id.  And a single source location can
  hold several *distinct* branches: clang gives every branch a macro expands to,
  and every && / || short circuit, the location of the expression it started
  from, so libpng's `isnonalpha(c)` -- four comparisons -- is four branches at
  pngerror.c:445:11.  The second is the common one; on a -O0 build, where
  nothing is inlined, it is the only one.  Both are handled the same way here,
  but they are not equally benign: for a group of unrelated branches, "the
  fuzzer covered one of these edges" no longer implies anything about the branch
  we are asking about, so callers should err towards doing the work.

  A case has only a dir=1 entry.  "Take this case" is a block; "do not take this
  case" is not one edge but everywhere else the switch could go, so that side
  stays unmapped and falls back to what this process has seen itself.

  (c) 2026 by Chengyu Song <csong@cs.ucr.edu>
  License: Apache 2.0
*/

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <unordered_map>
#include <vector>

namespace rgd {

class BranchMap {
public:
  /// Also remember each entry's source location, so a validation failure can
  /// name the branch instead of only a hash of it.  Call before load().
  ///
  /// Off by default: the strings cost several times what the ids they annotate
  /// do, and nothing in the fuzzing loop reads them -- lookup() answers with
  /// edge ids.  Only validate() needs to be able to say *which* branch.
  void keep_sources(bool on) { keep_sources_ = on; }

  /// Parse @p path.  Edge ids at or beyond @p map_size cannot index the
  /// fuzzer's coverage map and are counted in dropped() rather than stored;
  /// pass 0 to keep everything.
  ///
  /// @return the number of usable entries, or -1 if the file cannot be read
  int load(const std::string &path, size_t map_size);

  /// The edge ids for one side of a branch, or nullptr if this branch
  /// direction has no id -- either because the two builds disagree about the
  /// source location, or because AFL++ pruned the block (see
  /// shouldInstrumentBlock() in its LTO pass: a block that dominates all its
  /// successors carries no counter of its own).
  const std::vector<uint32_t> *lookup(uint32_t cid, bool direction) const {
    auto itr = edges_.find(key(cid, direction));
    return itr == edges_.end() ? nullptr : &itr->second;
  }

  /// Where a (cid, direction) came from, or nullptr -- unknown to the map, or
  /// keep_sources() was not set.  One location per key even when the key holds
  /// several edge ids: they share a location by construction, whether they are
  /// inlined copies of one branch or siblings out of one macro expansion.
  const std::string *source(uint32_t cid, bool direction) const {
    auto itr = srcs_.find(key(cid, direction));
    return itr == srcs_.end() ? nullptr : &itr->second;
  }

  /// Number of (cid, direction) pairs known.
  size_t size() const { return edges_.size(); }
  /// Lines skipped because their edge id was out of range.
  size_t dropped() const { return dropped_; }
  /// Lines carrying no src=/dir= fields -- unconditional edges, function
  /// entries, and anything compiled without -g.
  size_t skipped() const { return skipped_; }
  bool empty() const { return edges_.empty(); }

private:
  static uint64_t key(uint32_t cid, bool direction) {
    return ((uint64_t)cid << 1) | (direction ? 1u : 0u);
  }

  std::unordered_map<uint64_t, std::vector<uint32_t>> edges_;
  /// Same keys as edges_, but only when keep_sources() was set.
  std::unordered_map<uint64_t, std::string> srcs_;
  bool keep_sources_ = false;
  size_t dropped_ = 0;
  size_t skipped_ = 0;
};

} // namespace rgd
