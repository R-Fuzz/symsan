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

  Both directions of the relation are many-to-one: inlining duplicates a source
  branch into N copies, each with its own edge id, so one (cid, direction) maps
  to a *list*.

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
  size_t dropped_ = 0;
  size_t skipped_ = 0;
};

} // namespace rgd
