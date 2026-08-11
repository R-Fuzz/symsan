/*
  rgd::BranchMap -- parse TaintPass's -taint-branch-map output.

  (c) 2026 by Chengyu Song <csong@cs.ucr.edu>
  License: Apache 2.0
*/

#include "branch_map.h"

#include "branch_id.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fstream>

namespace {

/// Value of the whitespace-separated " <name>=" field in @p line, or an empty
/// string if absent.  Only the header has named fields, and it opens with a
/// comment marker, so the leading space is always there.
std::string field(const std::string &line, const char *name) {
  std::string needle = std::string(" ") + name + "=";
  size_t pos = line.find(needle);
  if (pos == std::string::npos) return std::string();
  size_t start = pos + needle.size();
  size_t end = line.find(' ', start);
  return line.substr(start, end == std::string::npos ? end : end - start);
}

} // namespace

namespace rgd {

int BranchMap::load(const std::string &path) {
  std::ifstream in(path);
  if (!in.is_open()) {
    fprintf(stderr, "[symsan] cannot open branch map %s: %s\n", path.c_str(),
            strerror(errno));
    return -1;
  }

  targets_.clear();
  base_ = 0;
  edges_ = 0;
  dropped_ = 0;
  skipped_ = 0;

  // An edge field as the writer spells it: a decimal id, or -1 for a direction
  // AFL++ pruned.  Signed on the way in so that -1 arrives as itself rather
  // than as a very large unsigned number that happens to equal kPruned.
  auto store = [this](uint32_t cid, bool direction, long long edge) {
    if (edge < 0) {
      targets_[key(cid, direction)] = kPruned;
      return;
    }
    // Only checkable once the header has been seen; every line after it is,
    // since the writer emits the header first.
    if (edges_ != 0 && (unsigned long long)edge >= edges_) {
      dropped_ += 1;
      return;
    }
    targets_[key(cid, direction)] = (uint32_t)edge;
  };

  std::string line;
  while (std::getline(in, line)) {
    if (line.empty()) continue;

    if (line[0] == '#') {
      // The one header, or a comment.  Absent fields leave the accessors at
      // zero, which reads as "unknown" everywhere they are consulted.
      std::string b = field(line, "base");
      std::string e = field(line, "edges");
      if (!b.empty()) base_ = (uint32_t)strtoul(b.c_str(), nullptr, 10);
      if (!e.empty()) edges_ = (uint32_t)strtoul(e.c_str(), nullptr, 10);
      continue;
    }

    // Fixed-shape records, so read them by shape.  The record type is the first
    // character and everything after it is numbers.
    const char *rest = line.c_str() + 1;
    unsigned long cid = 0;
    long long t = 0, f = 0;
    unsigned long long value = 0;

    switch (line[0]) {
      // A conditional branch, and a select AFL++ lowered to a pair of ids.
      // Both sides of both, since either can be the one worth flipping to.
      case 'C':
      case 'X':
        if (sscanf(rest, "%lu %lld %lld", &cid, &t, &f) != 3) {
          skipped_ += 1;
          break;
        }
        store((uint32_t)cid, true, t);
        store((uint32_t)cid, false, f);
        break;

      // Where a switch goes when no case matched.  Filed under the switch's own
      // cid with direction false, since "no case matched" is the one thing the
      // switch as a whole can be false about -- every case comparison failing.
      // Nothing asks for it yet: the runtime traces a switch as one comparison
      // per case (TaintFunction::visitSwitchInst), so the ids that reach the
      // backend are case ids.  It is kept because it is what the file says and
      // because solving a taken case to false is a question about this edge.
      case 'D':
        if (sscanf(rest, "%lu %lld", &cid, &t) != 2) {
          skipped_ += 1;
          break;
        }
        store((uint32_t)cid, false, t);
        break;

      // One case of a switch.  The line carries the switch's cid and the case
      // value, and the runtime names the case by mixing exactly those two --
      // see symsan::switch_case_cid in include/branch_id.h -- so mixing them
      // the same way here is what makes the two meet.  Two cases sharing a
      // destination block share an edge id and get one line each, which is
      // right: either of them reaching it is the same edge.
      //
      // True only.  "Do not take this case" is not one edge but everywhere else
      // the switch could go, so that direction is left unmapped.
      case 'S':
        if (sscanf(rest, "%lu %llu %lld", &cid, &value, &t) != 3) {
          skipped_ += 1;
          break;
        }
        store(symsan::switch_case_cid((uint32_t)cid, value), true, t);
        break;

      default:
        skipped_ += 1;
        break;
    }
  }

  return (int)targets_.size();
}

} // namespace rgd
