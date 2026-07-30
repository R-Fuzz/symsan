/*
  rgd::BranchMap -- parse AFL++'s AFL_LLVM_DOCUMENT_IDS output.

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
/// string if absent.  Every field we want (edgeID, dir, case) is preceded by
/// ModuleID, so the leading space is always there.  Not usable for src=, whose
/// value deliberately runs to the end of the line.
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

int BranchMap::load(const std::string &path, size_t map_size) {
  std::ifstream in(path);
  if (!in.is_open()) {
    fprintf(stderr, "[symsan] cannot open branch map %s: %s\n", path.c_str(),
            strerror(errno));
    return -1;
  }

  edges_.clear();
  dropped_ = 0;
  skipped_ = 0;

  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;

    // src= is emitted last precisely because a path may contain spaces and
    // colons, so take everything after it and split the two numbers off the
    // right rather than tokenising from the left.
    size_t src_pos = line.find(" src=");
    if (src_pos == std::string::npos) {
      skipped_ += 1;
      continue;
    }
    std::string src = line.substr(src_pos + 5);

    size_t col_sep = src.rfind(':');
    if (col_sep == std::string::npos || col_sep == 0) { skipped_ += 1; continue; }
    size_t line_sep = src.rfind(':', col_sep - 1);
    if (line_sep == std::string::npos) { skipped_ += 1; continue; }

    std::string file = src.substr(0, line_sep);
    unsigned lineno = (unsigned)strtoul(src.c_str() + line_sep + 1, nullptr, 10);
    unsigned col = (unsigned)strtoul(src.c_str() + col_sep + 1, nullptr, 10);

    std::string dir = field(line, "dir");
    std::string edge = field(line, "edgeID");
    if (dir.empty() || edge.empty()) { skipped_ += 1; continue; }

    unsigned long edge_id = strtoul(edge.c_str(), nullptr, 10);
    if (map_size != 0 && edge_id >= map_size) {
      dropped_ += 1;
      continue;
    }

    // A switch case block carries the switch's src= plus the case value, since
    // the location alone names the switch rather than the case; see
    // symsan::switch_case_cid.  Two cases that share a destination block share
    // an edge id, and AFL++ writes one line per value, so this can add the same
    // id under two keys -- which is right: either case reaching it is the same
    // edge.
    uint32_t cid = symsan::branch_cid(file, lineno, col);
    std::string case_value = field(line, "case");
    if (!case_value.empty()) {
      cid = symsan::switch_case_cid(
          cid, strtoull(case_value.c_str(), nullptr, 10));
    }
    edges_[key(cid, dir != "0")].push_back((uint32_t)edge_id);
  }

  return (int)edges_.size();
}

} // namespace rgd
