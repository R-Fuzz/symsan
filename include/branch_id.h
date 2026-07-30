#pragma once

/*
  The branch identity shared between SymSan's instrumentation and whatever
  coverage instrumentation the fuzzer uses.

  SymSan names a conditional branch by hashing its source location; AFL++ names
  the same branch by a sequential edge id assigned at link time.  Neither can
  use the other's knowledge unless there is a key both sides can compute, and
  the only such key is the source location.  This header is that key, kept in
  one place so the pass that bakes the id into the binary and the loader that
  reads AFL++'s exported id map cannot drift apart.

  See patches/aflpp-document-ids.patch for the AFL++ side.
*/

#include <stddef.h>
#include <stdint.h>

#include <string>

namespace symsan {

/// Daniel J. Bernstein's string hash -- byte for byte what llvm::djbHash()
/// does.  Reimplemented rather than #include'd from "llvm/Support/DJB.h" so
/// that the driver can compute a branch id without linking LLVM's support
/// library; tests/symsan/branch_id.cpp pins the two together.
inline uint32_t djb_hash(const char *s, size_t n) {
  uint32_t h = 5381;
  for (size_t i = 0; i < n; ++i)
    h = (h << 5) + h + (unsigned char)s[i];
  return h;
}

inline uint32_t djb_hash(const std::string &s) {
  return djb_hash(s.data(), s.size());
}

/// The identity of a branch: where its source text lives.
///
/// Keyed on the debug location's own file rather than the enclosing module's,
/// which makes it invariant under inlining -- a branch inlined from a header,
/// or under LTO from another translation unit, keeps the id it had where it was
/// written.  That invariance is the whole point: SymSan instruments per
/// translation unit and AFL++'s LTO pass instruments the merged module, so an
/// id that depended on the enclosing module would disagree wherever the
/// inliner had been.
inline uint32_t branch_cid(const std::string &file, unsigned line,
                           unsigned col) {
  std::string key = file;
  key += ":" + std::to_string(line) + ":" + std::to_string(col);
  return djb_hash(key);
}

} // namespace symsan
