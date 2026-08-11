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

/// How many edge ids are held back at the bottom of the coverage map for
/// SymSan's own use.
///
/// Not every branch SymSan solves is an edge the fuzzer numbered: a UB check, a
/// bounds check or a libc-wrapper size constraint is a decision point that
/// exists only in the instrumented build, and it still needs an id that cannot
/// be mistaken for a real edge.  Those ids are `enum undefined_check_ids` in
/// runtime/dfsan/dfsan.h, passed to __taint_trace_cond by the runtime itself
/// rather than assigned by the pass, and they run 1..16.  The build hands this
/// number to AFL++ as AFL_LLVM_LTO_STARTID so that its own numbering starts
/// above the range, which makes "cid < AFL_ID_BASE" a complete test for "this is
/// not an edge" -- answerable without knowing how many edges the target happens
/// to have.
///
/// The cost of holding ids back is one map byte each, so the number is chosen
/// to be comfortably more than any target will need rather than tight.
///
/// This covers the undefined_check_ids and nothing else.  It does *not* cover a
/// branch in code AFL++ never instrumented -- a separately-linked instrumented
/// archive, libc++ being the one every C++ target pulls in -- which keeps a
/// branch_cid() source hash and so can collide with a real edge id by chance.
/// See the TODO on Taint::getBranchId() in instrumentation/TaintPass.cpp.
static const uint32_t AFL_ID_BASE = 4096;

/// Does @p cid name a check the runtime raised rather than a branch in the
/// program?
///
/// The reserved range above is what makes this answerable, and the answer
/// changes how the check is treated: it has no edge behind either direction for
/// the fuzzer's coverage to have covered, so it is not a coverage question at
/// all -- see ConcolicSession::on_cond().
///
/// One-sided, and deliberately so.  In a build AFL++ never numbered every cid
/// is a branch_cid() source hash, uniform over 2^32, so one in a million lands
/// in the range and gets treated as a runtime check: it is then always solved
/// and never nested, which costs a little work and loses nothing.  The converse
/// error -- a runtime check mistaken for an edge -- cannot happen, which is the
/// direction that matters, because that one would look the branch up in the
/// coverage map and act on someone else's answer.
inline bool is_runtime_check_id(uint32_t cid) { return cid < AFL_ID_BASE; }

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

/// The identity of one case of a switch: the switch's own id, continued over
/// the case value.
///
/// A case has no source location either side can name it by.  SymSan's
/// instrumentation only ever holds the SwitchInst, whose debug location belongs
/// to the switch as a whole, and AFL++ only holds the case's destination block,
/// whose location is the case *body* rather than the label.  What both do have
/// is the switch's location and the case's constant value, so that pair is the
/// key.
///
/// @p case_value is the value zero-extended (or truncated) to 64 bits, which is
/// what TaintFunction::visitSwitchInst already passes to the runtime; the AFL++
/// side has to normalise the same way or the two hashes will not meet.
///
/// Spelled with the bytes taken out one at a time rather than by hashing the
/// object representation, so that the id does not depend on the host's byte
/// order -- and with no std::string, so that the taint runtime can compute it
/// too.
inline uint32_t switch_case_cid(uint32_t switch_cid, uint64_t case_value) {
  uint32_t h = switch_cid;
  for (unsigned i = 0; i < 8; ++i)
    h = (h << 5) + h + (unsigned char)((case_value >> (i * 8)) & 0xff);
  return h;
}

} // namespace symsan
