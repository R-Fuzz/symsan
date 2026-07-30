// Pins symsan::djb_hash() to llvm::djbHash(), and branch_cid()'s key format.
//
// This is a *host* test: it links neither the runtime nor LLVM, it just checks
// arithmetic, so it is compiled with a plain clang++ rather than %ko-clangxx.
//
// RUN: clang++ -std=c++17 -Wall -Werror -I%S/../../include %s -o %t
// RUN: %t

#include "branch_id.h"

#include <cstdio>
#include <string>

// llvm::djbHash() of the same strings, obtained by linking LLVMSupport and
// calling it -- which is exactly what this file exists to make unnecessary.
//
// The two must agree because instrumentation/TaintPass.cpp used llvm::djbHash
// for branch ids before include/branch_id.h existed; keeping the values
// identical means the change of hash *implementation* is not also a change of
// hash *value*, so only the deliberate change of key (the debug location's own
// filename, rather than the module's source name) moved the ids.
static const struct {
  const char *s;
  uint32_t h;
} kDjbCases[] = {
    {"", 5381u},
    {"a", 177670u},
    {"branch.c:21:7", 2808166290u},
    {"/a b/c:d.c:1:1", 21230318u},
    {"tests/data/branch.c:12:9", 2881322655u},
    {"\xff\xfe\x01", 193663075u},
};

// branch_cid() == djb_hash("<file>:<line>:<col>").  Pinned separately because
// the *format* of that key is the actual contract with AFL++: the loader in
// driver/session/branch-map.cpp reassembles it from a "src=" field that a
// patched AFL++ writes as file, ':', line, ':', col.  Change the separator or
// the order on one side and the join silently produces nothing.
static const struct {
  const char *file;
  unsigned line;
  unsigned col;
  uint32_t cid;
} kCidCases[] = {
    {"branch.c", 21, 7, 2808166290u},
    {"", 0, 0, 2088612185u},
    {"/tmp/x.c", 4294967295u, 4294967295u, 3305086563u},
};

// switch_case_cid() == the switch's cid continued over the eight little-endian
// bytes of the case value.  Pinned for the same reason branch_cid() is: it is a
// contract with AFL++, which computes it from a "case=" field written next to
// the switch's "src=".  The last three rows are the ids an actual build emitted
// for a switch at sw.c:18:3 (cid 3635955024) with those three case labels, and
// are the ones AFL++'s exported map has to reproduce.
static const struct {
  uint32_t switch_cid;
  uint64_t value;
  uint32_t cid;
} kSwitchCaseCases[] = {
    {2808166290u, 0ull, 2745215378u},
    {2808166290u, 7ull, 426605497u},
    {2808166290u, 0xdeadbeefull, 4195169162u},
    {2808166290u, 0xffffffffffffffffull, 199249418u},
    {5381u, 1ull, 1744117478u},
    {3635955024u, 0xdeadbeefull, 1484595016u},
    {3635955024u, 0x12345678ull, 395231588u},
    {3635955024u, 7ull, 2010998647u},
};

int main() {
  int failures = 0;

  for (auto const &c : kDjbCases) {
    uint32_t got = symsan::djb_hash(std::string(c.s));
    if (got != c.h) {
      fprintf(stderr, "djb_hash(\"%s\") = %u, want %u\n", c.s, got, c.h);
      failures += 1;
    }
  }

  for (auto const &c : kCidCases) {
    uint32_t got = symsan::branch_cid(c.file, c.line, c.col);
    if (got != c.cid) {
      fprintf(stderr, "branch_cid(\"%s\", %u, %u) = %u, want %u\n", c.file,
              c.line, c.col, got, c.cid);
      failures += 1;
    }
    // ...and that it really is the hash of that one string, so a future
    // "optimization" that stops building the key cannot pass by accident.
    std::string key = std::string(c.file) + ":" + std::to_string(c.line) + ":" +
                      std::to_string(c.col);
    if (got != symsan::djb_hash(key)) {
      fprintf(stderr, "branch_cid(\"%s\", %u, %u) is not djb_hash(\"%s\")\n",
              c.file, c.line, c.col, key.c_str());
      failures += 1;
    }
  }

  for (auto const &c : kSwitchCaseCases) {
    uint32_t got = symsan::switch_case_cid(c.switch_cid, c.value);
    if (got != c.cid) {
      fprintf(stderr, "switch_case_cid(%u, %llu) = %u, want %u\n", c.switch_cid,
              (unsigned long long)c.value, got, c.cid);
      failures += 1;
    }
    // A case id is not the switch's own id.  This is what went wrong before
    // switch cases had ids of their own: every case reached the solver as the
    // switch, so no case could be named.  The kind=switch line stays in the
    // exported id table, so the two must stay distinguishable.
    if (got == c.switch_cid) {
      fprintf(stderr, "switch_case_cid(%u, %llu) collided with the switch\n",
              c.switch_cid, (unsigned long long)c.value);
      failures += 1;
    }
  }

  // Distinct cases of one switch are distinct branches.  A hash cannot promise
  // that in general, but it must hold for the small values real switch labels
  // are made of, and the whole scheme is pointless if it does not.
  {
    const uint32_t kSwitch = 2808166290u;
    uint32_t seen[512];
    for (unsigned i = 0; i < 512; ++i) seen[i] = symsan::switch_case_cid(kSwitch, i);
    for (unsigned i = 0; i < 512; ++i)
      for (unsigned j = i + 1; j < 512; ++j)
        if (seen[i] == seen[j]) {
          fprintf(stderr, "cases %u and %u of one switch share id %u\n", i, j,
                  seen[i]);
          failures += 1;
        }
  }

  // Every byte of the value is hashed, all eight of them.  Truncating to 32
  // bits on one side and not the other would still pass every case above,
  // since none of those pinned values needs the high word.
  for (unsigned i = 0; i < 8; ++i) {
    uint64_t v = (uint64_t)1 << (i * 8);
    if (symsan::switch_case_cid(1u, v) == symsan::switch_case_cid(1u, 0)) {
      fprintf(stderr, "byte %u of the case value does not reach the id\n", i);
      failures += 1;
    }
  }

  // Different switches, same case value: still different branches.
  if (symsan::switch_case_cid(1u, 7) == symsan::switch_case_cid(2u, 7)) {
    fprintf(stderr, "case 7 of two different switches has one id\n");
    failures += 1;
  }

  // The two overloads must not disagree about where a string ends.
  const char embedded[] = "ab\0cd";
  if (symsan::djb_hash(embedded, sizeof(embedded) - 1) ==
      symsan::djb_hash(std::string("ab"))) {
    fprintf(stderr, "djb_hash(ptr, n) stopped at an embedded NUL\n");
    failures += 1;
  }

  if (failures) {
    fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
  }
  printf("ok\n");
  return 0;
}
