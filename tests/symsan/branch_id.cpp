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
