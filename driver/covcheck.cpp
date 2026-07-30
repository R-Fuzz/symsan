// Offline check that SymSan and the fuzzer name the same branches.
//
// SymSan calls a branch by a hash of its source location; AFL++ calls an edge
// by a sequential integer.  A BranchMap (patches/aflpp-document-ids.patch, then
// include/branch_map.h) joins the two, and SharedMapCovManager uses the join to
// skip branches the fuzzer already covered.  The mapped/unmapped counters say
// how *much* of that join lands -- but a map that resolved every branch to the
// wrong edge would report a perfect ratio while silently suppressing every
// solve.  Nothing in the fuzzing loop would notice; it would just find less.
//
// This driver is what notices.  Give it ground truth -- the edge ids the
// fuzzer's own build recorded for one input, i.e. an afl-showmap run -- and it
// traces the same input through the SymSan build and checks that every branch
// direction the trace took resolves to an edge afl-showmap saw.
//
// Usage: covcheck -m <branch.map> -c <showmap.out> -i <input> -- <target> [args]
//
// Any target argument spelled @@ is replaced by the staged input path, exactly
// as in AFL++; with no @@ the target reads the input on stdin.
//
// Exit status is 0 when nothing contradicted the map, 1 when something did, and
// 2 for a usage or setup error -- so it can be a test.
//
// (c) 2026 by Chengyu Song <csong@cs.ucr.edu>
// License: Apache 2.0

#include "concolic.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>
#include <vector>

namespace {

void usage(const char *argv0) {
  fprintf(stderr,
          "usage: %s -m <branch.map> -c <covered> -i <input> [-f <staged>] "
          "[-d] -- <target> [args...]\n"
          "  -m  AFL_LLVM_DOCUMENT_IDS output from the fuzzer's build\n"
          "  -c  edge ids the fuzzer's build covered for this input\n"
          "      (afl-showmap's default '%%06u:%%u' output, or bare integers)\n"
          "  -i  the input to trace\n"
          "  -f  where to stage the input for the target; must match the path\n"
          "      the target reads if it does not take @@ (default: a temporary\n"
          "      file, removed on exit)\n"
          "  -d  verbose session output\n",
          argv0);
}

/// Read a whole file. @return false and complain on failure.
bool read_file(const char *path, std::vector<uint8_t> *out) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    fprintf(stderr, "covcheck: cannot open %s: %s\n", path, strerror(errno));
    return false;
  }
  uint8_t buf[4096];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) out->insert(out->end(), buf, buf + n);
  bool ok = !ferror(f);
  if (!ok) fprintf(stderr, "covcheck: error reading %s\n", path);
  fclose(f);
  return ok;
}

/// Parse afl-showmap's default output: one "<edge id>:<hit count>" per line.
///
/// Bare integers are accepted too, so a hand-written expectation file works.
/// Base 10 explicitly: showmap zero-pads to six digits, and base 0 would read
/// those as octal.
bool read_covered(const char *path, std::vector<uint32_t> *out) {
  FILE *f = fopen(path, "r");
  if (!f) {
    fprintf(stderr, "covcheck: cannot open %s: %s\n", path, strerror(errno));
    return false;
  }
  char line[256];
  while (fgets(line, sizeof(line), f)) {
    char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '\0' || *p == '\n' || *p == '#') continue;
    char *end = nullptr;
    unsigned long id = strtoul(p, &end, 10);
    if (end == p) {
      fprintf(stderr, "covcheck: cannot parse '%s' in %s\n", p, path);
      fclose(f);
      return false;
    }
    out->push_back((uint32_t)id);
  }
  fclose(f);
  return true;
}

} // namespace

int main(int argc, char **argv) {
  const char *map_path = nullptr;
  const char *covered_path = nullptr;
  const char *input_path = nullptr;
  const char *staged_path = nullptr;
  bool debug = false;

  int opt;
  while ((opt = getopt(argc, argv, "m:c:i:f:dh")) != -1) {
    switch (opt) {
      case 'm': map_path = optarg; break;
      case 'c': covered_path = optarg; break;
      case 'i': input_path = optarg; break;
      case 'f': staged_path = optarg; break;
      case 'd': debug = true; break;
      default: usage(argv[0]); return 2;
    }
  }
  if (!map_path || !covered_path || !input_path || optind >= argc) {
    usage(argv[0]);
    return 2;
  }

  std::vector<uint8_t> input;
  std::vector<uint32_t> covered;
  if (!read_file(input_path, &input)) return 2;
  if (!read_covered(covered_path, &covered)) return 2;

  // A temporary of our own unless told otherwise, because the target has to
  // read the bytes the session wrote and not the ones the caller passed in --
  // they are the same here, but the session owns that file and truncates it.
  std::string staged;
  bool staged_is_temp = false;
  if (staged_path) {
    staged = staged_path;
  } else {
    staged = "/tmp/covcheck-" + std::to_string((long)getpid()) + ".input";
    staged_is_temp = true;
  }

  rgd::ConcolicConfig config;
  // The environment first, so SYMSAN_USE_JIGSAW and friends still work, then
  // our own arguments on top.  from_env() insists on SYMSAN_TARGET, which here
  // is positional instead, so hand it the one we were given rather than make
  // every caller set the same path twice.
  setenv("SYMSAN_TARGET", argv[optind], 1);
  config.from_env();
  config.symsan_bin = argv[optind];
  config.input_file = staged;
  config.branch_map = map_path;
  config.validate_coverage = true;
  config.debug = debug;
  config.use_stdin = true;
  for (int i = optind; i < argc; ++i) {
    if (strcmp(argv[i], "@@") == 0) {
      config.args.push_back(staged);
      config.use_stdin = false;
    } else {
      config.args.push_back(argv[i]);
    }
  }

  rgd::ConcolicSession session;
  if (session.init(config) != 0) {
    fprintf(stderr, "covcheck: failed to initialize the session\n");
    if (staged_is_temp) unlink(staged.c_str());
    return 2;
  }

  int rc = 2;
  if (session.trace(input.data(), input.size()) < 0) {
    fprintf(stderr, "covcheck: failed to trace %s\n", input_path);
  } else {
    rgd::JoinReport r;
    if (session.check_coverage(covered.data(), covered.size(), &r) != 0) {
      // The map failed to load, most likely: init() only warns about that,
      // because for the fuzzing loop it is a lost opportunity rather than an
      // error.  Here it is the whole point.
      fprintf(stderr, "covcheck: no branch map in use; is %s loadable?\n",
              map_path);
    } else {
      printf("covered edges: %zu\n", covered.size());
      printf("executed: %zu\n", r.executed);
      printf("checked: %zu\n", r.checked);
      printf("violations: %zu\n", r.violations);
      printf("ambiguous: %zu\n", r.ambiguous);
      printf("ambiguous-violations: %zu\n", r.ambiguous_violations);
      printf("unmapped: %zu\n", r.unmapped);
      // Say the verdict in one line as well, so a test can check for it
      // without having to know which counters are allowed to be non-zero.
      bool consistent = r.violations == 0 && r.ambiguous_violations == 0;
      printf("verdict: %s\n", consistent ? "consistent" : "INCONSISTENT");
      rc = consistent ? 0 : 1;
    }
  }

  if (staged_is_temp) unlink(staged.c_str());
  return rc;
}
