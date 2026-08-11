// Corpus-sweep apparatus shared by the standalone drivers.
//
// Both fgtest (the in-process z3 stack) and afltest (the RGD stack the fuzzer
// actually runs) want to answer the same question -- "which branches does the
// parser refuse on this target, and why" -- over a whole corpus.  They parse
// with different parsers, but the counting, the bucketing and the report are
// the same, and they have to *stay* the same or an RGD-vs-z3 comparison on one
// corpus is not readable side by side.  So they live here rather than being
// copied.
//
// Header-only and C++14: FGTest builds at 14 while AFLTest builds at 17, so
// nothing here may need 17.
//
// The parser side of this is ASTParser::last_error() (include/parse.h), which
// every rejection in both parsers now sets.  This is the half that reads it.

#ifndef SYMSAN_DRIVER_SWEEP_H
#define SYMSAN_DRIVER_SWEEP_H

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <map>
#include <string>
#include <utility>

namespace symsan {
namespace sweep {

// The per-condition log, and the join key it exists to write.
//
// Everything parse_stats counts is an aggregate: by reason, by call site, by
// branch cid.  None of those names a *condition*.  A cid is one branch executed
// thousands of times, a call site is coarser still, and two histograms that
// agree on totals can disagree about every single branch underneath them.  The
// key that does name one constraint is the pair **(input, label)**: the label
// is the runtime's index into this run's union table, so replaying the same
// seed through the same binary yields the same label for the same condition in
// whatever process is reading the trace.
//
// That is what makes an RGD-vs-z3 comparison a join instead of two tables side
// by side.  afltest and fgtest dump their outcome per (input, label); the pair
// says which conditions the two parsers disagree about and lets a claim like
// "if RGD folded it to a constant, z3 folded it too" be checked one condition
// at a time.  Reading it off PARSE-REASON counts cannot do that -- z3 folds ~9x
// more conditions than RGD on this corpus, and the totals alone leave open
// whether RGD's are a subset.
//
// The ordered label sequence per input is also the denominator check, and a
// much sharper one than matching conds=: if the two arms disagree about the
// n-th label, the two traces were not the same trace and nothing downstream is
// a comparison.  tools/cond-diff.py asserts that before it cross-tabulates.
//
// Off unless SYMSAN_DUMP_CONDS names a file: this is one line per condition,
// 4.5M of them on the libpng corpus.
inline FILE *&cond_log() {
  static FILE *f = nullptr;
  return f;
}

// @return false only if SYMSAN_DUMP_CONDS was set and the file would not open,
//   which the caller should treat as fatal -- a sweep that silently dumps
//   nothing is worse than one that refuses to start.  `tag` names the parser,
//   and goes in the file so two dumps cannot be mixed up later.
inline bool open_cond_log(const char *tag) {
  const char *path = getenv("SYMSAN_DUMP_CONDS");
  if (!path) return true;
  FILE *f = fopen(path, "w");
  if (!f) return false;
  fprintf(f, "# parser %s\n", tag);
  cond_log() = f;
  return true;
}

// Start a new input's section.  The name is the corpus path as the driver was
// given it; the join is by basename, since the two arms may be pointed at the
// same seeds through different paths.
inline void log_cond_input(const char *name) {
  if (cond_log()) fprintf(cond_log(), "I %s\n", name);
}

// A cond event carrying no condition (label 0, a loop exit).  Logged rather
// than skipped so that the two arms' line sequences line up event for event,
// which is what lets the sequence check above be an equality.
inline void log_cond_loop_exit() {
  if (cond_log()) fprintf(cond_log(), "L\n");
}

inline void close_cond_log() {
  if (cond_log()) { fclose(cond_log()); cond_log() = nullptr; }
}

struct parse_stats {
  // Trace events drained for this input, of every message type.  Not a parse
  // statistic, but it belongs in the same per-input block: without it a sweep
  // cannot tell "the parser accepted everything" from "the target traced
  // nothing", and #115 is an open bug where afltest reads zero events under a
  // concurrent lit run.  A sweep that could not see that would launder it into
  // a clean result.
  uint64_t events = 0;
  uint64_t conds = 0;         // cond messages seen
  uint64_t cond_tasks = 0;    // tasks the parser built from them
  uint64_t cond_ok = 0;       // parsed, at least one task
  uint64_t cond_empty = 0;    // parsed, no task -- a silent drop
  uint64_t cond_failed = 0;   // parse_cond returned -1
  // Clauses the parser handed out with a conjunct missing, i.e. tasks that are
  // weaker than the branch condition and whose solutions need not flip it.
  // Not a failure -- lenient mode does this on purpose (see construct_task) --
  // but it belongs next to ok/empty/failed, because these are counted in ok=
  // and a rise here is the difference between a solver that is missing and a
  // task that was never going to flip.  Filled by the caller from the parser's
  // own counter; the reason histogram cannot carry it, since note() only
  // buckets a parse that failed or produced nothing.
  uint64_t cond_weakened = 0;
  // Loop-exit notifications carrying no condition.  The runtime forwards a
  // cond message with label 0 when a loop leaves by a concrete test (see
  // __taint_trace_cond), because the backend wants to know the loop ended even
  // though there is nothing to solve.  Counting those as parse failures put
  // 38600 phantom "invalid label" rejections in the first sweep, all of them at
  // loop latches, so they get their own line rather than a reason bucket.
  uint64_t loop_exits = 0;
  uint64_t geps = 0;
  uint64_t gep_tasks = 0;
  uint64_t gep_ok = 0;
  uint64_t gep_empty = 0;
  uint64_t gep_failed = 0;
  // GEPs parse_gep declined on the strength of enum_index alone.  Its own line
  // rather than a reason bucket, because the answer is the same for every GEP
  // in the trace and it is our own argument coming back: with enum_gep=0 it is
  // simply the whole gep count, and the reason histogram would say nothing
  // except that we passed 0.  Kept as a count so that a run still reports how
  // many GEPs it walked past.
  uint64_t gep_skipped = 0;
  // Why a GEP was not enumerable, by the shape of what the runtime sent: the
  // parser needs either an array extent (num_elems) or a bounds label on the
  // pointer, and "neither" is a different problem from "the index would not
  // parse".  Indexed by (num_elems != 0) * 2 + (ptr_label != 0).
  uint64_t gep_shape[4] = {0, 0, 0, 0};
  // reason -> count, over both the -1 returns and the parsed-but-empty ones.
  // Ordered so that two runs of the sweep diff cleanly.
  std::map<std::string, uint64_t> reasons;
  // (call site, reason) -> count.  A whole-corpus reason histogram says what the
  // parser refuses but not where, and "where" is what decides whether a
  // rejection is a parser bug or a property of the target -- a mismatch under an
  // uninstrumented library looks exactly like one under a broken AST until the
  // address is symbolized.  The site is the runtime return address the trace
  // event carried; the binary is non-PIE, so addr2line resolves it directly.
  std::map<std::pair<uint64_t, std::string>, uint64_t> sites;
  // (branch cid, reason) -> count.  The same events as `sites`, keyed the other
  // way.  Under the two-stage build the cid *is* the AFL edge id, so this is
  // the key that joins a parse outcome to the fuzzer's coverage map, and hence
  // to which stage first covered the branch.  A return address cannot: it is an
  // address in the SymSan binary, and AFL numbered a different one.
  // Conditions only -- a GEP is not an edge and passes 0.
  std::map<std::pair<uint32_t, std::string>, uint64_t> cids;

  // Attribute one parse. `reason` is the parser's own account of why it
  // stopped; an empty one on an empty result means the parser had nothing to
  // say, which is itself worth a bucket rather than being silently dropped.
  // `cid` is the branch id the trace event carried, 0 for an event with none.
  void note(bool failed, size_t produced, const std::string &reason, void *addr,
            uint64_t &ok, uint64_t &empty, uint64_t &fail, uint32_t cid = 0) {
    const char *bucket = nullptr;
    if (failed) {
      fail++;
      bucket = reason.empty() ? "(unreported)" : reason.c_str();
    } else if (produced == 0) {
      empty++;
      bucket = reason.empty() ? "(no task, unreported)" : reason.c_str();
    } else {
      ok++;
      return;
    }
    reasons[bucket]++;
    sites[std::make_pair((uint64_t)addr, std::string(bucket))]++;
    if (cid) cids[std::make_pair(cid, std::string(bucket))]++;
  }

  // Attribute one condition to the per-condition log, if one is open.  Split
  // from note() rather than folded into it because note() is also the GEP path,
  // and a GEP has no label to key on -- see cond_log().
  void log(uint32_t label, bool failed, size_t produced,
           const std::string &reason, void *addr, uint32_t cid) const {
    FILE *f = cond_log();
    if (!f) return;
    fprintf(f, "C %u %u 0x%lx %c %s\n", (unsigned)label, (unsigned)cid,
            (unsigned long)(uintptr_t)addr,
            failed ? 'f' : (produced == 0 ? 'e' : 'o'),
            reason.empty() ? "-" : reason.c_str());
  }

  void report() const {
    printf("PARSE-SUMMARY conds=%lu ok=%lu empty=%lu failed=%lu weakened=%lu "
           "tasks=%lu loop_exits=%lu events=%lu\n",
           (unsigned long)conds, (unsigned long)cond_ok,
           (unsigned long)cond_empty, (unsigned long)cond_failed,
           (unsigned long)cond_weakened,
           (unsigned long)cond_tasks, (unsigned long)loop_exits,
           (unsigned long)events);
    printf("PARSE-SUMMARY geps=%lu ok=%lu empty=%lu failed=%lu tasks=%lu "
           "skipped=%lu\n",
           (unsigned long)geps, (unsigned long)gep_ok, (unsigned long)gep_empty,
           (unsigned long)gep_failed, (unsigned long)gep_tasks,
           (unsigned long)gep_skipped);
    printf("PARSE-GEPSHAPE none=%lu ptr_only=%lu elems_only=%lu both=%lu\n",
           (unsigned long)gep_shape[0], (unsigned long)gep_shape[1],
           (unsigned long)gep_shape[2], (unsigned long)gep_shape[3]);
    for (const auto &kv : reasons) {
      printf("PARSE-REASON %lu\t%s\n", (unsigned long)kv.second,
             kv.first.c_str());
    }
    for (const auto &kv : sites) {
      printf("PARSE-SITE %lu\t0x%lx\t%s\n", (unsigned long)kv.second,
             (unsigned long)kv.first.first, kv.first.second.c_str());
    }
    for (const auto &kv : cids) {
      printf("PARSE-CID %lu\t%u\t%s\n", (unsigned long)kv.second,
             (unsigned)kv.first.first, kv.first.second.c_str());
    }
  }
};

// The one file every run of a corpus sweep points the target at.
//
// A fork server can only be told the input path once -- the launcher bakes it
// into the server's environment at spawn time, and every forked child re-reads
// that same path -- so serving a corpus means one fixed path whose *contents*
// change per seed.  That is what AFL does, and the reason the file lives in
// /dev/shm: it is rewritten once per seed and read once per seed, and there is
// no reason for any of that to reach a disk.
//
// Only used for a corpus.  A lone input keeps running where it lies, which is
// what every existing caller and lit test expects.
class input_stager {
 public:
  ~input_stager() {
    if (fd_ != -1) close(fd_);
    if (path_[0]) unlink(path_);
  }

  // Returns false if none of the candidate directories would have us; the
  // caller decides whether that is fatal.  `tag` names the driver, so two
  // sweeps running side by side do not collide (the pid already separates
  // them, but the name says which process to go looking for).
  bool open_staging(const char *tag) {
    const char *dirs[] = {"/dev/shm", getenv("TMPDIR"), "/tmp"};
    for (const char *dir : dirs) {
      if (!dir) continue;
      snprintf(path_, sizeof(path_), "%s/%s-%d.input", dir, tag, (int)getpid());
      fd_ = ::open(path_, O_RDWR | O_CREAT | O_TRUNC, 0600);
      if (fd_ != -1) return true;
    }
    path_[0] = '\0';
    return false;
  }

  // Point the fixed input file at this seed's bytes.  Truncate first: a short
  // seed after a long one would otherwise be read with the tail of its
  // predecessor still attached.
  int stage(const char *buf, size_t size) {
    if (ftruncate(fd_, 0) != 0) return -1;
    size_t done = 0;
    while (done < size) {
      ssize_t w = pwrite(fd_, buf + done, size - done, done);
      if (w > 0) done += (size_t)w;
      else if (w < 0 && errno == EINTR) continue;
      else return -1;
    }
    if (lseek(fd_, 0, SEEK_SET) == (off_t)-1) return -1;
    return 0;
  }

  // Null until open_staging succeeds, which is also how the drivers ask "am I
  // sweeping a corpus or running one seed where it lies".
  const char *path() const { return path_[0] ? path_ : nullptr; }
  int fd() const { return fd_; }

 private:
  char path_[PATH_MAX] = {0};
  int fd_ = -1;
};

} // namespace sweep
} // namespace symsan

#endif // SYMSAN_DRIVER_SWEEP_H
