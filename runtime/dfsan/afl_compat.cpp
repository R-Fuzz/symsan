//===-- afl_compat.cpp ----------------------------------------------------===//
//
// Part of the Symsan project.
//
//===----------------------------------------------------------------------===//
//
// SymSan runtime support.
//
// The AFL++ half of the ABI, for a binary built the two-stage way: one
// afl-clang-lto link produces the merged, AFL++-instrumented module, and
// TaintPass then runs over that same module (-taint-with-afl, see
// instrumentation/TaintPass.cpp).  The result carries AFL++'s edge counters --
// which is what lets SymSan name a branch by the fuzzer's own edge id -- but
// nothing in it defines the globals those counters are written through.
//
// The obvious way to supply them is to link AFL++'s afl-compiler-rt.o, and that
// is wrong here: it installs __afl_auto_init as a constructor, which starts a
// fork server inside a process whose fork server SymSan already owns (see
// InitializeSymSanForkServer, called from dfsan_init).  Two fork servers on one
// process is not a configuration either side survives.  So this file supplies
// what the counters need and nothing else -- no fork server, no persistent-mode
// loop, no forkserver handshake, no dictionary or cmplog apparatus.
//
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_posix.h"

#include <sys/mman.h>
#include <sys/shm.h>

using namespace __sanitizer;

namespace {

// AFL++'s MAP_SIZE (include/config.h): the smallest map it will work with, and
// the size of the one we fall back to.
const uptr kDefaultMapSize = 1 << 16;

// Where __afl_area_ptr points until AttachCoverageMap() runs, so that a counter
// store reaching it early writes somewhere valid rather than through a null
// pointer.
//
// AFL++ sizes the equivalent buffer at MAP_INITIAL_SIZE -- 2MB for an LTO build
// -- because its own attach happens in a constructor, and any .init_array entry
// ordered ahead of it is already counting edges.  Here the attach is reached
// from dfsan_init, which runs out of .preinit_array, ahead of every constructor
// in the program.  So this buffer covers a window in which no instrumented code
// can run at all, and its size is a formality; it is kept at AFL++'s minimum
// rather than its maximum because ko-clang links the runtime with
// --whole-archive, so every SymSan binary carries it, AFL++-instrumented or not.
u8 InitialMap[kDefaultMapSize];

} // namespace

extern "C" {

// The coverage map every edge counter AFL++ injected writes into.
SANITIZER_INTERFACE_ATTRIBUTE u8 *__afl_area_ptr = InitialMap;

// How much of that map holds edge counts.  Nothing in an LTO-instrumented
// module reads it -- it is afl-compiler-rt's own bookkeeping -- but AFL++'s
// other instrumentation modes reference it, so it is defined and kept honest.
SANITIZER_INTERFACE_ATTRIBUTE u32 __afl_cov_map_size = kDefaultMapSize;

// Set by the constructor AFL++ appends to a module whose autodictionary found
// anything: it points __afl_dictionary at the module's own read-only
// __afl_internal_dictionary and stores the length.  Nothing here reads them --
// the tokens are for the fuzzer's havoc stage, and this process is not the
// fuzzer -- but the stores happen whether or not anyone is listening, so the
// globals have to exist.
SANITIZER_INTERFACE_ATTRIBUTE u8 *__afl_dictionary;
SANITIZER_INTERFACE_ATTRIBUTE u32 __afl_dictionary_len;

// Only referenced when AFL++ was configured for context-sensitive coverage
// (AFL_LLVM_CTX / NGRAM), which is not the default and not what this pipeline
// builds; defined so that such a module still links.
SANITIZER_INTERFACE_ATTRIBUTE __thread u32 __afl_prev_ctx;

// Defined by AFL++'s pass as a strong global whose initialiser is the edge
// count.  Weak here so that the same runtime still links into a binary that
// never went through that pass -- where it reads 0, which is exactly the test
// InitializeAflCoverage() uses to tell the two apart.
SANITIZER_WEAK_ATTRIBUTE u32 __afl_final_loc;

} // extern "C"

namespace {

// How many counter bytes this binary can actually write, which is the only
// thing that makes a map too small.  AFL++'s pass defines __afl_final_loc with
// the edge count as its static initialiser, already rounded up past the highest
// id it assigned (SanitizerCoverageLTO.so.cc:1337), so it is both the count and
// the size.
//
// Deliberately not AFL_MAP_SIZE, which reads like the answer and is not one.
// AFL++ exports it into the child as DEFAULT_SHMEM_SIZE -- 8MB -- *before* it
// knows how big a map the target wants, as a placeholder for the size the
// forkserver handshake is about to report back (afl_fsrv_resize_mapsize,
// src/afl-forkserver.c:2305-2317).  A SymSan binary never reaches that
// handshake, so it only ever sees the placeholder, and a placeholder larger
// than the segment AFL++ really made turns a working run into a fatal error.
uptr CoverageMapNeeded() {
  if (__afl_final_loc)
    return __afl_final_loc;
  return kDefaultMapSize;
}

void AttachCoverageMap() {
  uptr need = CoverageMapNeeded();

  // Whichever map the launcher named.  Note for whoever wires the launcher up:
  // symsan-fuzz has already put its *own* map in this variable and every child
  // inherits it, so the traced process has to be given a replacement value
  // rather than merely a value -- otherwise a trace's edge counts land in the
  // map the fuzzer is reading coverage out of.
  const char *id_str = GetEnv("__AFL_SHM_ID");
  if (id_str) {
    int id = (int)internal_simple_strtoll(id_str, nullptr, 10);

    // Check the segment is big enough before attaching to it.  A short map is
    // not a survivable mistake: a counter is a plain store at a constant
    // offset, so every id past the end lands in whatever the fuzzer put after
    // the map, and the symptom is the fuzzer misbehaving rather than this
    // process failing.  Refusing to start is the kinder answer.
    //
    // The segment's own size is what to compare against: it is what the kernel
    // will actually let us write, and unlike AFL_MAP_SIZE nobody can set it to
    // a guess.
    uptr have = 0;
    struct shmid_ds ds;
    if (shmctl(id, IPC_STAT, &ds) == 0)
      have = (uptr)ds.shm_segsz;
    if (have && have < need) {
      Report("FATAL: AFL++ coverage map is %zu bytes but this binary needs %zu; "
             "run the fuzzer with AFL_MAP_SIZE=%zu\n", have, need, need);
      Die();
    }

    void *shm = shmat(id, nullptr, 0);
    if (shm != (void *)-1) {
      __afl_area_ptr = (u8 *)shm;
      __afl_cov_map_size = (u32)need;
      return;
    }
    Report("WARNING: failed to attach AFL++ coverage map %d, "
           "falling back to a private one\n", id);
  }

  // Nobody to share with -- the binary is being run standalone, or by a driver
  // that has not made a map.  The counters still have to land somewhere, and
  // InitialMap is somewhere, so only bother mapping when the ids do not fit.
  //
  // No segment to fit into either, so the size may as well be whatever was
  // asked for.  AFL_MAP_SIZE is a floor and nothing more, and it is honoured
  // here only because a map this process alone reads costs nothing to
  // oversize -- the reasoning on CoverageMapNeeded() is about the shm path,
  // where believing it can be fatal.
  //
  // MAP_PRIVATE rather than MAP_SHARED, and likewise for InitialMap being plain
  // bss: this mapping is made before the fork point, so with the fork server
  // every run inherits it, and a private mapping gives each child its own
  // copy-on-write zeroes.  That is per-run coverage for free, which is what a
  // map nobody else is reading wants to be.  (The shm case above is shared on
  // purpose, and is zeroed by whoever owns it, once per run.)
  uptr size = need;
  if (const char *env = GetEnv("AFL_MAP_SIZE")) {
    s64 val = internal_simple_strtoll(env, nullptr, 10);
    if (val > 0 && (uptr)val > size)
      size = (uptr)val;
  }

  if (size <= sizeof(InitialMap)) {
    __afl_cov_map_size = (u32)size;
    return;
  }

  int err;
  uptr map = internal_mmap(nullptr, size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (internal_iserror(map, &err)) {
    Report("WARNING: failed to map a private %zu-byte AFL++ coverage map (%d); "
           "edge ids above %zu will not be counted\n",
           size, err, sizeof(InitialMap));
    return;
  }
  __afl_area_ptr = (u8 *)map;
  __afl_cov_map_size = (u32)size;
}

} // namespace

extern "C" {

// Called from dfsan_init, before the fork point, so that the attach is paid for
// once and inherited by every run rather than repeated per child.
SANITIZER_INTERFACE_ATTRIBUTE void InitializeAflCoverage() {
  // ko-clang links the runtime with --whole-archive, so this object is present
  // in every SymSan binary and cannot use its own linkage to decide whether it
  // applies.  __afl_final_loc is the module's own statement that AFL++'s pass
  // ran, and it is the whole test.
  //
  // Not "or __AFL_SHM_ID is set", which was the first spelling and was wrong:
  // symsan-fuzz publishes that variable into its own environment
  // (bindings/rust/fuzzer/src/main.rs), so every SymSan child inherits it
  // whether or not the child has a single AFL++ counter in it.  Under that
  // spelling an ordinary per-TU ko-clang binary -- no counters at all -- would
  // attach to the fuzzer's map and, if the fuzzer had sized it below AFL++'s
  // minimum, die in the size check before main.
  //
  // The gap that leaves is AFL_LLVM_LTO_DONTWRITEID, which suppresses this
  // global while still emitting counters.  Nothing here can detect that build,
  // and nothing needs to: TaintPass reads the same global for the .bmap
  // `edges=` header, so a DONTWRITEID module cannot produce a usable branch map
  // and is already outside this pipeline.
  if (!__afl_final_loc)
    return;
  AttachCoverageMap();
}

} // extern "C"
