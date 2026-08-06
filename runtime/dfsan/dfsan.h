//===-- dfsan.h -------------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DataFlowSanitizer.
//
// Private DFSan header.
//===----------------------------------------------------------------------===//

#ifndef DFSAN_H
#define DFSAN_H

#include "sanitizer_common/sanitizer_internal_defs.h"
#include "dfsan_platform.h"
#include <stdio.h>
#include <stdint.h>

using __sanitizer::uptr;

extern bool print_debug;

# define AOUT(...)                                      \
  do {                                                  \
    if (print_debug)  {                                 \
      Printf("[RT] (%s:%d) ", __FUNCTION__, __LINE__);  \
      Printf(__VA_ARGS__);                              \
    }                                                   \
  } while(false)

// Copy declarations from public sanitizer/dfsan_interface.h header here.
typedef uint32_t dfsan_label;

typedef union {
  uint64_t i;
  float f;
  double d;
} data;

struct dfsan_label_info {
  dfsan_label l1;
  dfsan_label l2;
  data op1;
  data op2;
  uint16_t op;
  uint16_t size; // FIXME: this limit the size of the operand to 65535 bits or bytes (in case of memcmp)
  uint32_t hash;
} __attribute__((aligned (8), packed));

#ifndef PATH_MAX
# define PATH_MAX 4096
#endif
#define CONST_OFFSET 1
#define CONST_LABEL 0

static const size_t minimum_uniontable_size = 0x10000 * sizeof(dfsan_label_info); // 64K entries
static size_t uniontable_size = 0xc00000000; // FIXME

struct taint_file {
  char filename[PATH_MAX];
  int fd;
  off_t offset;
  dfsan_label offset_label;
  dfsan_label label;
  off_t size;
  uint8_t is_stdin;
  uint8_t is_utmp;
  char *buf;
  uptr buf_size;
};

struct taint_socket {
  int family;
  int port;
  int fd;
  off_t offset;
  char host[PATH_MAX];
};

extern "C" {
void dfsan_add_label(dfsan_label label, uint8_t op, void *addr, uptr size);
void dfsan_set_label(dfsan_label label, void *addr, uptr size);
void dfsan_clear_thread_local_state();
dfsan_label dfsan_read_label(const void *addr, uptr size);
void dfsan_store_label(dfsan_label l1, void *addr, uptr size);
dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2, uint16_t op, uint16_t size,
                        uint64_t op1, uint64_t op2);
dfsan_label dfsan_create_label(uint64_t input_id, uint64_t offset, uint32_t size_in_bytes);
dfsan_label dfsan_get_label(const void *addr);
dfsan_label_info* dfsan_get_label_info(dfsan_label label);

// taint source
void taint_set_file(int dirfd, const char *filename, int fd);
off_t taint_get_file(int fd);
void taint_close_file(int fd);
int is_taint_file(const char *filename);
int is_stdin_taint(void);
void taint_set_offset_label(dfsan_label label);
dfsan_label taint_get_offset_label();

// taint tracking for string operations
void taint_set_str_content_label(void *addr, dfsan_label label);
dfsan_label taint_get_str_content_label(const void *addr);
void taint_set_str_indexof_label(void *addr, dfsan_label label);
dfsan_label taint_get_str_indexof_label(const void *addr);
dfsan_label taint_find_string_op_source(dfsan_label label);
dfsan_label taint_get_base_input_label(dfsan_label label);

// taint source utmp
off_t get_utmp_offset(void);
void set_utmp_offset(off_t offset);
int is_utmp_taint(void);

// taint source socket
void taint_set_socket(const void *addr, unsigned addrlen, int fd);
off_t taint_get_socket(int fd);
void taint_update_socket_offset(int fd, size_t size);
void taint_close_socket(int fd);

// AFL++ coverage map, for a binary carrying AFL++'s edge counters; afl_compat.cpp.
// Unlike InitializeSymSanSolver/InitializeSymSanForkServer this is not a weak
// hook a backend may or may not fill in -- it lives in the same archive as its
// caller and decides at run time whether it applies, because --whole-archive
// links the object either way.
void InitializeAflCoverage(void);
}  // extern "C"

template <typename T>
void dfsan_set_label(dfsan_label label, T &data) {  // NOLINT
  dfsan_set_label(label, (void *)&data, sizeof(T));
}

namespace __dfsan {

const dfsan_label kInitializingLabel = -1;

void InitializeInterceptors();

inline dfsan_label *shadow_for(void *ptr) {
  return (dfsan_label *) ((((uptr) ptr) & ShadowMask()) << 2);
}

inline const dfsan_label *shadow_for(const void *ptr) {
  return shadow_for(const_cast<void *>(ptr));
}

inline void *app_for(const dfsan_label *l) {
  return (void *) ((((uptr) l) >> 2) | AppBaseAddr());
}

dfsan_label_info* get_label_info(dfsan_label label);

struct Flags {
#define DFSAN_FLAG(Type, Name, DefaultValue, Description) Type Name;
#include "dfsan_flags.inc"
#undef DFSAN_FLAG

  void SetDefaults();
};

extern Flags flags_data;
inline Flags &flags() {
  return flags_data;
}

// taint source
extern struct taint_file tainted;
extern struct taint_socket tainted_socket;

enum operators {
  Not       = 1,
  Neg       = 2,
#define HANDLE_BINARY_INST(num, opcode, Class) opcode = num,
#define HANDLE_MEMORY_INST(num, opcode, Class) opcode = num,
#define HANDLE_CAST_INST(num, opcode, Class) opcode = num,
#define HANDLE_OTHER_INST(num, opcode, Class) opcode = num,
#define LAST_OTHER_INST(num) last_llvm_op = num,
#include "llvm/IR/Instruction.def"
#undef HANDLE_BINARY_INST
#undef HANDLE_MEMORY_INST
#undef HANDLE_CAST_INST
#undef HANDLE_OTHER_INST
#undef LAST_OTHER_INST // last_llvm_op = 67 for llvm14
  // self-defined
  Free      = last_llvm_op + 3, // 70
  Extract   = last_llvm_op + 4, // 71
  Concat    = last_llvm_op + 5, // 72
  Arg       = last_llvm_op + 6, // 73
  // higher-order
  fmemcmp   = last_llvm_op + 7, // 74
  fsize     = last_llvm_op + 8, // 75
  fatoi     = last_llvm_op + 9, // 76
  fstrlen   = last_llvm_op + 10, // 77
  // string search ops that return positions (for chaining detection)
  fstr_op_start = last_llvm_op + 11, // 78
  fstrchr   = last_llvm_op + 11,  // 78 strchr/memchr
  fstrrchr  = last_llvm_op + 12,  // 79 strrchr/memrchr
  fstrstr   = last_llvm_op + 13,  // 80 strstr/memmem
  fstrpbrk  = last_llvm_op + 14,  // 81 strpbrk - find first char from set
  fstr_off  = last_llvm_op + 15,  // 82 string op + constant offset (for ptr arithmetic)
  fsubstr   = last_llvm_op + 16,  // 83 substr(s, 0, len) - for bounded search
  fstrcat   = last_llvm_op + 17,  // 84 strcat/strncat - string concatenation
  fstr_op_end = last_llvm_op + 18, // 85
  // string comparison (returns 0/1, NOT a position - must be outside fstr_op range)
  fstrcmp   = last_llvm_op + 18, // 85 strcmp using Z3 string theory
  fprefixof = last_llvm_op + 19, // 86 prefixof(str, prefix) using Z3 string theory
  fsuffixof = last_llvm_op + 20, // 87 suffixof(str, suffix) using Z3 string theory
  flength   = last_llvm_op + 21, // 88 z3::length(str_var), Int sort
  // floating-point ops.  Binary FP arithmetic (FAdd/FSub/FMul/FDiv/FRem),
  // FP casts (FPToUI/FPToSI/UIToFP/SIToFP/FPTrunc/FPExt) and FCmp reuse the LLVM
  // opcodes directly (they are already in this enum via Instruction.def).  The
  // ops below are the ones LLVM does *not* give us a usable opcode for: FNeg is a
  // unary instruction (Instruction.def UNARY insts are not expanded here) and the
  // FP intrinsics have no opcode at all.  They are placed in [Add, LastOp) so
  // is_valid_op() accepts them.
  fp_neg      = last_llvm_op + 22, // 89 fneg (llvm FNeg is unary, not in enum)
  fp_fabs     = last_llvm_op + 23, // 90 llvm.fabs
  fp_sqrt     = last_llvm_op + 24, // 91 llvm.sqrt
  fp_round    = last_llvm_op + 25, // 92 round-to-integral; rounding mode in op1
  fp_min      = last_llvm_op + 26, // 93 llvm.minnum
  fp_max      = last_llvm_op + 27, // 94 llvm.maxnum
  fp_copysign = last_llvm_op + 28, // 95 llvm.copysign
  // FP predicates + rounding-to-int libcalls modeled as custom wrappers (see
  // done_abilist.txt / dfsan_custom.cpp).  SymSan has no working "functional"
  // ABI (WK_Functional is a no-op that drops taint), so these must build real
  // op nodes for the solver.  Predicate results are 0/1 integers; fp_lrint is
  // round-to-nearest (RNE) then convert to a signed integer.
  fp_is_nan    = last_llvm_op + 29, // 96 isnan/isnanf
  fp_is_inf    = last_llvm_op + 30, // 97 isinf/isinff and __isinf/__isinff
  fp_is_finite = last_llvm_op + 31, // 98 finite/finitef
  fp_signbit   = last_llvm_op + 32, // 99 __signbit/__signbitf
  fp_lrint     = last_llvm_op + 33, // 100 lrint/lrintf/llrint/llrintf
  // FP transcendentals modeled as custom wrappers (see done_abilist.txt /
  // dfsan_custom.cpp).  z3 cannot invert them and jigsaw is integer-only, so
  // only the i2s solver flips these guards (it computes the numeric libm
  // inverse and verifies).  fp_pow is binary (base, exponent).
  fp_exp       = last_llvm_op + 34, // 101 exp/expf
  fp_exp2      = last_llvm_op + 35, // 102 exp2
  fp_log       = last_llvm_op + 36, // 103 log/logf
  fp_log2      = last_llvm_op + 37, // 104 log2/log2f
  fp_log10     = last_llvm_op + 38, // 105 log10
  fp_log1p     = last_llvm_op + 39, // 106 log1p/log1pf
  fp_pow       = last_llvm_op + 40, // 107 pow/powf
  // Load from a read-only global lookup table at a symbolic index.  Produced at
  // the *load*, not the GEP, so the loaded value gets a real shadow instead of
  // going concrete (shadow memory over globals is zero).  l1 is the index label,
  // op1 the table base address, op2 the element count; size is elem_size * 8.
  // The table contents are shipped separately (see table_type) because the
  // solver runs in another process and cannot read the target's memory.
  // Neither z3 nor jigsaw model this: only the i2s solver inverts it, by
  // scanning the table for the wanted output and re-targeting the index.
  tlookup      = last_llvm_op + 41, // 108
  // llvm.bitreverse: reverse the bit order of the operand.  Unary, l1 is the
  // operand; size is the operand width, which is also the result width.  Kept
  // as one node rather than decomposed the way bswap is (into size Extracts and
  // size-1 Concats): bswap costs 15 union-table entries for an i64, bit
  // reversal would cost 127, and clang's idiom recognizer emits this for every
  // byte of a CRC's reflection loop.  z3 expands it to a concat of one-bit
  // extracts, jigsaw JITs the native LLVM intrinsic, and i2s inverts it by
  // reversing the wanted value.
  bitreverse   = last_llvm_op + 42, // 109
  // A concrete operand of an operation wider than 64 bits, carried as a leaf
  // label: l1 = l2 = 0, op1 = low 64 bits, op2 = high 64 bits, size = width.
  // The traced-operand slots in dfsan_label_info are 64 bits each, so a wide
  // concrete operand reaching __taint_union the normal way (as a zero label
  // plus a value in op1/op2) would be TRUNCATED and embedded in the AST as a
  // wrong constant -- silently, since a wrong constant is still a well-formed
  // formula.  Giving it a real label instead moves the value into op1+op2
  // together, which is exactly 128 bits, and costs one union-table entry per
  // *distinct* constant for the whole trace: operator== in union_util.cpp
  // compares both slots, so identical constants dedup and distinct ones do not
  // collide.  Note this is needed even for small constants like the 64 in
  // `(unsigned __int128)x >> 64` -- what matters is that the runtime can tell
  // an exact value from a truncated one, and a zero label cannot say which it
  // is.  The parser lowers it to a multi-slot rgd::Constant, the convention
  // z3-solver.cpp and jit.cc already read.
  WideConst = last_llvm_op + 43, // 110
  LastOp    = last_llvm_op + 44, // 111
};

// rounding-mode selector carried in op1 for fp_round, and used when lowering FP
// arithmetic in the solver.  Values match z3::rounding_mode ordering.
enum fp_rounding_mode {
  fp_rm_rna = 0, // round nearest, ties to away (llvm.round)
  fp_rm_rne = 1, // round nearest, ties to even (llvm.rint/nearbyint, default)
  fp_rm_rtp = 2, // round toward +inf (llvm.ceil)
  fp_rm_rtn = 3, // round toward -inf (llvm.floor)
  fp_rm_rtz = 4, // round toward zero (llvm.trunc)
};

// Flag packed into the high bits of a fatoi label's op1 (which otherwise holds
// the numeric base).  When set, the solver must NOT append a NUL terminator
// after the rendered digits: the parsed number is embedded in a larger input
// (e.g. an sscanf field) rather than a standalone null-terminated string, so a
// NUL would clobber the following separator/bytes.  Kept clear for
// atoi/strtol so their labels stay bit-identical.
#define FATOI_NO_NULL (1u << 16)
#define FATOI_BASE_MASK 0xffffu

enum predicate {
  bveq = 32,
  bvneq = 33,
  bvugt = 34,
  bvuge = 35,
  bvult = 36,
  bvule = 37,
  bvsgt = 38,
  bvsge = 39,
  bvslt = 40,
  bvsle = 41
};

static inline uint8_t get_const_result(uint64_t c1, uint64_t c2, uint32_t predicate) {
  switch (predicate) {
    case bveq:  return c1 == c2;
    case bvneq: return c1 != c2;
    case bvugt: return c1 > c2;
    case bvuge: return c1 >= c2;
    case bvult: return c1 < c2;
    case bvule: return c1 <= c2;
    case bvsgt: return (int64_t)c1 > (int64_t)c2;
    case bvsge: return (int64_t)c1 >= (int64_t)c2;
    case bvslt: return (int64_t)c1 < (int64_t)c2;
    case bvsle: return (int64_t)c1 <= (int64_t)c2;
    default: break;
  }
  return 0;
}

// Is this op's `size` field a byte count rather than a bit width?
//
// dfsan_label_info::size is overloaded: for everything the instrumentation
// emits it is the operand's width in bits, but the libc wrappers in
// dfsan_custom.cpp put a *byte* count there for the ops that compare or search
// memory -- the extent that was compared, which the solver needs and which has
// no bit width to speak of.  __taint_union's wide-operand guards read `size`
// unconditionally as a width, so without this every memcmp/strstr of more than
// 64 bytes was silently declined; a 65-byte memcmp and a 168-character strchr
// haystack are both entirely ordinary.
//
// Written as a list of the ops that ARE byte counts, so a new op is treated as
// a width by default -- which is the safe way round: a width that is really a
// byte count only ever declines a shadow, while the reverse would take a real
// 128-bit operand through a guard meant to catch it.
static inline bool op_size_is_byte_count(uint16_t op) {
  switch (op & 0xff) {
    // the extent memcmp/bcmp compared
    case fmemcmp:
    // str_content_len() of the haystack, saturated at 0xffff
    case fstrchr: case fstrrchr: case fstrstr: case fstrpbrk:
    // the compared or concatenated length
    case fstrcmp: case fprefixof: case fsuffixof: case fstrcat:
      return true;
    // fsize/fatoi/fstrlen/fstr_off/fsubstr are deliberately absent: they carry
    // the bit width of the integer or pointer they produce, not a length.
    default:
      return false;
  }
}

// For an operation wider than 64 bits, does op2 carry a value operand?  A
// concrete value operand cannot be represented at that width -- op1/op2 are 64
// bits each and the instrumentation truncates into them -- so a zero l2 on such
// an op has to be declined rather than embedded as a wrong constant.  See
// WideConst, which is how a *constant* operand avoids this; a zero label
// reaching here at >64 bits therefore means a runtime-untainted wide value.
//
// Written as a list of the ops that do NOT read op2 as a value, so anything not
// considered here is declined: a miss rather than a wrong formula.
static inline bool wide_op_reads_op2(uint16_t op) {
  switch (op & 0xff) {
    case Not: case Neg:
    // every unary cast, which is the rule rather than a list of the ones that
    // happen to be reachable wide today: `fptosi double to i128` is the one
    // that is, and declining it would be a gratuitous miss.
    case Trunc: case ZExt: case SExt: case BitCast:
    case FPToUI: case FPToSI: case UIToFP: case SIToFP:
    case FPTrunc: case FPExt: case PtrToInt: case IntToPtr:
    case AddrSpaceCast:
    case bitreverse:
    // Extract does read op2, but it is the bit offset the instrumentation
    // emitted, always < the operand width and so never truncated.
    case Extract:
    // Load keeps a byte count in l2, not a label.
    case Load:
    // the wide-constant leaf itself, whose whole purpose is to fill op1+op2
    case WideConst:
      return false;
    default:
      return true;
  }
}

static inline bool is_commutative(uint16_t op) {
  // mask to the base opcode: cmp packs a predicate and FP arithmetic may pack a
  // rounding-mode selector into the high byte (neither changes commutativity).
  switch(op & 0xff) {
    case Not:
    case And:
    case Or:
    case Xor:
    case Add:
    case Mul:
    // FP add/mul/min/max are commutative (NaN propagation and signed-zero
    // results are symmetric), so operands may be swapped for dedup.
    case FAdd:
    case FMul:
    case fp_min:
    case fp_max:
    case fmemcmp:
    case fstrcmp:
      return true;
    default:
      return false;
  }
}

// Check if an op is a string operation (fstr_op_start to fstr_op_end)
static inline bool is_string_op(uint16_t op) {
  return op >= __dfsan::fstr_op_start && op < __dfsan::fstr_op_end;
}

// Check if an op is an indexOf-type operation (returns position, not content)
// These are: fstrchr, fstrrchr, fstrstr, fstrpbrk, fstr_off
static inline bool is_indexof_op(uint16_t op) {
  return op >= __dfsan::fstrchr && op <= __dfsan::fstr_off;
}

// Check if an op is a content-type string operation (fsubstr, fstrcat)
static inline bool is_content_string_op(uint16_t op) {
  return op == __dfsan::fsubstr || op == __dfsan::fstrcat;
}

// for out-of-process solving

enum pipe_msg_type {
  cond_type = 0,
  gep_type = 1,
  memcmp_type = 2,
  add_constraint_type = 3,
  memerr_type = 4,
  // from thoroupy
  exit_type,
  loop_type,
  bb_type,
  event_type,
  gv_type,
  minimize_type,
  // contents of a read-only global lookup table, sent once per table per trace
  // so the out-of-process solver can invert a tlookup (see table_msg)
  table_type,
};

static const uint8_t TrueBranchLoopLatch = 0x8;
static const uint8_t FalseBranchLoopLatch = 0x4;
static const uint8_t TrueBranchLoopExit = 0x2;
static const uint8_t FalseBranchLoopExit = 0x1;
static const uint8_t LoopFlagMask = 0xF;
static const uint8_t UndefinedCheck = 0x10;

enum undefined_check_ids {
  ub_integer_overflow = 1,
  ub_division_by_zero,
  ub_shift_exponent,
  ub_shift_overflow,
  ub_shift_base,
  ub_index_underflow,
  ub_index_overflow,
  ub_size_underflow,
  ub_size_overflow,
  ub_size_to_buffer_overflow,
  ub_integer_to_buffer_overflow,
  ub_null_pointer,
  ub_unsigned_integer_truncation,
  ub_signed_integer_truncation,
  ub_integer_sign_change,
  ub_assertion_failure,
};

#define F_ADD_CONS   0x1
#define F_LOOP_EXIT  0x2
#define F_LOOP_LATCH 0x4

#define F_MEMERR_UAF  0x1
#define F_MEMERR_OLB  0x2
#define F_MEMERR_OUB  0x4
#define F_MEMERR_UBI  0x8
#define F_MEMERR_NULL 0x10
#define F_MEMERR_FREE 0x20 // double free

struct pipe_msg {
  uint16_t msg_type;
  uint16_t flags;
  uint32_t instance_id;
  uptr addr;
  uint32_t context;
  uint32_t id;
  uint32_t label;
  uint64_t result;
} __attribute__((packed));

// additional info for gep
struct gep_msg {
  uint32_t ptr_label;
  uint32_t index_label;
  uptr ptr;
  int64_t index;
  uint64_t num_elems;
  uint64_t elem_size;
  int64_t current_offset;
} __attribute__((packed));

// saving the memcmp target
struct memcmp_msg {
  uint32_t label;
  uint8_t content[0];
} __attribute__((packed));

// contents of a read-only lookup table, keyed on its base address (the same
// value a tlookup label carries in op1).  Sent once per table per trace: the
// solver runs in a different process and cannot read the target's memory.
struct table_msg {
  uptr ptr;
  uint64_t num_elems;
  uint64_t elem_size;
  uint8_t content[0];
} __attribute__((packed));

}  // namespace __dfsan

#endif  // DFSAN_H
