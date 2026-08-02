//===-- dfsan.cc ----------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DataFlowSanitizer.
//
// DataFlowSanitizer runtime.  This file defines the public interface to
// DataFlowSanitizer as well as the definition of certain runtime functions
// called automatically by the compiler (specifically the instrumentation pass
// in llvm/lib/Transforms/Instrumentation/DataFlowSanitizer.cpp).
//
// The public interface is defined in include/sanitizer/dfsan_interface.h whose
// functions are prefixed dfsan_ while the compiler interface functions are
// prefixed __dfsan_.
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_allocator_internal.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_mutex.h"
#include "sanitizer_common/sanitizer_posix.h"

#include "dfsan.h"
#include "taint_allocator.h"
#include "union_util.h"
#include "union_hashtable.h"
#include "ucsan_exit_reason.h"

#include <assert.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

using namespace __dfsan;

typedef atomic_uint32_t atomic_dfsan_label;

static atomic_dfsan_label __dfsan_last_label;
static dfsan_label_info *__dfsan_label_info;

// FIXME: single thread
// statck bottom
static dfsan_label __alloca_stack_bottom;
static dfsan_label __alloca_stack_top;
static const int MAX_SAVED_STACK_ENTRIES = 1024;
static dfsan_label __saved_alloca_stack_top[MAX_SAVED_STACK_ENTRIES];
static int __current_saved_stack_index = 0;

// taint source
struct taint_file __dfsan::tainted;
struct taint_socket __dfsan::tainted_socket;

// Hash table
static const uptr hashtable_size = (1ULL << 32);
static const size_t hashtable_buckets = (1ULL << 20);
static __taint::union_hashtable __union_table(hashtable_buckets);

Flags __dfsan::flags_data;
bool print_debug;

// The size of TLS variables. These constants must be kept in sync with the ones
// in Taint.cc
static const int kArgTlsSize = 800;
static const int kRetvalTlsSize = 800;

SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL dfsan_label
    __dfsan_retval_tls[kRetvalTlsSize / sizeof(dfsan_label)];
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL dfsan_label
    __dfsan_arg_tls[kArgTlsSize / sizeof(dfsan_label)];

SANITIZER_INTERFACE_ATTRIBUTE uptr __dfsan_shadow_ptr_mask;

// On Linux/x86_64, memory is laid out as follows:
//
// +--------------------+ 0x800000000000 (top of memory)
// | application memory |
// +--------------------+ 0x700000040000 (kAppAddr)
// |--------------------| UnusedAddr()
// |                    |
// |    union table     |
// |                    |
// +--------------------+ 0x400100000000 (kUnionTableAddr)
// |    hash table      |
// +--------------------+ 0x400000000000 (kHashTableAddr)
// |   shadow memory    |
// +--------------------+ 0x000000100000 (kShadowAddr)
// |       unused       |
// +--------------------+ 0x000000010000 (kKernelAddr)
// | reserved by kernel |
// +--------------------+ 0x000000000000
//
// To derive a shadow memory address from an application memory address,
// bits 44-46 are cleared to bring the address into the range
// [0x000000040000,0x100000000000).  Then the address is shifted left by 2 to
// account for the double byte representation of shadow labels and move the
// address into the shadow memory range.  See the function shadow_for below.

#ifdef DFSAN_RUNTIME_VMA
// Runtime detected VMA size.
int __dfsan::vmaSize;
#endif

static uptr UnusedAddr() {
  return MappingArchImpl<MAPPING_UNION_TABLE_ADDR>() + uniontable_size;
}

// Checks we do not run out of labels.
static void dfsan_check_label(dfsan_label label) {
  if (label == kInitializingLabel) {
    Report("FATAL: Taint: out of labels\n");
    Die();
  }
  // Alloca labels are in range [__alloca_stack_top, __alloca_stack_bottom]
  if (label >= __alloca_stack_top && label <= __alloca_stack_bottom) {
    return; // Valid Alloca label
  }
  // For regular labels, check against __dfsan_last_label
  dfsan_label last = atomic_load(&__dfsan_last_label, memory_order_relaxed);
  if (label > last) {
    Report("FATAL: Invalid label %u > last %u\n", label, last);
    Die();
  }
}

// based on https://github.com/Cyan4973/xxHash
// simplified since we only have 12 bytes info
static inline uint32_t xxhash(uint32_t h1, uint32_t h2, uint32_t h3) {
  const uint32_t PRIME32_1 = 2654435761U;
  const uint32_t PRIME32_2 = 2246822519U;
  const uint32_t PRIME32_3 = 3266489917U;
  const uint32_t PRIME32_4 =  668265263U;
  const uint32_t PRIME32_5 =  374761393U;

  #define XXH_rotl32(x,r) ((x << r) | (x >> (32 - r)))
  uint32_t h32 = PRIME32_5;
  h32 += h1 * PRIME32_3;
  h32  = XXH_rotl32(h32, 17) * PRIME32_4;
  h32 += h2 * PRIME32_3;
  h32  = XXH_rotl32(h32, 17) * PRIME32_4;
  h32 += h3 * PRIME32_3;
  h32  = XXH_rotl32(h32, 17) * PRIME32_4;
  #undef XXH_rotl32

  h32 ^= h32 >> 15;
  h32 *= PRIME32_2;
  h32 ^= h32 >> 13;
  h32 *= PRIME32_3;
  h32 ^= h32 >> 16;

  return h32;
}

dfsan_label_info* __dfsan::get_label_info(dfsan_label label) {
  return &__dfsan_label_info[label];
}

static inline bool is_constant_label(dfsan_label label) {
  return label == CONST_LABEL;
}

static inline bool is_kind_of_label(dfsan_label label, uint16_t kind) {
  return get_label_info(label)->op == kind;
}

static bool isZeroOrPowerOfTwo(uint16_t x) { return (x & (x - 1)) == 0; }

static inline bool is_valid_op(uint16_t op) {
  op &= 0xff;
  return op >= __dfsan::Add && op < __dfsan::LastOp || op == __dfsan::Not;
}

static inline dfsan_label add_taint_info(dfsan_label_info *info) {
  dfsan_label label =
    atomic_fetch_add(&__dfsan_last_label, 1, memory_order_relaxed) + 1;
  dfsan_check_label(label);

  AOUT("%u = (%u, %u, %u, %u, %lu, %lu)\n", label, info->l1, info->l2,
       info->op, info->size, info->op1.i, info->op2.i);

  internal_memcpy(&__dfsan_label_info[label], info, sizeof(dfsan_label_info));
  return label;
}

// for internal use only, skip optimization and ubsan checks
// caller must ensure op is valid, handle commutative conventions
static dfsan_label do_taint_union(dfsan_label l1, dfsan_label l2, uint16_t op,
                                  uint16_t size, uint64_t op1, uint64_t op2) {
  // dedup
  uint32_t h1 = l1 ? __dfsan_label_info[l1].hash : 0;
  uint32_t h2 = l2 ? __dfsan_label_info[l2].hash : 0;
  uint32_t h3 = op;
  h3 = (h3 << 16) | size;
  uint32_t hash = xxhash(h1, h2, h3);

  struct dfsan_label_info label_info = {
    .l1 = l1, .l2 = l2, .op1 = {op1}, .op2 = {op2}, .op = op, .size = size,
    .hash = hash};

  __taint::option res = __union_table.lookup(label_info);
  if (res != __taint::none()) {
    dfsan_label label = *res;
    AOUT("%u found\n", label);
    return label;
  }

  dfsan_label label = add_taint_info(&label_info);
  __union_table.insert(&__dfsan_label_info[label], label);

  return label;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_trace_cond(dfsan_label label, bool r, uint8_t flag, uint32_t cid);

// Forward declarations for trace callbacks (implemented in solvers)
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_trace_event_addr(uint32_t label, uint32_t event_id,
                              uint64_t info, void* addr, uint32_t info2);

// A WideConst leaf is a constant that happens to need a real label to hold its
// 128 bits, so it carries no more symbolic content than a small literal does.
static inline bool is_wide_const(dfsan_label l) {
  return l != 0 && get_label_info(l)->op == __dfsan::WideConst;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_union(dfsan_label l1, dfsan_label l2, uint16_t op,
                          uint16_t size, uint64_t op1, uint64_t op2) {
  if (!is_valid_op(op)) {
    AOUT("WARNING: invalid op %d\n", op);
    return 0;
  }
  if (l1 > l2 && is_commutative(op)) {
    // needs to swap both labels and concretes
    Swap(l1, l2);
    Swap(op1, op2);
  }
  if (l1 == 0 && l2 < CONST_OFFSET &&
      op != fsize && op != __dfsan::Alloca && op != __dfsan::WideConst)
    return 0;
  // Operations wider than 64 bits can only be represented when every value
  // operand has a real label: op1/op2 hold 64 bits each and combineShadows
  // truncates into them, so a concrete wide operand arriving as a zero label is
  // indistinguishable from an exact one and would be embedded as a wrong
  // constant.  Instrumented code calls __taint_get_wide on each operand first,
  // which turns a concrete one into a WideConst leaf before getting here, so a
  // zero label at this point comes from a caller that has no high half to offer
  // -- dfsan_union, a libc wrapper -- and there is nothing to do but drop the
  // shadow rather than lie about it.
  if (size > 64 && wide_op_reads_op2(op) && (l1 == 0 || l2 == 0))
    return 0;
  // ...and every value operand having a real label is now weaker than having
  // symbolic content, since __taint_get_wide hands out a label for a concrete
  // operand too.  When it did so for all of them the result is concrete, which
  // is what the l2 < CONST_OFFSET early-out above drops for narrow ops; it
  // cannot see this case because a WideConst is a real label, not a small
  // literal.  Untainted wide arithmetic is common enough -- program startup,
  // any instrumented i128 that never meets input -- that skipping this would
  // fill the union table with nodes that constrain nothing.
  if (size > 64 && is_wide_const(l1) &&
      (!wide_op_reads_op2(op) || is_wide_const(l2)))
    return 0;
  if (l1 == kInitializingLabel || l2 == kInitializingLabel)
    return kInitializingLabel;

  // special handling for bounds
  if (get_label_info(l1)->op == __dfsan::Alloca ||
      (op != __dfsan::Load && get_label_info(l2)->op == __dfsan::Alloca)) {
    // propagate if it's casting op
    if (op == __dfsan::BitCast) return l1;
    if (op == __dfsan::PtrToInt) {AOUT("WARNING: ptrtoint %d\n", l1); return 0;}
    if ((op & 0xff) == __dfsan::ICmp) { return 0; } // ptr1 op ptr2
    if (op != __dfsan::Extract) {
      AOUT("WARNING: unsupported op %d over ptr1 %d ptr2 %d\n", op, l1, l2);
      return 0;
    }
  }

  // backup old op-values
  uint64_t orig_op1 = op1, orig_op2 = op2;

  // Preserve op1/op2 for certain operations:
  // - Alloca: uses op1/op2 for bounds tracking
  // - ICmp: records both operands for comparison
  // - Higher-order ops (>= fmemcmp): use op1/op2 for various purposes
  if (op == __dfsan::fmemcmp) {
    // fmemcmp special: copy up to 8 bytes of the data for i2s inference
    uint16_t len = size > 8 ? 8 : size; // for fmemcmp, size is in bytes, not bits
    if (l1 >= CONST_OFFSET) internal_memcpy(&op1, (void*)op1, len);
    if (l2 >= CONST_OFFSET) internal_memcpy(&op2, (void*)op2, len);
  } else if ((op & 0xff) < __dfsan::fmemcmp &&
             op != __dfsan::Alloca &&
             op != __dfsan::PtrToInt &&
             (op & 0xff) != __dfsan::ICmp &&
             (op & 0xff) != __dfsan::FCmp) {
    // mask to the base opcode: FP arithmetic (FAdd/FSub/FMul/FDiv) may pack a
    // rounding-mode selector into the high byte, and must still zero op1/op2 for
    // symbolic operands so identical symbolic nodes dedup (the operand values
    // are irrelevant once symbolic; the selector lives in op, not op1/op2).
    // Not a higher-order op and not Alloca/ICmp/FCmp/PtrToInt - zero out for
    // symbolic operands.
    // PtrToInt needs op1 preserved to compute base pointer for string ops.
    // FCmp, like ICmp, keeps both operand bit patterns so the solver can
    // validate/evaluate the comparison (FILTER_WRONG_AST) without re-deriving
    // the concrete FP values.
    if (l1 >= CONST_OFFSET) op1 = 0;
    if (l2 >= CONST_OFFSET) op2 = 0;
  }

  // try simple simplifications, from qsym
  bool op1_is_zero = (l1 == 0 && op1 == 0);
  bool op1_is_all_one = (l1 == 0 && op1 == ((uint64_t)1 << size) - 1);
  bool op2_is_zero = (l2 == 0 && op2 == 0);
  if (op1_is_zero) {
    switch (op) {
      case __dfsan::And: // 0 & x = 0
      case __dfsan::Mul: // 0 * x = 0
      case __dfsan::Shl: // 0 << x = 0
        return 0;
      case __dfsan::Or: // 0 | x = x
      case __dfsan::Xor: // 0 ^ x = x
      case __dfsan::Add: // 0 + x = x
        return l2;
    }
  } else if (op1_is_all_one) {
    if (op == __dfsan::And) return l2; // 0b11..1 & x = x
    else if (op == __dfsan::Or) return 0; // 0b11..1 | x = 11..1b
    else if (op == __dfsan::Xor && size == 1) op = __dfsan::Not; // 0b1 ^ x = !x
  }
  if (op2_is_zero) {
    if (op == __dfsan::Sub) return l1; // x - 0 = x
    else if (op == __dfsan::Shl) return l1; // x << 0 = x
    else if (op == __dfsan::LShr) return l1; // x >> 0 = x
    else if (op == __dfsan::AShr) return l1; // x >> 0 = x
  }
  // Simplify PtrToInt(string_op) - base_addr to just PtrToInt (the index)
  // This is the ptr2int+sub equivalent of what __taint_gep_offset does for GEP:
  // ptr = base + index, so PtrToInt(ptr) - base = index,
  // and PtrToInt already represents the index as a bitvector
  if (op == __dfsan::Sub && l2 == 0 && l1 >= CONST_OFFSET) {
    dfsan_label_info *l1_info = get_label_info(l1);
    if (l1_info->op == __dfsan::PtrToInt && l1_info->l1 >= CONST_OFFSET) {
      dfsan_label_info *src_info = get_label_info(l1_info->l1);
      if (src_info->op >= __dfsan::fstr_op_start &&
          src_info->op < __dfsan::fstr_op_end &&
          src_info->op1.i == op2) {
        AOUT("simplify ptr2int(string_op) - base: %d\n", l1);
        return l1;
      }
    }
  }
  if (op == __dfsan::Trunc) {
    if (__dfsan_label_info[l1].op == __dfsan::ZExt ||
        __dfsan_label_info[l1].op == __dfsan::SExt) {
      dfsan_label base = __dfsan_label_info[l1].l1;
      if (size == __dfsan_label_info[base].size) return base;
    }
  } else if ((op == __dfsan::Xor || op == __dfsan::Sub) && l1 == l2) {
    // x ^ x = 0
    // x - x = 0
    return 0;
  }

  // setup a hash tree for dedup
  uint32_t h1 = l1 ? __dfsan_label_info[l1].hash : 0;
  uint32_t h2 = l2 ? __dfsan_label_info[l2].hash : 0;
  uint32_t h3 = op;
  h3 = (h3 << 16) | size;
  uint32_t hash = xxhash(h1, h2, h3);

  struct dfsan_label_info label_info = {
    .l1 = l1, .l2 = l2, .op1 = {op1}, .op2 = {op2}, .op = op, .size = size,
    .hash = hash};

  __taint::option res = __union_table.lookup(label_info);
  if (res != __taint::none()) {
    dfsan_label label = *res;
    AOUT("%u found\n", label);
    return label;
  }

  // All the ubsan modeling below is 64-bit arithmetic: it builds masks as
  // (1UL << size) - 1 and sign bits as 1ULL << (size - 1).  Once an operand can
  // be wider than 64 bits those shifts are undefined, and on x86 the shift count
  // is masked -- so a 128-bit Add computes mask 0 and sign_bit 1ULL << 63, and
  // every overflow ICmp derived from them is garbage.  That garbage is not a
  // missing check: it is handed straight to __taint_trace_cond as a real branch
  // constraint, i.e. a formula that does not describe the program.  Skip the
  // checks when any width involved exceeds 64 bits.  The operand widths matter
  // as well as the result's -- a Trunc from i128 to i64 has size == 64 but still
  // evaluates 1UL << size on a value it only holds the low half of.
  const bool ub_width_ok = size <= 64 &&
                           (l1 == 0 || get_label_info(l1)->size <= 64) &&
                           (l2 == 0 || get_label_info(l2)->size <= 64);

  // ubsan checks, after dedup, so we don't do redundant checks
  if (l2 && flags().solve_ub && ub_width_ok) {
    dfsan_label cond = 0;
    uint16_t op_size = get_label_info(l2)->size;
    switch(op & 0xff) {
      case __dfsan::Add:
      case __dfsan::Sub:
      case __dfsan::Mul:
        // check for integer overflow
        break;
      case __dfsan::UDiv:
      case __dfsan::SDiv:
      case __dfsan::URem:
      case __dfsan::SRem:
        // check for division by zero
        // -fsanitize=integer-divide-by-zero
        if (orig_op2 != 0) {
          cond = do_taint_union(l2, 0, (bveq << 8) | __dfsan::ICmp, size,
                                orig_op2, 0);
          __taint_trace_cond(cond, 0, UndefinedCheck, ub_division_by_zero);
        } else {
          AOUT("WARNING: division by zero\n");
          __taint_trace_event_addr(l2, EVENT_DIV_BY_ZERO, 0, __builtin_return_address(0), 0);
        }
        break;
      case __dfsan::Shl:
      case __dfsan::LShr:
      case __dfsan::AShr:
        // -fsanitize=shift-exponent
        // check for too large value: exponent > size
        if (orig_op2 < size) {
          cond = do_taint_union(l2, 0, (bvuge << 8) | __dfsan::ICmp,
                               op_size, orig_op2, size);
          __taint_trace_cond(cond, 0, UndefinedCheck, ub_shift_exponent);
        }
        if ((int64_t)orig_op2 >= 0) {
          // check for negative value
          cond = do_taint_union(l2, 0, (bvslt << 8) | __dfsan::ICmp,
                                op_size, orig_op2, 0);
          __taint_trace_cond(cond, 0, UndefinedCheck, ub_shift_exponent);
        }
        if (op == __dfsan::Shl && orig_op1 != 0 &&
            orig_op2 <= __builtin_clzl(orig_op1) - (64 - size)) {
          // check for shift overflow
          // op2 > leading zero bits in op1
          cond = do_taint_union(l2, 0, (bvugt << 8) | __dfsan::ICmp, op_size,
                                orig_op2, __builtin_clzl(orig_op1) - (64 - size));
          __taint_trace_cond(cond, 0, UndefinedCheck, ub_shift_overflow);
        }
        if (l1 && (int64_t)orig_op1 >= 0) {
          // check for negative base
          // -fsanitize=shift-base
          // op1 < 0
          cond = do_taint_union(l1, 0, (bvslt << 8) | __dfsan::ICmp,
                                get_label_info(l1)->size, orig_op1, 0);
          __taint_trace_cond(cond, 0, UndefinedCheck, ub_shift_base);
        }
        break;
      default:
        break;
    }
  }

  dfsan_label label = add_taint_info(&label_info);
  __union_table.insert(&__dfsan_label_info[label], label);

  if (flags().solve_ub && ub_width_ok) {
    if (op == __dfsan::Trunc && l1) {
      // check for data loss, after the new label is created
      // -fsanitize=implicit-unsigned-integer-truncation
      // old_vale >= (1 << new_size)
      if (orig_op1 < (1UL << size)) {
        // if current value does not have loss
        dfsan_label loss = do_taint_union(l1, 0, (bvuge << 8) | __dfsan::ICmp,
                                          get_label_info(l1)->size, orig_op1,
                                          1UL << size);
        __taint_trace_cond(loss, 0, UndefinedCheck, ub_unsigned_integer_truncation);
      }
      // -fsanitize=implicit-signed-integer-truncation
      // old_value < signed(1 << (size - 1))
      int64_t target = (int64_t)((0xFFFFFFFFFFFFFFFFUL >> (size-1)) << (size-1));
      if ((int64_t)orig_op1 >= target) {
        uint16_t old_size = get_label_info(l1)->size;
        if (old_size < 64) target &= ~(1UL << old_size);
        dfsan_label loss = do_taint_union(l1, 0, (bvslt << 8) | __dfsan::ICmp,
                                          old_size, orig_op1, target);
        __taint_trace_cond(loss, 0, UndefinedCheck, ub_signed_integer_truncation);
      }

      // -fsanitize=implicit-integer-sign-change
      // Check if sign bit changed during truncation
      {
        uint16_t src_size = get_label_info(l1)->size;
        const uint64_t new_mask = size == 64 ? 0xFFFFFFFFFFFFFFFFUL : (1UL << size) - 1;
        uint64_t src_sign_bit = 1ULL << (src_size - 1);
        uint64_t dst_sign_bit = 1ULL << (size - 1);
        bool src_sign = (orig_op1 & src_sign_bit) != 0;
        bool dst_sign = ((orig_op1 & new_mask) & dst_sign_bit) != 0;
        if (src_sign == dst_sign) {
          // Currently no sign change, check if it can happen
          // Sign changes when: sign_bit(l1) != sign_bit(label)
          // We check: (l1 < 0) XOR (label < 0)
          dfsan_label src_neg = do_taint_union(l1, 0, (bvslt << 8) | __dfsan::ICmp,
                                               src_size, orig_op1, 0);
          dfsan_label dst_neg = do_taint_union(label, 0, (bvslt << 8) | __dfsan::ICmp,
                                               size, orig_op1 & new_mask, 0);
          dfsan_label sign_diff = do_taint_union(src_neg, dst_neg, __dfsan::Xor, 1,
                                                 src_sign ? 1 : 0, dst_sign ? 1 : 0);
          __taint_trace_cond(sign_diff, 0, UndefinedCheck, ub_integer_sign_change);
        }
      }
    } else if (op == __dfsan::Add) {
      // check for integer overflow
      // -fsanitize=signed-integer-overflow, unsigned-integer-overflow
      //
      // we only care about l2, which is always symbolic
      const uint64_t mask = size == 64 ? 0xFFFFFFFFFFFFFFFFUL : (1UL << size) - 1;
      uint64_t result = (orig_op1 + orig_op2) & mask;

      // Signed overflow detection:
      // Overflow occurs when ((op1 ^ result) & (op2 ^ result)) has sign bit set
      // This means both operands had same sign, but result has different sign
      uint64_t xor1 = (orig_op1 ^ result) & mask;
      uint64_t xor2 = (orig_op2 ^ result) & mask;
      uint64_t overflow_check = xor1 & xor2;
      uint64_t sign_bit = 1ULL << (size - 1);
      bool has_signed_overflow = (overflow_check & sign_bit) != 0;

      if (!has_signed_overflow) {
        // Build symbolic expression: ((l1 ^ label) & (l2 ^ label)) < 0
        dfsan_label xor_l1 = do_taint_union(l1, label, __dfsan::Xor, size, orig_op1, result);
        dfsan_label xor_l2 = do_taint_union(l2, label, __dfsan::Xor, size, orig_op2, result);
        dfsan_label and_xors = do_taint_union(xor_l1, xor_l2, __dfsan::And, size, xor1, xor2);
        dfsan_label cond = do_taint_union(and_xors, 0, (bvslt << 8) | __dfsan::ICmp,
                                          size, overflow_check, 0);
        __taint_trace_cond(cond, 0, UndefinedCheck, ub_integer_overflow);
      } else {
        AOUT("WARNING: signed integer overflow\n");
        __taint_trace_event_addr(label, EVENT_INT_OVERFLOW, 0, __builtin_return_address(0), 0);
      }

      // Unsigned overflow: result < op1 (for any non-zero op2)
      // When adding two unsigned numbers, overflow means result wrapped around
      if (result >= orig_op1 && (orig_op2 != 0 || l2 != 0)) {
        dfsan_label cond = do_taint_union(label, l1, (bvult << 8) | __dfsan::ICmp,
                                          size, result, orig_op1);
        __taint_trace_cond(cond, 0, UndefinedCheck, ub_integer_overflow);
      }
    } else if (op == __dfsan::Mul) {
      // check for integer overflow
      // we only care about l2, which is always symbolic
      const uint64_t mask = size == 64 ? 0xFFFFFFFFFFFFFFFFUL : (1UL << size) - 1;
      uint64_t result = (orig_op1 * orig_op2) & mask;

      // For multiplication, overflow is harder to detect symbolically
      // Use the approach: if a != 0, then overflow iff result / a != b
      // But we approximate with sign-based check similar to addition
      uint64_t xor1 = (orig_op1 ^ result) & mask;
      uint64_t xor2 = (orig_op2 ^ result) & mask;
      uint64_t overflow_check = xor1 & xor2;
      uint64_t sign_bit = 1ULL << (size - 1);

      // For signed multiplication: check if signs are inconsistent
      // Product of same signs should be positive, different signs should be negative
      // This is an approximation - full check would need wider multiplication
      bool has_signed_overflow = (overflow_check & sign_bit) != 0;

      if (!has_signed_overflow && (orig_op1 != 0 || l1 != 0) && (orig_op2 != 0 || l2 != 0)) {
        dfsan_label xor_l1 = do_taint_union(l1, label, __dfsan::Xor, size, orig_op1, result);
        dfsan_label xor_l2 = do_taint_union(l2, label, __dfsan::Xor, size, orig_op2, result);
        dfsan_label and_xors = do_taint_union(xor_l1, xor_l2, __dfsan::And, size, xor1, xor2);
        dfsan_label cond = do_taint_union(and_xors, 0, (bvslt << 8) | __dfsan::ICmp,
                                          size, overflow_check, 0);
        __taint_trace_cond(cond, 0, UndefinedCheck, ub_integer_overflow);
      } else {
        AOUT("WARNING: signed integer overflow\n");
        __taint_trace_event_addr(label, EVENT_INT_OVERFLOW, 0, __builtin_return_address(0), 0);
      }

      // Unsigned overflow: for multiplication, check if result / op1 != op2 (when op1 != 0)
      // When orig_op1 == 0, no overflow possible concretely (0 * x = 0), but if symbolic, still check
      bool no_unsigned_overflow = (orig_op1 == 0 || result / orig_op1 == orig_op2);
      if (no_unsigned_overflow && (orig_op1 > 1 || l1 != 0) && (orig_op2 > 1 || l2 != 0)) {
          dfsan_label cond = do_taint_union(label, l1, (bvult << 8) | __dfsan::ICmp,
                                            size, result, orig_op1);
          __taint_trace_cond(cond, 0, UndefinedCheck, ub_integer_overflow);
      }
    } else if (op == __dfsan::Sub) {
      // check for integer overflow (underflow for subtraction)
      // -fsanitize=signed-integer-overflow, unsigned-integer-overflow
      const uint64_t mask = size == 64 ? 0xFFFFFFFFFFFFFFFFUL : (1UL << size) - 1;
      uint64_t result = (orig_op1 - orig_op2) & mask;

      // Signed overflow detection for subtraction:
      // Overflow occurs when sign(a) != sign(b) and sign(result) != sign(a)
      // Formula: (a ^ b) & (a ^ result) has sign bit set
      // Examples:
      //   INT_MAX - (-1) = overflow (positive - negative, result should be more positive but wraps)
      //   INT_MIN - 1 = overflow (negative - positive, result should be more negative but wraps)
      uint64_t xor_ab = (orig_op1 ^ orig_op2) & mask;
      uint64_t xor_ar = (orig_op1 ^ result) & mask;
      uint64_t overflow_check = xor_ab & xor_ar;
      uint64_t sign_bit = 1ULL << (size - 1);
      bool has_signed_overflow = (overflow_check & sign_bit) != 0;

      if (!has_signed_overflow) {
        // Build symbolic expression: ((l1 ^ l2) & (l1 ^ label)) < 0
        dfsan_label xor_l1l2 = do_taint_union(l1, l2, __dfsan::Xor, size, orig_op1, orig_op2);
        dfsan_label xor_l1r = do_taint_union(l1, label, __dfsan::Xor, size, orig_op1, result);
        dfsan_label and_xors = do_taint_union(xor_l1l2, xor_l1r, __dfsan::And, size, xor_ab, xor_ar);
        dfsan_label cond = do_taint_union(and_xors, 0, (bvslt << 8) | __dfsan::ICmp,
                                          size, overflow_check, 0);
        __taint_trace_cond(cond, 0, UndefinedCheck, ub_integer_overflow);
      } else {
        AOUT("WARNING: signed integer overflow\n");
        __taint_trace_event_addr(label, EVENT_INT_OVERFLOW, 0, __builtin_return_address(0), 0);
      }

      // Unsigned underflow: result > op1 when op2 > 0
      // When subtracting, if a < b, result wraps around to large value (result > a)
      if (result <= orig_op1 && orig_op2 != 0) {
        dfsan_label cond = do_taint_union(label, l1, (bvugt << 8) | __dfsan::ICmp,
                                          size, result, orig_op1);
        __taint_trace_cond(cond, 0, UndefinedCheck, ub_integer_overflow);
      }
    }
  }
  return label;
}

// If label is zero or kInitializingLabel, return it directly
// If label is bounds (Alloca), return it directly
// If label is a string op, create a new fstr_off label
// If label is other symbolic label, create an Add label with offset
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_gep_offset(dfsan_label label, char* result, char* base) {
  // check label
  if (label == 0 || label == kInitializingLabel)
    return label;

  dfsan_label_info *info = get_label_info(label);

  // concrete ptrs, op == Alloca, just propagate bounds info
  if (info->op == __dfsan::Alloca) {
    return label;
  }

  // symbolic ptrs, record the offset
  int64_t offset = result - base;

  // Check if base_label is or derives from a string op
  dfsan_label str_op_label = taint_find_string_op_source(label);
  if (str_op_label != 0) {
    // string op - create fstr_off label: l1=str_op_label, op1=offset
    // This represents the content at (string_op_position + offset)
    dfsan_label off_label = do_taint_union(str_op_label, 0, __dfsan::fstr_off,
                                           sizeof(void*) * 8,
                                           0, (uint64_t)offset);
    AOUT("str: label=%u, str_op=%u, offset=%ld, result=%u\n",
         label, str_op_label, offset, off_label);

    // record the label (fstr_off is an indexOf-type op)
    taint_set_str_indexof_label(result, off_label);

    return off_label;
  } else if (offset == 0) {
    // no offset, return original label
    return label;
  }

  if (info->size != sizeof(base) * 8) {
    AOUT("WARNING: unexpected size %u for label %u\n", info->size, label);
    return label;
  }

  return do_taint_union(0, label, __dfsan::Add, info->size, (uint64_t)offset, 0);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_union_load(const dfsan_label *ls, uptr n, uint64_t size_in_bits, uint64_t align) {
  if ((uptr)ls < 4096) {
    AOUT("WARNING: nullptr deref\n");
    return 0;
  } else if (((uptr)ls & (align - 1)) != 0) {
    AOUT("WARNING: unaligned load %p\n", ls);
  }
  dfsan_label label0 = ls[0];
  if (label0 == kInitializingLabel) return kInitializingLabel;

  // for debugging
  // dfsan_label l = atomic_load(&__dfsan_last_label, memory_order_relaxed);
  // assert(label0 <= l);
  if (label0 >= CONST_OFFSET) assert(get_label_info(label0)->size != 0);

  // fast path 1: constant and bounds
  if (is_constant_label(label0) || is_kind_of_label(label0, Alloca)) {
    bool same = true;
    for (uptr i = 1; i < n; i++) {
      if (ls[i] == kInitializingLabel) return kInitializingLabel;
      else if (ls[i] != label0) {
        same = false;
        break;
      }
    }
    if (same) return label0;
  }
  AOUT("label0 = %d, n = %lu, ls = %p\n", label0, n, ls);

  // shape
  bool shape = true;
  if (__dfsan_label_info[label0].op != 0) {
    // not raw input bytes
    shape = false;
  } else {
    off_t offset = get_label_info(label0)->op1.i;
    for (uptr i = 1; i != n; ++i) {
      dfsan_label next_label = ls[i];
      if (next_label == kInitializingLabel) return kInitializingLabel;
      else if (get_label_info(next_label)->op1.i != offset + i) {
        shape = false;
        break;
      }
    }
  }
  if (shape) {
    dfsan_label result;
    if (n == 1)
      result = label0;
    else {
      AOUT("shape: label0: %d %lu\n", label0, n);
      result = do_taint_union(label0, (dfsan_label)n, Load, n * 8, 0, 0);
    }
    if (size_in_bits < n * 8)
      result = do_taint_union(result, CONST_LABEL, Trunc, size_in_bits, 0, 0);
    return result;
  }

  // fast path 2: all labels are extracted from a n-size label,
  // then return that label
  if (is_kind_of_label(label0, Extract)) {
    dfsan_label parent = get_label_info(label0)->l1;
    uptr offset = 0;
    for (uptr i = 0; i < n; i++) {
      dfsan_label next_label = ls[i];
      if (next_label == kInitializingLabel) return kInitializingLabel;
      dfsan_label_info *info = get_label_info(next_label);
      if (info->op != Extract || offset != info->op2.i || parent != info->l1) {
        break;
      }
      offset += info->size;
    }
    if (get_label_info(parent)->size == offset && offset == n * 8) {
      AOUT("Fast path (2): all labels are extracts: %u\n", parent);
      if (size_in_bits < n * 8)
        return do_taint_union(parent, CONST_LABEL, Trunc, size_in_bits, 0, 0);
      return parent;
    }
  }

  // slowpath
  AOUT("union load slowpath at %p\n", __builtin_return_address(0));
  dfsan_label label = label0;
  for (uptr i = get_label_info(label0)->size / 8; i < n;) {
    dfsan_label next_label = ls[i];
    if (next_label == kInitializingLabel) return kInitializingLabel;
    uint16_t next_size = get_label_info(next_label)->size;
    AOUT("next label=%u, size=%u\n", next_label, next_size);
    if (!is_constant_label(next_label)) {
      if (next_size <= (n - i) * 8) {
        i += next_size / 8;
        label = do_taint_union(label, next_label, Concat, i * 8, 0, 0);
      } else {
        Report("WARNING: partial loading expected=%lu has=%d\n", n-i, next_size);
        uptr size = n - i;
        dfsan_label trunc = do_taint_union(next_label, CONST_LABEL, Trunc, size * 8, 0, 0);
        dfsan_label result = do_taint_union(label, trunc, Concat, n * 8, 0, 0);
        if (size_in_bits < n * 8)
          result = do_taint_union(result, CONST_LABEL, Trunc, size_in_bits, 0, 0);
        return result;
      }
    } else {
      Report("WARNING: taint mixed with concrete %lu\n", i);
      char *c = (char *)app_for(&ls[i]);
      ++i;
      label = do_taint_union(label, 0, Concat, i * 8, 0, *c);
    }
  }
  AOUT("\n");
  if (size_in_bits < n * 8)
    label = do_taint_union(label, CONST_LABEL, Trunc, size_in_bits, 0, 0);
  return label;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_union_store(dfsan_label l, dfsan_label *ls, uptr n, uint64_t align) {
  //AOUT("label = %d, n = %lu, ls = %p\n", l, n, ls);
  if ((uptr)ls < 4096) {
    AOUT("WARNING: nullptr deref\n");
    return;
  } else if (((uptr)ls & (align - 1)) != 0) {
    AOUT("WARNING: unaligned store %p\n", ls);
  }
  if (l != kInitializingLabel) {
    // for debugging
    dfsan_label h = atomic_load(&__dfsan_last_label, memory_order_relaxed);
    assert(l <= __alloca_stack_bottom);
    if (l > h && l < __alloca_stack_top) {
      AOUT("WARNING: unallocated label %d > %d, and < %d\n",
           l, h, __alloca_stack_top);
    }
  } else {
    for (uptr i = 0; i < n; ++i)
      ls[i] = l;
    return;
  }

  // fast path 1: constant and bounds
  if (l == 0 || is_kind_of_label(l, Alloca)) {
    for (uptr i = 0; i < n; ++i)
      ls[i] = l;
    return;
  }

  dfsan_label_info *info = get_label_info(l);
  // fast path 2: single byte
  if (n == 1 && info->size == 8) {
    ls[0] = l;
    return;
  }

  // fast path 3: load
  if (is_kind_of_label(l, Load)) {
    // if source label is union load, just break it up
    dfsan_label label0 = info->l1;
    if (n > info->l2) {
      Report("WARNING: store size=%lu larger than load size=%d\n", n, info->l2);
    }
    for (uptr i = 0; i < n; ++i)
      ls[i] = label0 + i;
    return;
  }

  // default fall through
  for (uptr i = 0; i < n; ++i) {
    ls[i] = do_taint_union(l, CONST_LABEL, Extract, 8, 0, i * 8);
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __taint_trace_loop_push_stack();
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __taint_trace_loop_pop_stack();

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_push_stack_frame() {
  if (flags().trace_bounds) {
    if (__current_saved_stack_index < MAX_SAVED_STACK_ENTRIES)
      __saved_alloca_stack_top[++__current_saved_stack_index] = __alloca_stack_top;
  }
  __taint_trace_loop_push_stack();
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_pop_stack_frame() {
  if (flags().trace_bounds) {
    __alloca_stack_top = __saved_alloca_stack_top[__current_saved_stack_index--];
  }
  __taint_trace_loop_pop_stack();
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_trace_alloca(dfsan_label l, uint64_t size,
                                 uint64_t elem_size, uint64_t base) {
  if (flags().trace_bounds) {
    __alloca_stack_top -= 1;
    AOUT("label = %d, base = %p, size = %lu, elem_size = %lu\n",
        __alloca_stack_top, (void*)base, size, elem_size);
    dfsan_label_info *info = get_label_info(__alloca_stack_top);
    internal_memset(info, 0, sizeof(dfsan_label_info));
    info->l2    = l;
    info->op    = Alloca;
    info->size  = sizeof(void*) * 8;
    info->op1.i = base;
    info->op2.i = base + size * elem_size;

    // set uninit label
    dfsan_set_label(kInitializingLabel, (void*)base, size * elem_size);

    return __alloca_stack_top;
  } else {
    return 0;
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_trace_global(uint64_t addr, uint64_t size) {
  if (flags().trace_bounds) {
    // setup a hash tree for dedup
    uint32_t h1 = (uint32_t)addr; // lower 32 bits
    uint32_t h2 = (uint32_t)(addr >> 32); // upper 32 bits
    uint32_t hash = xxhash(h1, h2, Alloca);

    struct dfsan_label_info label_info = {
      .l1 = 0, .l2 = 0, .op1 = {addr}, .op2 = {addr + size},
      .op = __dfsan::Alloca, .size = sizeof(void*) * 8, .hash = hash};

    __taint::option res = __union_table.lookup(label_info);
    if (res != __taint::none()) {
      dfsan_label label = *res;
      AOUT("global %u found\n", label);
      return label;
    }

    dfsan_label label =
      atomic_fetch_add(&__dfsan_last_label, 1, memory_order_relaxed) + 1;
    dfsan_check_label(label);
    internal_memcpy(&__dfsan_label_info[label], &label_info, sizeof(dfsan_label_info));
    __union_table.insert(&__dfsan_label_info[label], label);

    AOUT("adding global bounds %d=(%lx, %lu)\n", label, addr, size);

    return label;
  }

  return 0;
}

SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_memerr, dfsan_label, uptr,
                             dfsan_label, uint64_t, uint16_t, void*) {}

// NOTES: for Alloca, or buffer buounds info
// .l1 = num of elements label, for calloc style allocators
// .l2 = (element) size label
// .op1 = lower bounds
// .op2 = upper bounds
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_check_bounds(dfsan_label addr_label, uptr addr,
                          dfsan_label size_label, uint64_t size) {
  if (flags().trace_bounds) {
    void *retaddr = __builtin_return_address(0);
    if (addr == 0) {
      AOUT("WARNING: null ptr deref %p = %d @%p\n", (void*)addr, addr_label, retaddr);
      __taint_trace_memerr(addr_label, addr, size_label, size, F_MEMERR_NULL, retaddr);
      if (flags().exit_on_memerror) Die();
      else return;
    }
    if (addr_label == kInitializingLabel) {
      AOUT("WARNING: uninitialized memory %p = %d @%p\n", (void*)addr, addr_label, retaddr);
      __taint_trace_memerr(addr_label, addr, size_label, size, F_MEMERR_UBI, retaddr);
      if (flags().exit_on_memerror) Die();
      else return;
    }
    dfsan_label_info *info = get_label_info(addr_label);
    if (info->op == __dfsan::Free) {
      // UAF
      AOUT("ERROR: UAF detected %p = %d @%p\n", (void*)addr, addr_label, retaddr);
      __taint_trace_memerr(addr_label, addr, size_label, size, F_MEMERR_UAF, retaddr);
      if (flags().exit_on_memerror) Die();
    } else if (info->op == __dfsan::Alloca) {
      AOUT("addr = %p, lower = %p, upper = %p\n",
           (void*)addr, (void*)info->op1.i, (void*)info->op2.i);
      if (addr < info->op1.i) {
        AOUT("ERROR: OOB underflow detected %p = %d, %lu = %d @%p\n",
             (void*)addr, addr_label, size, size_label, retaddr);
        __taint_trace_memerr(addr_label, addr, size_label, size, F_MEMERR_OLB, retaddr);
        if (flags().exit_on_memerror) Die();
      } else if ((addr + size) > info->op2.i || (addr + size) < info->op1.i) {
        AOUT("ERROR: OOB overflow detected %p = %d, %lu = %d @%p\n",
             (void*)addr, addr_label, size, size_label, __builtin_return_address(0));
        __taint_trace_memerr(addr_label, addr, size_label, size, F_MEMERR_OUB, retaddr);
        if (flags().exit_on_memerror) Die();
      }
    } else if (addr_label != 0) {
      AOUT("WARNING: incorrect label %p = %d @%p\n",
           (void*)addr, addr_label, __builtin_return_address(0));
    }
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_solve_bounds(dfsan_label ptr_label, uint64_t ptr,
                          dfsan_label index_label, int64_t index,
                          uint64_t num_elems, uint64_t elem_size,
                          int64_t current_offset, uint32_t cid) {
  if (index_label == 0 || !flags().solve_ub)
    return;

  void *addr = __builtin_return_address(0);

  if (index_label == kInitializingLabel) {
    // uninitialized label
    AOUT("WARNING: uninitialized label %u @%p\n", index_label, addr);
    __taint_trace_memerr(ptr_label, ptr, index_label, index, F_MEMERR_UBI, addr);
    if (flags().exit_on_memerror) Die();
    else return;
  }
  if (ptr_label == kInitializingLabel) {
    // uninitialized label
    AOUT("WARNING: uninitialized label %u @%p\n", ptr_label, addr);
    __taint_trace_memerr(ptr_label, ptr, index_label, index, F_MEMERR_UBI, addr);
    if (flags().exit_on_memerror) Die();
    else return;
  }

  AOUT("solve bounds: %ld = %d, ne: %ld, es: %ld, offset: %ld\n",
      index, index_label, num_elems, elem_size, current_offset);

  // construct bounds solving tasks here
  uint16_t index_bits = get_label_info(index_label)->size;
  if (num_elems > 0) {
    // array with known size
    //
    // check underflow, index < 0
    dfsan_label lb = do_taint_union(index_label, 0, (bvslt << 8) | ICmp,
                                    index_bits, index, 0);
    // assume the result is false, as bounds check should happen before solving
    // no flag, no nested
    __taint_trace_cond(lb, 0, UndefinedCheck, ub_index_underflow);

    // check overflow, index >= num_elems
    dfsan_label ub = do_taint_union(index_label, 0, (bvsge << 8) | ICmp,
                                    index_bits, index, num_elems);
    __taint_trace_cond(ub, 0, UndefinedCheck, ub_index_overflow);
  } else {
    // array with unknown size
    dfsan_label_info *bounds_info = get_label_info(ptr_label);
    if (bounds_info->op == __dfsan::Alloca) {
      // bounds information is available, check if allocation size is symbolic
      if (index_bits < 64) // extends index to 64 bits
        index_label = do_taint_union(index_label, 0, ZExt, 64, index, 0);
      if (bounds_info->l2 == 0) {
        // concrete allocation size, check bounds
        // check underflow, index * elem_size + current_offset + ptr < lower_bound
        // => index < (lower_bound - current_offset - ptr) / elem_size
        uint64_t lower_bound =
            (bounds_info->op1.i - current_offset - ptr) / elem_size;
        dfsan_label lb = do_taint_union(index_label, 0, (bvult << 8) | ICmp,
                                        64, index, lower_bound);
        __taint_trace_cond(lb, 0, UndefinedCheck, ub_index_underflow);

        // check overflow, (index + 1) * elem_size + current_offset + ptr > upper_bound
        // => index > (upper_bound - current_offset - ptr) / elem_size - 1
        uint64_t upper_bound =
            (bounds_info->op2.i - current_offset - ptr) / elem_size - 1;
        dfsan_label ub = do_taint_union(index_label, 0, (bvugt << 8) | ICmp,
                                        64, index, upper_bound);
        __taint_trace_cond(ub, 0, UndefinedCheck, ub_index_overflow);
      } else {
        // index * elem_size + current_offset + (ptr - lower_bound) > array_size * alloc_elem_size
        dfsan_label size_label = elem_size == 1 ? index_label :
            do_taint_union(index_label, 0, Mul, 64, index, elem_size);
        uint64_t size = index * elem_size;
        uint64_t offset = current_offset + ptr - bounds_info->op1.i;
        size_label = offset == 0 ? size :
            do_taint_union(size_label, 0, Add, 64, size, offset);
        size += offset;
        uint64_t alloc_size = bounds_info->op2.i - bounds_info->op1.i;
        dfsan_label overflow =
            do_taint_union(size_label, bounds_info->l2, (bvugt << 8) | ICmp,
                           64, size, alloc_size);
        __taint_trace_cond(overflow, 0, UndefinedCheck, ub_integer_to_buffer_overflow);
      }
    } else {
      // symbolic pointer but no bounds info?
      AOUT("WARNING: symbolic pointer %p = %u with no bounds info @%p\n",
           (void*)ptr, ptr_label, addr);
      // FIXME: check if null is possible?
      // dfsan_label null = do_taint_union(ptr_label, 0, bveq, 64, ptr, 0);
      // __taint_trace_cond(null, 0, UndefinedCheck, ub_null_pointer);
    }
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_solve_size(dfsan_label ptr_label, uint64_t ptr,
                        dfsan_label size_label, uint64_t size,
                        uint32_t cid) {
  if (!flags().solve_ub)
    return;

  void *addr = __builtin_return_address(0);

  if (size_label == kInitializingLabel) {
    // uninitialized label
    AOUT("WARNING: uninitialized size label %u @%p\n", size_label, addr);
    __taint_trace_memerr(ptr_label, ptr, size_label, size, F_MEMERR_UBI, addr);
    if (flags().exit_on_memerror) Die();
    else return;
  }
  if (ptr_label == kInitializingLabel) {
    // uninitialized label
    AOUT("WARNING: uninitialized pointer label %u @%p\n", ptr_label, addr);
    __taint_trace_memerr(ptr_label, ptr, size_label, size, F_MEMERR_UBI, addr);
    if (flags().exit_on_memerror) Die();
    else return;
  }

  AOUT("solve size: %lu = %d, ptr: %p = %d\n",
      size, size_label, (void*)ptr, ptr_label);

  // construct size solving tasks here
  uint16_t size_bits = 64; // Default to 64 bits
  if (size_label != 0) {
    size_bits = get_label_info(size_label)->size;
  }

  // check overflow with buffer bounds if ptr has bounds info
  if (ptr_label != 0) {
    dfsan_label_info *bounds_info = get_label_info(ptr_label);
    if (bounds_info->op == __dfsan::Alloca) {
      // bounds information is available
      if (size_bits < 64) // extend size to 64 bits
        size_label = do_taint_union(size_label, 0, ZExt, 64, size, 0);

      if (bounds_info->l2 == 0) {
        // concrete allocation size
        if (size_label == 0) {
          // concrete size, concrete allocation size, nothing to solve
          return;
        }
        // check underflow: ptr + size < lower_bound (wrap around)
        // => size < lower_bound - ptr (when lower_bound > ptr, but this shouldn't happen in valid code)
        // or equivalently, check that ptr < lower_bound (shouldn't happen)
        uint64_t min_size = bounds_info->op1.i - ptr;
        dfsan_label underflow = do_taint_union(size_label, 0, (bvult << 8) | ICmp,
                                               64, size, min_size);
        __taint_trace_cond(underflow, 0, UndefinedCheck, ub_size_underflow);

        // check overflow: ptr + size > upper_bound
        // => size > upper_bound - ptr
        uint64_t max_size = bounds_info->op2.i - ptr;
        dfsan_label overflow = do_taint_union(size_label, 0, (bvugt << 8) | ICmp,
                                              64, size, max_size);
        __taint_trace_cond(overflow, 0, UndefinedCheck, ub_size_overflow);
      } else {
        // symbolic allocation size
        // check: size > alloc_size
        uint64_t offset = ptr - bounds_info->op1.i;
        uint64_t alloc_size = bounds_info->op2.i - bounds_info->op1.i;
        dfsan_label adjusted_size = (offset == 0 || size_label == 0) ? size_label :
            do_taint_union(size_label, 0, Add, 64, size, offset);
        uint64_t actual_size = size + offset;
        dfsan_label overflow = do_taint_union(adjusted_size, bounds_info->l2,
                                              (bvugt << 8) | ICmp, 64,
                                              actual_size, alloc_size);
        __taint_trace_cond(overflow, 0, UndefinedCheck, ub_size_to_buffer_overflow);
      }
    } else if (ptr_label != 0) {
      // symbolic pointer but no bounds info
      AOUT("WARNING: symbolic pointer %p = %u with no bounds info @%p\n",
           (void*)ptr, ptr_label, addr);
      // FIXME: check if null is possible
      // dfsan_label null = do_taint_union(ptr_label, 0, bveq, 64, ptr, 0);
      // __taint_trace_cond(null, 0, UndefinedCheck, ub_null_pointer);
    }
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_solve_str_bounds(const char *str_ptr,
                              dfsan_label buf_label, uint64_t buf_ptr,
                              uint64_t step) {
  if (!flags().solve_ub)
    return;

  size_t len = strlen(str_ptr);
  AOUT("solve_str_bounds: str_ptr=%p, strlen=%zu, buf_label=%u, buf_ptr=%p, step=%lu\n",
       str_ptr, len, buf_label, (void*)buf_ptr, step);
  bool tainted_zero = false;
  if (len == 0) {
    const dfsan_label *sp = shadow_for(str_ptr);
    AOUT("solve_str_bounds: strlen==0, shadow[0]=%u\n", sp[0]);
    if (sp[0] == 0)
      return;
    len = 1;
    while (sp[len] != 0)
      len++;
    tainted_zero = true;
    AOUT("solve_str_bounds: tainted extent=%zu\n", len);
  }

  dfsan_label str_label = dfsan_read_label(str_ptr, len + 1);
  AOUT("solve_str_bounds: str_label=%u\n", str_label);
  if (str_label == 0)
    return;

  dfsan_label null_label = dfsan_read_label(str_ptr + len, 1);
  bool null_from_input = (null_label != 0 || tainted_zero);

  dfsan_label strlen_label = do_taint_union(0, str_label, fstrlen,
                                            64, null_from_input ? 1 : 0, len);

  uint64_t total = len;
  if (step > 1) {
    strlen_label = do_taint_union(strlen_label, 0, Mul, 64, len, step);
    total = len * step;
  }

  AOUT("solve str bounds: strlen=%zu, step=%lu, total=%lu, buf=%p, buf_label=%u\n",
       len, step, total, (void*)buf_ptr, buf_label);

  // Concrete OOB detection (same as __taint_check_bounds)
  __taint_check_bounds(buf_label, buf_ptr, 0, total);

  // Symbolic solving
  __taint_solve_size(buf_label, buf_ptr, strlen_label, total, 0);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void dfsan_store_label(dfsan_label l, void *addr, uptr size) {
  if (l == 0) return;
  __taint_union_store(l, shadow_for(addr), size, sizeof(dfsan_label));
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __dfsan_unimplemented(char *fname) {
  if (flags().warn_unimplemented)
    Report("WARNING: DataFlowSanitizer: call to uninstrumented function %s\n",
           fname);

}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __dfsan_wrapper_extern_weak_null(
    const void *addr, char *fname) {
  if (!addr)
    Report(
        "ERROR: DataFlowSanitizer: dfsan generated wrapper calling null "
        "extern_weak function %s\nIf this only happens with dfsan, the "
        "dfsan instrumentation pass may be accidentally optimizing out a "
        "null check\n",
        fname);
}

// Use '-mllvm -dfsan-debug-nonzero-labels' and break on this function
// to try to figure out where labels are being introduced in a nominally
// label-free program.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __dfsan_nonzero_label() {
  if (flags().warn_nonzero_labels)
    Report("WARNING: DataFlowSanitizer: saw nonzero label\n");
}

// Indirect call to an uninstrumented vararg function. We don't have a way of
// handling these at the moment.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__dfsan_vararg_wrapper(const char *fname) {
  Report("FATAL: DataFlowSanitizer: unsupported indirect call to vararg "
         "function %s\n", fname);
  Die();
}

// Like __dfsan_union, but for use from the client or custom functions.  Hence
// the equality comparison is done here before calling __dfsan_union.
SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
dfsan_union(dfsan_label l1, dfsan_label l2, uint16_t op, uint16_t size,
            uint64_t op1, uint64_t op2) {
  return __taint_union(l1, l2, op, size, op1, op2);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label dfsan_create_label(uint64_t input_id, uint64_t offset, uint32_t size_in_bytes) {
  dfsan_label label =
    atomic_fetch_add(&__dfsan_last_label, 1, memory_order_relaxed) + 1;
  dfsan_check_label(label);
  AOUT("creating label %u: input %lu, offset %lu, size %u\n",
       label, input_id, offset, size_in_bytes);
  internal_memset(&__dfsan_label_info[label], 0, sizeof(dfsan_label_info));
  __dfsan_label_info[label].size = 8 * size_in_bytes;
  __dfsan_label_info[label].op1.i = offset;
  __dfsan_label_info[label].op2.i = input_id;
  // init a non-zero hash
  __dfsan_label_info[label].hash = xxhash(offset, input_id, 8);
  return label;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __dfsan_set_label(dfsan_label label, void *addr, uptr size) {
  if (addr == 0) return;
  for (dfsan_label *labelp = shadow_for(addr); size != 0; --size, ++labelp) {
    // Don't write the label if it is already the value we need it to be.
    // In a program where most addresses are not labeled, it is common that
    // a page of shadow memory is entirely zeroed.  The Linux copy-on-write
    // implementation will share all of the zeroed pages, making a copy of a
    // page when any value is written.  The un-sharing will happen even if
    // the value written does not change the value in memory.  Avoiding the
    // write when both |label| and |*labelp| are zero dramatically reduces
    // the amount of real memory used by large programs.
    if (label == *labelp)
      continue;

    // AOUT("%p = %u\n", addr, label);
    *labelp = label;
  }
}

SANITIZER_INTERFACE_ATTRIBUTE
void dfsan_set_label(dfsan_label label, void *addr, uptr size) {
  __dfsan_set_label(label, addr, size);
}

SANITIZER_INTERFACE_ATTRIBUTE
void dfsan_add_label(dfsan_label label, uint8_t op, void *addr, uptr size) {
  return; // not used, do nothing
}

// Unlike the other dfsan interface functions the behavior of this function
// depends on the label of one of its arguments.  Hence it is implemented as a
// custom function.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
__dfsw_dfsan_get_label(long data, dfsan_label data_label,
                       dfsan_label *ret_label) {
  *ret_label = 0;
  return data_label;
}

SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
dfsan_read_label(const void *addr, uptr size) {
  if (size == 0)
    return 0;
  dfsan_label label =
      __taint_union_load(shadow_for(addr), size, size * 8, sizeof(dfsan_label));
  // __taint_union_load hands kInitializingLabel back to instrumented loads on
  // purpose: it is the marker __taint_trace_alloca writes over an alloca's
  // shadow, and propagating it is how a load of never-written stack memory
  // stays flagged.  It is not a label, though, and this is the entry point the
  // custom wrappers read shadow through.  They pass what they get straight to
  // dfsan_get_label_info(), whose dfsan_check_label() reports
  // "FATAL: Taint: out of labels" and Die()s -- losing the entire trace from
  // there on, over a buffer that merely had an unwritten tail.  A range that
  // includes uninitialized bytes has no label; say that instead.
  if (label == kInitializingLabel)
    return 0;
  return label;
}

SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
dfsan_get_label(const void *addr) {
  return *shadow_for(addr);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label_info *dfsan_get_label_info(dfsan_label label) {
  dfsan_check_label(label);
  return &__dfsan_label_info[label];
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE int
dfsan_has_label(dfsan_label label, dfsan_label elem) {
  if (label == kInitializingLabel || elem == kInitializingLabel) return false;
  if (label == elem)
    return true;
  const dfsan_label_info *info = dfsan_get_label_info(label);
  if (info->l1 != 0) {
    return dfsan_has_label(info->l1, elem);
  }
  if (info->l2 != 0) {
    return dfsan_has_label(info->l2, elem);
  } 
  return false;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE uptr
dfsan_get_label_count(void) {
  dfsan_label max_label_allocated =
      atomic_load(&__dfsan_last_label, memory_order_relaxed);

  return static_cast<uptr>(max_label_allocated);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
dfsan_dump_labels(int fd) {
  dfsan_label last_label =
      atomic_load(&__dfsan_last_label, memory_order_relaxed);

  for (dfsan_label l = 1; l <= last_label; ++l) {
    char buf[64];
    internal_snprintf(buf, sizeof(buf), "%u (%u %u %u %u)", l,
                      __dfsan_label_info[l].l1, __dfsan_label_info[l].l2,
                      __dfsan_label_info[l].op, __dfsan_label_info[l].size);
    WriteToFile(fd, buf, internal_strlen(buf));
    WriteToFile(fd, "\n", 1);
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_debug(dfsan_label op1, dfsan_label op2, int predicate,
              uint32_t size, uint32_t target) {
  if (op1 == 0 && op2 == 0) return;
}

SANITIZER_INTERFACE_ATTRIBUTE void
taint_set_file(int dirfd, const char *filename, int fd) {
  char path[PATH_MAX];
  if (dirfd != AT_FDCWD) {
    // only resolve dirfd if not CWD
    ssize_t len = readlinkat(dirfd, filename, path, sizeof(path));
    if (len < 0) {
      AOUT("WARNING: readlinkat failed %s\n", filename);
      return;
    }
    path[len] = '\0';
  }
  realpath(filename, path);
  if (internal_strcmp(tainted.filename, path) == 0) {
    tainted.fd = fd;
    AOUT("fd:%d created\n", fd);
  }
}

SANITIZER_INTERFACE_ATTRIBUTE int
is_taint_file(const char *filename) {
  char path[PATH_MAX];
  realpath(filename, path);
  if (internal_strcmp(tainted.filename, path) == 0) {
    tainted.is_utmp = 1;
    return 1;
  }
  tainted.is_utmp = 0;
  return 0;
}

SANITIZER_INTERFACE_ATTRIBUTE off_t
taint_get_file(int fd) {
  AOUT("fd: %d\n", fd);
  AOUT("tainted.fd: %d\n", tainted.fd);
  if (tainted.fd == fd) {
    return tainted.size;
  } else if (flags().force_stdin && fd == 0) {
    return tainted.size;
  } else {
    return 0;
  }
}

SANITIZER_INTERFACE_ATTRIBUTE void
taint_close_file(int fd) {
  if (fd == tainted.fd) {
    AOUT("close tainted.fd: %d\n", tainted.fd);
    tainted.fd = -1;
  }
}

SANITIZER_INTERFACE_ATTRIBUTE int
is_stdin_taint(void) {
  return tainted.is_stdin;
}

// for utmp interface
SANITIZER_INTERFACE_ATTRIBUTE int
is_utmp_taint(void) {
  return tainted.is_utmp;
}

SANITIZER_INTERFACE_ATTRIBUTE void
set_utmp_offset(off_t offset) {
  tainted.offset = offset;
}

SANITIZER_INTERFACE_ATTRIBUTE off_t
get_utmp_offset() {
  return tainted.offset;
}

SANITIZER_INTERFACE_ATTRIBUTE void
taint_set_offset_label(dfsan_label label) {
  tainted.offset_label = label;
}

SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
taint_get_offset_label() {
  return tainted.offset_label;
}

SANITIZER_INTERFACE_ATTRIBUTE void
taint_set_socket(const void *addr, unsigned addrlen, int fd) {
  const struct sockaddr *sa = (struct sockaddr *)addr;
  AOUT("taint host %s:%d\n", tainted_socket.host, tainted_socket.port);
  if (sa->sa_family != tainted_socket.family) return;

  if (sa->sa_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)sa;
    if (tainted_socket.port != ntohs(sin->sin_port)) return;
    struct in_addr addr;
    inet_pton(AF_INET, tainted_socket.host, &addr);
    if (addr.s_addr != sin->sin_addr.s_addr) return;
    // family, port, and address match
    AOUT("taint sockfd %d\n", fd);
    tainted_socket.fd = fd;
  } else if (sa->sa_family == AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
    if (tainted_socket.port != ntohs(sin6->sin6_port)) return;
    struct in6_addr addr;
    inet_pton(AF_INET6, tainted_socket.host, &addr);
    if (internal_memcmp(&addr, &sin6->sin6_addr, sizeof(addr)) != 0) return;
    // family, port, and address match
    AOUT("taint sockfd %d\n", fd);
    tainted_socket.fd = fd;
  } else if (sa->sa_family == AF_UNIX) {
    struct sockaddr_un *sun = (struct sockaddr_un *)sa;
    if (internal_strncmp(tainted_socket.host, sun->sun_path, sizeof(tainted_socket.host)) == 0) {
      AOUT("taint sockfd %d\n", fd);
      tainted_socket.fd = fd;
    }
  }
}

SANITIZER_INTERFACE_ATTRIBUTE off_t
taint_get_socket(int fd) {
  if (tainted_socket.fd == fd) {
    return tainted_socket.offset;
  } else if (flags().force_stdin) {
    return tainted_socket.offset;
  } else {
    return -1;
  }
}

SANITIZER_INTERFACE_ATTRIBUTE void
taint_update_socket_offset(int fd, size_t size) {
  if (tainted_socket.fd == fd)
    tainted_socket.offset += size;
}

SANITIZER_INTERFACE_ATTRIBUTE void
taint_close_socket(int fd) {
  if (tainted_socket.fd == fd) {
    AOUT("close tainted_socket.fd: %d\n", tainted_socket.fd);
    tainted_socket.fd = -1;
  }
}

void Flags::SetDefaults() {
#define DFSAN_FLAG(Type, Name, DefaultValue, Description) Name = DefaultValue;
#include "dfsan_flags.inc"
#undef DFSAN_FLAG
}

static void RegisterDfsanFlags(FlagParser *parser, Flags *f) {
#define DFSAN_FLAG(Type, Name, DefaultValue, Description) \
  RegisterFlag(parser, #Name, Description, &f->Name);
#include "dfsan_flags.inc"
#undef DFSAN_FLAG
}

static void InitializeTaintFile() {
  struct stat st;
  const char *filename = flags().taint_file;
  int err;
  if (internal_strcmp(filename, "stdin") == 0) {
    tainted.fd = 0;
    // try to get the size, as stdin may be a file
    if (!fstat(0, &st) && S_ISREG(st.st_mode)) {
      tainted.size = st.st_size;
      tainted.is_stdin = 0;
      // map a copy
      tainted.buf_size = RoundUpTo(st.st_size, GetPageSizeCached());
      uptr map = internal_mmap(nullptr, tainted.buf_size, PROT_READ, MAP_PRIVATE, 0, 0);
      if (internal_iserror(map, &err)) {
        Printf("FATAL: failed to map a copy of input file %s\n", strerror(err));
        Die();
      }
      tainted.buf = reinterpret_cast<char *>(map);
    } else {
      tainted.size = 1;
      tainted.is_stdin = 1; // truly stdin
    }
  } else if (internal_strcmp(filename, "") == 0) {
    tainted.fd = -1;
  } else {
    if (!realpath(filename, tainted.filename)) {
      Report("WARNING: failed to get to real path for taint file\n");
      return;
    }
    stat(filename, &st);
    tainted.size = st.st_size;
    tainted.is_stdin = 0;
    // map a copy
    tainted.buf = static_cast<char *>(
      MapFileToMemory(filename, &tainted.buf_size));
    if (tainted.buf == nullptr) {
      Printf("FATAL: failed to map a copy of input file\n");
      Die();
    }
    AOUT("%s %ld size\n", filename, tainted.size);
  }

  if (tainted.fd != -1 && !tainted.is_stdin) {
    for (off_t i = 0; i < tainted.size; i++) {
      dfsan_label label = dfsan_create_label(0, i, 1);
      dfsan_check_label(label);
    }
  }
}

static void InitializeTaintSocket() {
  const char *host = flags().taint_socket;
  internal_memset(tainted_socket.host, 0, sizeof(tainted_socket.host));
  tainted_socket.family = -1;
  tainted_socket.port = -1;
  tainted_socket.fd = -1;
  if (internal_strstr(host, "tcp@") == host || internal_strstr(host, "udp@") == host) {
    char *port = internal_strchr(host + 4, '@');
    if (port) {
      tainted_socket.family = AF_INET;
      size_t addr_len = (uptr)port - (uptr)host - 4;
      internal_memcpy(tainted_socket.host, host + 4, addr_len);
      tainted_socket.host[addr_len] = '\0';
      tainted_socket.port = atoi(port + 1);
    } else {
      Report("FATAL: invalid inet socket %s\n", host);
      Die();
    }
  } else if (internal_strstr(host, "tcp6@") == host || internal_strstr(host, "udp6@") == host) {
    char *port = internal_strchr(host + 5, '@');
    if (port) {
      tainted_socket.family = AF_INET6;
      size_t addr_len = (uptr)port - (uptr)host - 5;
      internal_memcpy(tainted_socket.host, host + 5, addr_len);
      tainted_socket.host[addr_len] = '\0';
      tainted_socket.port = atoi(port + 1);
    } else {
      Report("FATAL: invalid inet6 socket %s\n", host);
      Die();
    }
  } else if (internal_strstr(host, "unix@") == host) {
    tainted_socket.family = AF_UNIX;
    uptr len = internal_strlen(host + 5);
    if (len < sizeof(tainted_socket.host)) {
      internal_memcpy(tainted_socket.host, host + 5, len);
    } else {
      Report("FATAL: invalid unix socket %s\n", host);
      Die();
    }
  } else if (internal_strcmp(host, "")) {
    Report("FATAL: unsupported taint socket %s\n", host);
    Die();
  }
}

// Hash tables for string label tracking
static uptr content_map_capacity = 0;
static struct {
  uptr addr;
  dfsan_label label;
} *__taint_content_map = nullptr;
static uptr content_map_count = 0;

static uptr indexof_map_capacity = 0;
static struct {
  uptr addr;
  dfsan_label label;
} *__taint_indexof_map = nullptr;
static uptr indexof_map_count = 0;

// Hash function optimized for shadow memory addresses (0x700000040000 ~ 0x800000000000)
// Focus on middle bits where entropy is highest
static inline uptr hash_addr(uptr addr, uptr capacity) {
  addr >>= 3;  // Remove low 3 bits (8-byte alignment)
  addr *= 2654435769UL;  // Multiplicative hash
  return addr & (capacity - 1);  // Fast modulo for power-of-2
}

// Grow content map when load factor exceeds 0.7
static void grow_content_map() {
  uptr new_capacity = content_map_capacity * 2;
  uptr new_size = RoundUpTo(new_capacity * sizeof(*__taint_content_map), GetPageSizeCached());
  typeof(__taint_content_map) new_map = (typeof(__taint_content_map))MmapOrDie(
      new_size, "taint_content_map");

  // Rehash existing entries
  for (uptr i = 0; i < content_map_capacity; i++) {
    if (__taint_content_map[i].addr != 0) {
      uptr hash = hash_addr(__taint_content_map[i].addr, new_capacity);
      while (new_map[hash].addr != 0) {
        hash = (hash + 1) & (new_capacity - 1);
      }
      new_map[hash] = __taint_content_map[i];
    }
  }

  uptr old_size = RoundUpTo(content_map_capacity * sizeof(*__taint_content_map), GetPageSizeCached());
  UnmapOrDie(__taint_content_map, old_size);
  __taint_content_map = new_map;
  content_map_capacity = new_capacity;
}

// Grow indexOf map
static void grow_indexof_map() {
  uptr new_capacity = indexof_map_capacity * 2;
  uptr new_size = RoundUpTo(new_capacity * sizeof(*__taint_indexof_map), GetPageSizeCached());
  typeof(__taint_indexof_map) new_map = (typeof(__taint_indexof_map))MmapOrDie(
      new_size, "taint_indexof_map");

  for (uptr i = 0; i < indexof_map_capacity; i++) {
    if (__taint_indexof_map[i].addr != 0) {
      uptr hash = hash_addr(__taint_indexof_map[i].addr, new_capacity);
      while (new_map[hash].addr != 0) {
        hash = (hash + 1) & (new_capacity - 1);
      }
      new_map[hash] = __taint_indexof_map[i];
    }
  }

  uptr old_size = RoundUpTo(indexof_map_capacity * sizeof(*__taint_indexof_map), GetPageSizeCached());
  UnmapOrDie(__taint_indexof_map, old_size);
  __taint_indexof_map = new_map;
  indexof_map_capacity = new_capacity;
}

static void InitializeStringMaps() {
  // Round up to nearest power of 2 for efficient hashing
  uptr capacity = flags().string_map_capacity;
  if (capacity < 16) capacity = 16;  // Minimum size
  // Round up to power of 2
  capacity--;
  capacity |= capacity >> 1;
  capacity |= capacity >> 2;
  capacity |= capacity >> 4;
  capacity |= capacity >> 8;
  capacity |= capacity >> 16;
  capacity |= capacity >> 32;
  capacity++;

  // Content map
  content_map_capacity = capacity;
  __taint_content_map = (typeof(__taint_content_map))MmapOrDie(
      RoundUpTo(content_map_capacity * sizeof(*__taint_content_map), GetPageSizeCached()),
      "taint_content_map");
  content_map_count = 0;

  // IndexOf map
  indexof_map_capacity = capacity;
  __taint_indexof_map = (typeof(__taint_indexof_map))MmapOrDie(
      RoundUpTo(indexof_map_capacity * sizeof(*__taint_indexof_map), GetPageSizeCached()),
      "taint_indexof_map");
  indexof_map_count = 0;
}

extern "C" void taint_set_str_content_label(void *addr, dfsan_label label) {
  AOUT("taint_set_str_content_label: addr=%p, label=%u\n", addr, label);

  // Grow if needed
  if (content_map_count > (content_map_capacity * 7 / 10)) {
    grow_content_map();
  }

  uptr hash = hash_addr((uptr)addr, content_map_capacity);

  // Linear probing
  while (__taint_content_map[hash].addr != 0 &&
         __taint_content_map[hash].addr != (uptr)addr) {
    hash = (hash + 1) & (content_map_capacity - 1);
  }

  if (__taint_content_map[hash].addr == 0) {
    content_map_count++;
  } else {
    AOUT("update content label: old = %u\n", __taint_content_map[hash].label);
  }

  __taint_content_map[hash].addr = (uptr)addr;
  __taint_content_map[hash].label = label;
}

extern "C" dfsan_label taint_get_str_content_label(const void *addr) {
  uptr hash = hash_addr((uptr)addr, content_map_capacity);
  uptr start = hash;

  while (__taint_content_map[hash].addr != 0) {
    if (__taint_content_map[hash].addr == (uptr)addr) {
      AOUT("taint_get_str_content_label: addr=%p, found label=%u\n",
           addr, __taint_content_map[hash].label);
      return __taint_content_map[hash].label;
    }
    hash = (hash + 1) & (content_map_capacity - 1);
    if (hash == start) break;
  }
  AOUT("addr=%p, not found\n", addr);
  return 0;
}

extern "C" void taint_set_str_indexof_label(void *addr, dfsan_label label) {
  AOUT("taint_set_str_indexof_label: addr=%p, label=%u\n", addr, label);

  if (indexof_map_count > (indexof_map_capacity * 7 / 10)) {
    grow_indexof_map();
  }

  uptr hash = hash_addr((uptr)addr, indexof_map_capacity);

  while (__taint_indexof_map[hash].addr != 0 &&
         __taint_indexof_map[hash].addr != (uptr)addr) {
    hash = (hash + 1) & (indexof_map_capacity - 1);
  }

  if (__taint_indexof_map[hash].addr == 0) {
    indexof_map_count++;
  } else {
    AOUT("update indexof label: old = %u\n", __taint_indexof_map[hash].label);
  }

  __taint_indexof_map[hash].addr = (uptr)addr;
  __taint_indexof_map[hash].label = label;
}

extern "C" dfsan_label taint_get_str_indexof_label(const void *addr) {
  uptr hash = hash_addr((uptr)addr, indexof_map_capacity);
  uptr start = hash;

  while (__taint_indexof_map[hash].addr != 0) {
    if (__taint_indexof_map[hash].addr == (uptr)addr) {
      AOUT("addr=%p, found label=%u\n", addr, __taint_indexof_map[hash].label);
      return __taint_indexof_map[hash].label;
    }
    hash = (hash + 1) & (indexof_map_capacity - 1);
    if (hash == start) break;
  }
  AOUT("addr=%p, not found\n", addr);
  return 0;
}

// Helper: Find if a label derives from a string op (fstrchr, fstrrchr, fstrstr)
// by walking through PtrToInt, Sub, Add operations.
// Returns the string op label if found, 0 otherwise.
extern "C" dfsan_label taint_find_string_op_source(dfsan_label label) {
  if (label < CONST_OFFSET) return 0;

  dfsan_label_info *info = dfsan_get_label_info(label);
  uint16_t op = info->op;

  // Check if this is directly a string op
  if (is_string_op(op)) {
    return label;
  }

  // Follow through PtrToInt, Sub, Add to find the source string op
  if (op == __dfsan::PtrToInt || op == __dfsan::Sub || op == __dfsan::Add) {
    // Recursively check l1 (the primary operand)
    if (info->l1 >= CONST_OFFSET) {
      dfsan_label result = taint_find_string_op_source(info->l1);
      if (result != 0) return result;
    }
    // For Sub/Add, also check l2
    if ((op == __dfsan::Sub || op == __dfsan::Add) && info->l2 >= CONST_OFFSET) {
      dfsan_label result = taint_find_string_op_source(info->l2);
      if (result != 0) return result;
    }
  }

  return 0;
}

// Helper: Find the first (base) input byte label from a content label.
// Walks through Concat chains and Load operations to find the starting input.
// Returns the base label, or 0 if not found.
extern "C" dfsan_label taint_get_base_input_label(dfsan_label label) {
  if (label < CONST_OFFSET) return 0;

  dfsan_label_info *info = dfsan_get_label_info(label);

  // Base input label has op == 0
  if (info->op == 0) return label;

  // For Concat (op 72), walk left (l1) to find the base
  if (info->op == __dfsan::Concat) {
    return taint_get_base_input_label(info->l1);
  }

  // For Load (op 32), l1 is the starting label
  if (info->op == __dfsan::Load) {
    return info->l1;
  }

  // For other ops, try l1
  if (info->l1 >= CONST_OFFSET) {
    return taint_get_base_input_label(info->l1);
  }

  return 0;
}

// information is passed implicitly through flags()
extern "C" void InitializeSymSanSolver();
extern "C" void InitializeSymSanForkServer();

static void InitializeFlags() {
  SetCommonFlagsDefaults();
  flags().SetDefaults();

  FlagParser parser;
  RegisterCommonFlags(&parser);
  RegisterDfsanFlags(&parser, &flags());
  parser.ParseString(GetEnv("TAINT_OPTIONS"));
  InitializeCommonFlags();
  if (Verbosity()) ReportUnrecognizedFlags();
  if (common_flags()->help) parser.PrintFlagDescriptions();
}

static void InitializePlatformEarly() {
  AvoidCVE_2016_2143();
#ifdef DFSAN_RUNTIME_VMA
  __dfsan::vmaSize =
    (MostSignificantSetBitIndex(GET_CURRENT_FRAME()) + 1);
  if (__dfsan::vmaSize == 39 || __dfsan::vmaSize == 42 ||
      __dfsan::vmaSize == 48) {
    __dfsan_shadow_ptr_mask = ShadowMask();
  } else {
    Printf("FATAL: DataFlowSanitizer: unsupported VMA range\n");
    Printf("FATAL: Found %d - Supported 39, 42, and 48\n", __dfsan::vmaSize);
    Die();
  }
#endif
}

static void dfsan_fini() {
  if (internal_strcmp(flags().dump_labels_at_exit, "") != 0) {
    fd_t fd = OpenFile(flags().dump_labels_at_exit, WrOnly);
    if (fd == kInvalidFd) {
      Report("WARNING: DataFlowSanitizer: unable to open output file %s\n",
             flags().dump_labels_at_exit);
      return;
    }

    Report("INFO: DataFlowSanitizer: dumping labels to %s\n",
           flags().dump_labels_at_exit);
    dfsan_dump_labels(fd);
    CloseFile(fd);
  }
  if (tainted.buf) {
    UnmapOrDie(tainted.buf, tainted.buf_size);
  }
  if (flags().shm_fd != -1 || internal_strcmp(flags().shm_name, "") != 0) {
    internal_munmap((void *)UnionTableAddr(), uniontable_size);
  }
}

static bool dfsan_initialized;

static void dfsan_init(int argc, char **argv, char **envp) {
  if (dfsan_initialized)
    return;
  dfsan_initialized = true;

  InitializeFlags();
  print_debug = flags().debug;

  ::InitializePlatformEarly();
  uptr ret;
  int err;
  ret = MmapFixedSuperNoReserve(ShadowAddr(), UnionTableAddr() - ShadowAddr());
  if (internal_iserror(ret, &err)) {
    Printf("FATAL: error mapping shadow %s\n", strerror(err));
    Die();
  }

  // init union table
  __dfsan_label_info = (dfsan_label_info *)UnionTableAddr();
  if (flags().shm_size != 0) {
    if (flags().shm_size > minimum_uniontable_size) {
      uniontable_size = flags().shm_size;
    } else {
      Report("Warning: shm_size %zu is smaller than minimum %zu\n",
             flags().shm_size, minimum_uniontable_size);
      // use the default size
    }
  }
  if (flags().shm_fd != -1) {
    AOUT("shm_fd %d\n", flags().shm_fd);
    ret = internal_mmap((void*)UnionTableAddr(), uniontable_size,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, flags().shm_fd, 0);
  } else if (internal_strcmp(flags().shm_name, "")  != 0) {
    int shm = shm_open(flags().shm_name, O_RDWR, S_IRUSR | S_IWUSR);
    if (shm == -1) {
      Printf("FATAL: error creating shared union table\n");
      Die();
    }
    ret = internal_mmap((void *)UnionTableAddr(), uniontable_size,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, shm, 0);
  } else {
    ret = MmapFixedSuperNoReserve(UnionTableAddr(), uniontable_size);
  }
  if (internal_iserror(ret, &err)) {
    Printf("FATAL: error mapping shared union table %s\n", strerror(err));
    Die();
  }

  // init const label
  internal_memset(&__dfsan_label_info[CONST_LABEL], 0, sizeof(dfsan_label_info));
  __dfsan_label_info[CONST_LABEL].size = 8;

  // init hashtable allocator
  __taint::allocator_init(HashTableAddr(), HashTableAddr() + hashtable_size);

  // init main thread
  auto num_of_labels = uniontable_size / sizeof(dfsan_label_info);
  __alloca_stack_top = __alloca_stack_bottom = (dfsan_label)(num_of_labels - 2);

  // Protect the region of memory we don't use, to preserve the one-to-one
  // mapping from application to shadow memory. But if ASLR is disabled, Linux
  // will load our executable in the middle of our unused region. This mostly
  // works so long as the program doesn't use too much memory. We support this
  // case by disabling memory protection when ASLR is disabled.
  uptr init_addr = (uptr)&dfsan_init;
  if (!(init_addr >= UnusedAddr() && init_addr < AppAddr()))
    MmapFixedNoAccess(UnusedAddr(), AppAddr() - UnusedAddr());

  InitializeInterceptors();

  // Attach AFL++'s coverage map, if this binary carries AFL++'s edge counters
  // (see afl_compat.cpp; a no-op when it does not).  Above the fork point along
  // with everything else that is input-independent -- the map is shared memory
  // the fuzzer owns for the whole campaign, not something staged per run, so
  // attaching once and letting every child inherit the mapping is both cheaper
  // and the only way the counts reach the fuzzer at all.
  InitializeAflCoverage();

  // The fork server, if one was asked for, has to sit exactly here.  Everything
  // above is input-independent -- the shadow and union mappings, the hashtable
  // allocator, the interceptors -- and is what we want to pay for once and
  // amortize over every run.  Everything below reads the input the driver
  // staged for *this* run, so it has to happen again in each child.  (ucsan
  // forks after its whole init instead, because thoroupy receives the input as
  // a ticket payload rather than reading a file.)
  InitializeSymSanForkServer();

  InitializeTaintFile();

  InitializeTaintSocket();

  InitializeStringMaps();

  InitializeSymSanSolver();

  // Register the fini callback to run when the program terminates successfully
  // or it is killed by the runtime.
  Atexit(dfsan_fini);
  AddDieCallback(dfsan_fini);
}

#if SANITIZER_CAN_USE_PREINIT_ARRAY
__attribute__((section(".preinit_array"), used))
static void (*dfsan_init_ptr)(int, char **, char **) = dfsan_init;
#endif

extern "C" {

// Called by ucsan_init_internal to ensure dfsan is initialized before the fork server
SANITIZER_INTERFACE_ATTRIBUTE
void __dfsan_ensure_init(int argc, char **argv, char **envp) {
  dfsan_init(argc, argv, envp);
}

SANITIZER_INTERFACE_WEAK_DEF(void, InitializeSymSanSolver, void) {}

// Backends that do not implement a fork server just run once, as before.
SANITIZER_INTERFACE_WEAK_DEF(void, InitializeSymSanForkServer, void) {}

// Default empty implementations (weak) for hooks
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_cmp, dfsan_label, dfsan_label,
                             uint32_t, uint32_t, uint64_t, uint64_t, uint32_t) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_cond, dfsan_label, bool,
                             uint8_t, uint32_t) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_loop, uint32_t, uint32_t) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_loop_push_stack, void) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_loop_pop_stack, void) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_switch_end, uint32_t) {}
SANITIZER_INTERFACE_WEAK_DEF(dfsan_label, __taint_trace_select, dfsan_label,
                             dfsan_label, dfsan_label, uint8_t, uint8_t, uint8_t,
                             uint32_t) {return 0;}
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_indcall, dfsan_label) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_gep, dfsan_label, uint64_t,
                             dfsan_label, int64_t, uint64_t, uint64_t, int64_t,
                             uint32_t) {}
SANITIZER_INTERFACE_WEAK_DEF(dfsan_label, __taint_table_lookup, dfsan_label,
                             int64_t, uint64_t, uint64_t, uint64_t) {return 0;}
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_offset, dfsan_label, int64_t,
                             unsigned) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_memcmp, dfsan_label) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_distance, uint64_t, uint64_t) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_add_constraint, dfsan_label, uint8_t) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_minimize_label, dfsan_label, uint64_t, dfsan_label) {}
SANITIZER_WEAK_ATTRIBUTE THREADLOCAL uint32_t __taint_trace_callstack;
}  // extern "C"

//===----------------------------------------------------------------------===//
// SymSan Bridge - Strong Implementations
//===----------------------------------------------------------------------===//
// These strong definitions override the weak stubs in ucsan.cpp when linked.
// They enable UCSan to propagate symbolic state to SymSan.

extern "C" {

// Create a SymSan label for input bytes
// @param input_id: input source identifier (fd, socket, ucsan object, etc.)
// @param offset: byte offset within the source
// @param size_in_bytes: size of the input in bytes
// Overrides weak stub in ucsan.cpp
SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_create_label(uint32_t input_id, uint64_t offset, uint32_t size_in_bytes) {
  return dfsan_create_label(input_id, offset, size_in_bytes);
}

// Set SymSan arg TLS entry
// Overrides weak stub in ucsan.cpp
SANITIZER_INTERFACE_ATTRIBUTE
void __taint_set_arg_tls(uint32_t index, dfsan_label label, uint32_t size_in_bits) {
  if (index < kArgTlsSize / sizeof(dfsan_label)) {
    // Truncate if size_in_bits is not byte-aligned
    uint32_t size_in_bytes = (size_in_bits + 7) / 8;
    if (size_in_bits < size_in_bytes * 8) {
      label = do_taint_union(label, CONST_LABEL, Trunc, size_in_bits, 0, 0);
    }
    AOUT("set arg tls[%u] = %u\n", index, label);
    __dfsan_arg_tls[index] = label;
  }
}

// Set SymSan retval TLS entry
// Overrides weak stub in ucsan.cpp
SANITIZER_INTERFACE_ATTRIBUTE
void __taint_set_retval_tls(uint32_t index, dfsan_label label, uint32_t size_in_bits) {
  if (index >= kRetvalTlsSize / sizeof(dfsan_label)) return;
  // Truncate if size_in_bits is not byte-aligned
  uint32_t size_in_bytes = (size_in_bits + 7) / 8;
  if (size_in_bits < size_in_bytes * 8) {
    label = do_taint_union(label, CONST_LABEL, Trunc, size_in_bits, 0, 0);
  }
  AOUT("set retval tls[%u] = %u\n", index, label);
  __dfsan_retval_tls[index] = label;
}

// Zero the argument/return-value TLS.  Custom function wrappers that invoke an
// instrumented callback directly (e.g. dl_iterate_phdr, pthread_create) use
// this to give the callback zero-labelled arguments now that the trampoline
// mechanism has been removed (opaque pointers, LLVM 15+).
SANITIZER_INTERFACE_ATTRIBUTE
void dfsan_clear_thread_local_state() {
  internal_memset(__dfsan_arg_tls, 0, sizeof(__dfsan_arg_tls));
  internal_memset(__dfsan_retval_tls, 0, sizeof(__dfsan_retval_tls));
}

// Set SymSan shadow memory for a region
// Overrides weak stub in ucsan.cpp
SANITIZER_INTERFACE_ATTRIBUTE
void __taint_set_label(dfsan_label label, void *addr, uint64_t size) {
  dfsan_set_label(label, addr, size);
}

// Copy SymSan shadow memory from src to dst
// Overrides weak stub in ucsan.cpp
SANITIZER_INTERFACE_ATTRIBUTE
void __taint_copy_shadow(void *dst, void *src, uint64_t size) {
  dfsan_label *dst_shadow = shadow_for(dst);
  dfsan_label *src_shadow = shadow_for(src);
  internal_memcpy(dst_shadow, src_shadow, size * sizeof(dfsan_label));
  // Propagate string content label from src to dst
  dfsan_label str_label = taint_get_str_content_label(src);
  if (str_label != 0) {
    taint_set_str_content_label(dst, str_label);
  }
}

// Move SymSan shadow memory from src to dst (handles overlapping regions)
// Overrides weak stub in ucsan.cpp
SANITIZER_INTERFACE_ATTRIBUTE
void __taint_move_shadow(void *dst, void *src, uint64_t size) {
  dfsan_label *dst_shadow = shadow_for(dst);
  dfsan_label *src_shadow = shadow_for(src);
  internal_memmove(dst_shadow, src_shadow, size * sizeof(dfsan_label));
  // Propagate string content label from src to dst
  dfsan_label str_label = taint_get_str_content_label(src);
  if (str_label != 0) {
    taint_set_str_content_label(dst, str_label);
  }
}

// Extend a SymSan label to a wider bit width via ZExt or SExt.
// Overrides weak stub in ucsan.cpp
SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_extend_label(dfsan_label label, bool sign_extend, uint16_t new_size_in_bits) {
  if (label == 0) return 0;
  uint16_t op = sign_extend ? __dfsan::SExt : __dfsan::ZExt;
  return do_taint_union(label, CONST_LABEL, op, new_size_in_bits, 0, 0);
}

// Get or create an Alloca bounds label for a pointer
// If ptr != NULL, checks shadow_for(&ptr) for existing Alloca to update
// If ptr == NULL or no existing Alloca, creates a new one
// Returns the Alloca label; caller stores it (e.g., via __taint_set_retval_tls)
// Overrides weak stub in ucsan.cpp
SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_get_ptr_bounds_label(void *ptr, uint64_t lower, uint64_t upper) {
  if (!flags().trace_bounds) return 0;
  if (ptr != nullptr) {
    dfsan_label label = *shadow_for(&ptr);
    if (label != 0) {
      dfsan_label_info *info = get_label_info(label);
      if (info->op == __dfsan::Alloca) {
        info->op1.i = lower;
        info->op2.i = upper;
        AOUT("update ptr bounds %p = %d, lower = %p, upper = %p\n",
             ptr, label, (void*)lower, (void*)upper);
        return label;
      }
    }
  }
  // Allocate new Alloca label
  dfsan_label bound = dfsan_union(0, 0, Alloca, sizeof(void*) * 8, lower, upper);
  AOUT("new ptr bounds label %d, lower = %p, upper = %p\n",
       bound, (void*)lower, (void*)upper);
  return bound;
}

// Materialize a concrete operand of an operation wider than 64 bits as a leaf
// label, so it reaches the solver at full width instead of being truncated into
// a single op slot.  Applies to small values too, like the 64 in
// `(unsigned __int128)x >> 64`, because what a zero label cannot express is not
// "large" but "exact".  dfsan_union dedups on (l1, l2, op, size, op1, op2), so
// repeated uses of the same value collapse to one union-table entry for the
// whole trace.
SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_wide_const(uint64_t lo, uint64_t hi, uint16_t size) {
  if (size <= 64 || size > 128) return 0;
  dfsan_label label = dfsan_union(0, 0, __dfsan::WideConst, size, lo, hi);
  AOUT("wide const label %d, size %u, lo = 0x%lx, hi = 0x%lx\n",
       label, size, lo, hi);
  return label;
}

// Give ONE operand of an operation wider than 64 bits a real label: a symbolic
// operand already has one, a concrete operand gets a WideConst leaf built from
// its full value.  Instrumented code calls this on each operand and then hands
// the results to the ordinary __taint_union, so there is no wide variant of the
// union itself to keep in step with it.
//
// The point of doing this in the runtime rather than in the instrumentation is
// that only the runtime knows which operands are actually tainted.  Deciding at
// compile time would mean recognising a ConstantInt operand, and at -O0 a
// literal __int128 is not one -- clang keeps it in an alloca and loads it -- so
// the whole shape would have worked only under optimization.
SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_get_wide(dfsan_label label, uint64_t lo, uint64_t hi,
                             uint16_t size) {
  if (label) return label;
  return __taint_wide_const(lo, hi, size);
}

// Weak stub for UCSan's event tracing
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_event_addr,
                             uint32_t, uint32_t, uint64_t, void*,
                             uint32_t) {}

}  // extern "C"
