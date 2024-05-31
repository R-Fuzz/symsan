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

static const size_t uniontable_size = 0xc00000000; // FIXME

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
dfsan_label dfsan_read_label(const void *addr, uptr size);
void dfsan_store_label(dfsan_label l1, void *addr, uptr size);
dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2, uint16_t op, uint16_t size,
                        uint64_t op1, uint64_t op2);
dfsan_label dfsan_create_label(off_t offset);
dfsan_label dfsan_get_label(const void *addr);
dfsan_label_info* dfsan_get_label_info(dfsan_label label);

// taint source
void taint_set_file(const char *filename, int fd);
off_t taint_get_file(int fd);
void taint_close_file(int fd);
int is_taint_file(const char *filename);
int is_stdin_taint(void);
void taint_set_offset_label(dfsan_label label);
dfsan_label taint_get_offset_label();

// taint source utmp
off_t get_utmp_offset(void);
void set_utmp_offset(off_t offset);
int is_utmp_taint(void);

// taint source socket
void taint_set_socket(const void *addr, unsigned addrlen, int fd);
off_t taint_get_socket(int fd);
void taint_update_socket_offset(int fd, size_t size);
void taint_close_socket(int fd);
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
#undef LAST_OTHER_INST
  // self-defined
  Free      = last_llvm_op + 3,
  Extract   = last_llvm_op + 4,
  Concat    = last_llvm_op + 5,
  Arg       = last_llvm_op + 6,
  // higher-order
  fmemcmp   = last_llvm_op + 7,
  fsize     = last_llvm_op + 8,
  fatoi     = last_llvm_op + 9,
  LastOp    = last_llvm_op + 10,
};

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
    case bvsgt: return (s64)c1 > (s64)c2;
    case bvsge: return (s64)c1 >= (s64)c2;
    case bvslt: return (s64)c1 < (s64)c2;
    case bvsle: return (s64)c1 <= (s64)c2;
    default: break;
  }
  return 0;
}

static inline bool is_commutative(unsigned char op) {
  switch(op) {
    case Not:
    case And:
    case Or:
    case Xor:
    case Add:
    case Mul:
    case fmemcmp:
      return true;
    default:
      return false;
  }
}

// for out-of-process solving

enum pipe_msg_type {
  cond_type = 0,
  gep_type = 1,
  memcmp_type = 2,
  fsize_type = 3,
  memerr_type = 4,
  fini_type = 5,
};

#define F_MEMERR_UAF 0x1
#define F_MEMERR_OLB 0x2
#define F_MEMERR_OUB 0x4
#define F_MEMERR_UBI 0x8
#define F_ADD_CONS  0x10
#define F_HAS_DISTANCE 0x20

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

}  // namespace __dfsan

struct mazerunner_msg {
  u16 flags;
  u32 id;
  uptr addr;
  u32 context;
  long global_min_dist;
  long local_min_dist;
} __attribute__((packed));

#endif  // DFSAN_H
