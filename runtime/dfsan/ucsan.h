//===-- ucsan.h - UCSan Runtime Header -------------------------*- C++ -*-===//
//
// Under-Constrained Symbolic Sanitizer Runtime
//
// UCSan focuses on:
// - Pointer shadow tracking (object membership, bounds)
// - Lazy object initialization and management
// - Pseudo-pointer resolution
//
// UCSan uses 16-bit labels (separate from SymSan's 32-bit labels).
// This is separate from SymSan which tracks symbolic expressions.
//
//===----------------------------------------------------------------------===//

#ifndef UCSAN_H
#define UCSAN_H

#include "ucsan_platform.h"
#include "ucsan_exit_reason.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_atomic.h"

#include <cstddef>
#include <cstdint>

using __sanitizer::uptr;
using __sanitizer::atomic_uint16_t;
using __sanitizer::atomic_uint32_t;
using __sanitizer::atomic_uint64_t;
using __sanitizer::memory_order_relaxed;

typedef uint32_t dfsan_label;

//===----------------------------------------------------------------------===//
// UCSan Configuration
//===----------------------------------------------------------------------===//

#define UCSAN_SAFE_GAP 0x1000
#define UCSAN_ROUNDUPGAP(x) (((x) + UCSAN_SAFE_GAP - 1) & ~(UCSAN_SAFE_GAP - 1))
#define UCSAN_OBJECT_SIZE_LIMIT (4096 * 10)
#define UCSAN_MAX_SAVED_STACK_ENTRIES 1024

namespace __ucsan {

//===----------------------------------------------------------------------===//
// Special Labels (16-bit)
//===----------------------------------------------------------------------===//

const ucsan_label kUninitializedLabel = (ucsan_label)0xFFFF;

//===----------------------------------------------------------------------===//
// Pointer State
//===----------------------------------------------------------------------===//

enum PTR_STATE : uint16_t {
  PTR_UNINITIALIZED = 0,     // uninitialized pointer (needs lazy init)
  PTR_INITIALIZED = 1,      // lazy-initialized pointer (has object)
  PTR_ALLOCATED = 2,        // allocated by malloc (may not be symbolized)
  PTR_EXTERNAL = 3,         // external pointer (from input)
};

//===----------------------------------------------------------------------===//
// UCSan Label Info Structures (designed for pointer/object tracking)
//
// All stored in the same union table, so must be the same size.
// Use 'op' field to distinguish type.
//===----------------------------------------------------------------------===//

// Byte info - tracks individual bytes within objects (op == OP_NONE)
// Shadow memory points to these for each byte in a lazy-initialized object
struct ucsan_byte_info {
  uint16_t op;                 // OP_NONE
  uint16_t _reserved;
  uint32_t object_id;          // which object this byte belongs to
  int64_t offset;         // byte's offset within the object
  uint64_t _padding;           // padding to match other structs
} __attribute__((aligned(8)));

// Pointer info - tracks symbolic/external pointers (op == OP_EXTERNAL)
// Offset is computed dynamically as (current_ptr - pseudo_base)
struct ucsan_ptr_info {
  uint16_t op;                 // OP_EXTERNAL, OP_NONE, etc.
  uint16_t status;             // PTR_STATE
  ucsan_label obj_label;  // label pointing to backing ucsan_obj_info
  uint16_t _reserved;
  void* pseudo_base;      // original symbolic pointer value
  uint64_t _padding;           // padding to match other structs
} __attribute__((aligned(8)));

// Object info - tracks lazy-initialized objects (op == OP_RESERVED_OBJ)
struct ucsan_obj_info {
  uint16_t op;                 // OP_RESERVED_OBJ
  uint16_t _reserved;
  uint32_t object_id;          // unique object ID (index into objects array)
  void* real_ptr;         // actual memory (points to base within allocated region)
  uint32_t lower_bound;        // bytes before base (for container_of)
  uint32_t upper_bound;        // bytes after base
} __attribute__((aligned(8)));

// Union of all label info types for the label table
union ucsan_label_info {
  struct { uint16_t op; } common;  // common header to check type
  ucsan_byte_info byte;
  ucsan_ptr_info ptr;
  ucsan_obj_info obj;
};

// Static assertions - all info structs must be same size (24 bytes)
static_assert(sizeof(ucsan_byte_info) == 24, "ucsan_byte_info should be 24 bytes");
static_assert(sizeof(ucsan_ptr_info) == 24, "ucsan_ptr_info should be 24 bytes");
static_assert(sizeof(ucsan_obj_info) == 24, "ucsan_obj_info should be 24 bytes");
static_assert(sizeof(ucsan_label_info) == 24, "ucsan_label_info should be 24 bytes");

// Size of each entry in the union table
static const size_t kLabelInfoSize = sizeof(ucsan_label_info);

//===----------------------------------------------------------------------===//
// Label Info Accessors
//===----------------------------------------------------------------------===//

// Convert label_info to specific types (for convenience)
inline ucsan_ptr_info* to_ptr_info(ucsan_label_info *info) {
  return &info->ptr;
}

inline ucsan_obj_info* to_obj_info(ucsan_label_info *info) {
  return &info->obj;
}

inline ucsan_byte_info* to_byte_info(ucsan_label_info *info) {
  return &info->byte;
}

//===----------------------------------------------------------------------===//
// Object Tracking Structures
//===----------------------------------------------------------------------===//

// Metadata about where an object originated
struct ObjectOrigin {
  uint32_t obj_id;   // parent object ID (0 = super object)
  int32_t offset;    // offset within parent object
  uint32_t target_offset; // offset within this object the pointer points to
};

//===----------------------------------------------------------------------===//
// Simple dynamic buffer (replaces std::vector<unsigned char>)
//===----------------------------------------------------------------------===//
struct ByteBuffer {
  unsigned char *buf;
  uint32_t len;
  uint32_t cap;

  void init() { buf = nullptr; len = 0; cap = 0; }
  void destroy();
  uint32_t size() const { return len; }
  unsigned char *data() { return buf; }
  const unsigned char *data() const { return buf; }
  unsigned char& operator[](uint32_t i) { return buf[i]; }
  const unsigned char& operator[](uint32_t i) const { return buf[i]; }
  unsigned char& at(uint32_t i) { return buf[i]; }
  const unsigned char& at(uint32_t i) const { return buf[i]; }
  void resize(uint32_t new_size);
  void clear() { len = 0; }
  void assign(const unsigned char *src, uint32_t n);
};

// An object tracked by UCSan
struct UCSanObject {
  uint32_t offset;                    // offset within object (for sub-objects)
  ByteBuffer data;                    // concrete data
  ObjectOrigin origin;                // where this object came from
};

//===----------------------------------------------------------------------===//
// Simple dynamic array for objects (replaces std::vector<UCSanObject>)
//===----------------------------------------------------------------------===//
struct ObjectStorage {
  UCSanObject *items;
  uint32_t len;
  uint32_t cap;

  void init() { items = nullptr; len = 0; cap = 0; }
  void destroy();
  uint32_t size() const { return len; }
  UCSanObject& operator[](uint32_t i) { return items[i]; }
  const UCSanObject& operator[](uint32_t i) const { return items[i]; }
  UCSanObject& at(uint32_t i) { return items[i]; }
  const UCSanObject& at(uint32_t i) const { return items[i]; }
  void resize(uint32_t new_size);
  void clear();
  void push_back(const UCSanObject &obj);
  UCSanObject& emplace_back(const UCSanObject &obj);
};

//===----------------------------------------------------------------------===//
// Simple open-addressing hash map (replaces std::map<pair, uint32_t>)
//===----------------------------------------------------------------------===//
struct ObjectMapKey {
  uint32_t first;   // parent_obj_id
  int32_t second;   // offset
};

struct ObjectMapEntry {
  ObjectMapKey key;
  uint32_t value;
  uint8_t occupied;
};

struct ObjectMap {
  ObjectMapEntry *entries;
  uint32_t cap;
  uint32_t count;

  void init(uint32_t initial_cap = 64);
  void destroy();
  uint32_t size() const { return count; }

  // Returns pointer to value if found, nullptr if not
  uint32_t *find_val(uint32_t parent_id, int32_t offset);

  // Insert or update
  void insert(uint32_t parent_id, int32_t offset, uint32_t value);

private:
  uint32_t hash(uint32_t parent_id, int32_t offset) const;
  void grow();
};

//===----------------------------------------------------------------------===//
// UCSan Taint Source (Input Tracking)
//===----------------------------------------------------------------------===//

struct ucsan_input {
  char filename[4096];          // input file path
  int fd;                       // file descriptor
  off_t offset;                 // current offset
  ucsan_label offset_label;     // label for offset (if symbolic)
  ucsan_label label;            // base label
  off_t size;                   // input size
  uint8_t is_stdin;             // is stdin input
  uint8_t is_utmp;              // is utmp input
  const char *buf;              // mapped input buffer
  uptr buf_size;                // buffer size

  // Object management (same pattern as dfsan)
  // All pointers to avoid C++ constructor ordering issues
  ObjectStorage *objects;       // pointer - allocated dynamically
  ObjectMap *obj_map;           // pointer - allocated dynamically

  // Super object offset tracking
  atomic_uint64_t arg_used;     // bytes used from super object

  // NOTE: No constructors - use ucsan_init_tainted() for C-style init
  // to avoid preinit_array ordering issues

  // Serialize objects to buffer
  char* dump();

  // Deserialize objects from buffer
  uint64_t load(const char *buf, size_t file_size);

  // Build object map from objects
  void build_obj_map();
};

// NOTE: ucsan_input initialization is handled internally by ucsan_init()
// via ucsan_init_input_struct() - a C-style init to avoid preinit_array issues

//===----------------------------------------------------------------------===//
// UCSan Event Types (for tracing)
//===----------------------------------------------------------------------===//

enum ucsan_event_type {
  EVENT_LAZY_INIT = 100,
  EVENT_USAGE_CITE = 101,
  EVENT_EXTENSION = 102,
  EVENT_ASSERTION = 103,
  EVENT_TYPE_BIND = 104,
};

enum ucsan_assertion_type {
  ASSERTION_NONE = 0,
  ASSERTION_NONE_SYMBOLIC = 1,
  ASSERTION_ALLOCATED_FAILED = 2,
  ASSERTION_ALLOCATED_SUCCESS = 3,
  ASSERTION_FREED_FAILED = 4,
  ASSERTION_FREED_SUCCESS = 5,
  ASSERTION_INIT_FAILED = 6,
  ASSERTION_INIT_SUCCESS = 7,
  ASSERTION_COND_FAILED = 8,
  ASSERTION_COND_SUCCESS = 9,
};

//===----------------------------------------------------------------------===//
// UCSan Operations (subset of LLVM opcodes needed for pointer tracking)
//===----------------------------------------------------------------------===//

enum ucsan_op : uint16_t {
  OP_NONE = 0,
  OP_LOAD = 32,
  OP_STORE = 33,
  OP_GEP = 34,
  OP_BITCAST = 47,
  OP_INTTOPTR = 50,
  OP_PTRTOINT = 51,

  // UCSan-specific operations
  OP_FREE = 100,
  OP_ALLOCA = 101,
  OP_EXTERNAL = 102,      // external/symbolic pointer
  OP_INITP = 103,         // initialized pointer
  OP_RESERVED_OBJ = 104,  // reserved object label
};

//===----------------------------------------------------------------------===//
// UCSan Runtime State
//===----------------------------------------------------------------------===//

// UCSan configuration flags (defined via ucsan_flags.inc)
struct UCSanFlags {
#define UCSAN_FLAG(Type, Name, DefaultValue, Description) Type Name;
#include "ucsan_flags.inc"
#undef UCSAN_FLAG

  void SetDefaults();
};

// Global UCSan state
extern ucsan_input ucsan_tainted;
extern UCSanFlags ucsan_flags_data;
extern bool ucsan_debug;

// Access flags
inline UCSanFlags& ucsan_flags() {
  return ucsan_flags_data;
}

//===----------------------------------------------------------------------===//
// UCSan Label Management
//===----------------------------------------------------------------------===//

// Get label info for a given label
ucsan_label_info* get_label_info(ucsan_label label);

// Allocate a new label
ucsan_label allocate_label();

// Check if label is valid
void check_label(ucsan_label label);

//===----------------------------------------------------------------------===//
// UCSan Helper Functions
//===----------------------------------------------------------------------===//

// Object lookup result
struct object_info {
  ucsan_label label;
  uint64_t offset;
};

// Look up or create an object for a given pointer label
UCSanObject& lookup_object(ucsan_label label, uint64_t offset, void* return_addr,
                           uint32_t *ret_object_id = nullptr, uint32_t type_id = 0,
                           uint32_t size = 0);

// Create a label from the super object (object 0)
object_info create_label_from_super_object(size_t size, bool is_pointer = false);

// Allocate memory with safe gap for pseudo-pointer resolution
void* customized_malloc(uint64_t size);

// Check if pointer is within data/bss section
bool in_data_section(void *p);
bool in_bss_section(void *p);

}  // namespace __ucsan

//===----------------------------------------------------------------------===//
// UCSan Public Interface (C linkage)
//===----------------------------------------------------------------------===//

extern "C" {

// UCSan TLS variables for argument/return value passing
#define UCSAN_TLS_SIZE 800
extern SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL __ucsan::ucsan_label
    __ucsan_retval_tls[UCSAN_TLS_SIZE / sizeof(__ucsan::ucsan_label)];
extern SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL __ucsan::ucsan_label
    __ucsan_arg_tls[UCSAN_TLS_SIZE / sizeof(__ucsan::ucsan_label)];
extern SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL uint8_t
    __ucsan_wrapped_return_tls[UCSAN_TLS_SIZE];

// Flag for null dereference checking
extern void* __ucsan_null_deref_flag;

//===----------------------------------------------------------------------===//
// Core UCSan Functions
//===----------------------------------------------------------------------===//

// Check and resolve a pointer (main UCSan entry point)
// Handles lazy object initialization and pseudo-pointer resolution
// @param p: the pointer to check
// @param label: the ucsan label for the pointer
// @param size: access size in bytes
// @param dereferencing: true if this is a dereference (load/store)
// @param type_id: compile-time type ID from type table (0 = unknown)
// @return: resolved real pointer (may differ from p for pseudo-pointers)
SANITIZER_INTERFACE_ATTRIBUTE
void* ucsan_check_pointer(void* p, __ucsan::ucsan_label label, size_t size, bool dereferencing, uint32_t type_id);

// Check pointer argument for use-before-initialization
SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_check_ptr_arg(__ucsan::ucsan_label *label, uint32_t arg_index, void* ret_addr);

// Load shadow for pointer type
SANITIZER_INTERFACE_ATTRIBUTE
__ucsan::ucsan_label ucsan_load_pointer_shadow(__ucsan::ucsan_label *ls, uint64_t n, bool is_pointer);

// Store shadow for pointer type
SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_store_pointer_shadow(__ucsan::ucsan_label l, __ucsan::ucsan_label *ls, uint64_t n);

// Set label for a memory region
// @param label: the label to set
// @param addr: start address of the memory region
// @param size: size of the memory region in bytes
SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_set_label(__ucsan::ucsan_label label, void *addr, uint64_t size);

// Set symbolic label for function arguments at entry point
// @param index: argument index
// @param size_in_bits: size of argument in bits
// @param is_pointer: true if argument is a pointer
// @param given: concrete value if no seed data available
// @return: concrete value to use (from seed or given)
SANITIZER_INTERFACE_ATTRIBUTE
void* ucsan_set_label_for_args(uint32_t index, uint32_t size_in_bits, uint8_t is_pointer, uint64_t given);

// Resign shadow for an object
// Called when passing pointer to external/uninstrumented code
// @param ptr: pointer to the object
// @param orig_label: pointer to the label for ptr
// @param n: size of the object in bytes
// @param ret_addr: return address for tracing
// @return: label representing the object
SANITIZER_INTERFACE_ATTRIBUTE
__ucsan::ucsan_label ucsan_resign_shadow(void *ptr, __ucsan::ucsan_label *orig_label, uint64_t n, void *ret_addr);

// Wrap return value with symbolic label
// @param size: size in bits
// @param ret_label: output label for return value
// @param is_ptr: true if return value is a pointer
// @param ret_addr: return address for tracing
// @return: pointer to buffer with concrete return value
SANITIZER_INTERFACE_ATTRIBUTE
void* ucsan_wrap_retval(uint64_t size, __ucsan::ucsan_label *ret_label, bool is_ptr, void* ret_addr);

//===----------------------------------------------------------------------===//
// UCSan Initialization
//===----------------------------------------------------------------------===//

// Initialize UCSan runtime
SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_init();

// Finalize UCSan runtime
SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_fini();

// Initialize UCSan input from file
SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_init_input(const char *filename);

}  // extern "C"

//===----------------------------------------------------------------------===//
// Debug Output Macro
//===----------------------------------------------------------------------===//

#define UCSAN_OUT(...)                                      \
  do {                                                      \
    if (__ucsan::ucsan_debug) {                             \
      Printf("[UCSAN] (%s:%d) ", __FUNCTION__, __LINE__);   \
      Printf(__VA_ARGS__);                                  \
    }                                                       \
  } while(false)

#endif  // UCSAN_H
