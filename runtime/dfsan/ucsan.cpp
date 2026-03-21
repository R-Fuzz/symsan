//===-- ucsan.cpp - UCSan Runtime Implementation ------------------===//
//
// Under-Constrained Symbolic Sanitizer Runtime
//
// This file implements the UCSan runtime for:
// - Lazy object initialization
// - Pseudo-pointer resolution
// - Pointer shadow tracking
//
// UCSan is designed to work alongside SymSan but with independent
// shadow memory for pointer/object tracking (vs symbolic expressions).
//
//===----------------------------------------------------------------------===//

#include "ucsan.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_posix.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstring>
#include <cassert>

using namespace __sanitizer;

// Forward declarations for trace callbacks (implemented in solvers)
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_trace_event_addr(__ucsan::ucsan_label label, uint32_t event_id,
                              uint64_t info, void* addr, uint32_t info2);

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_trace_global_var(__ucsan::ucsan_label label, uint64_t size,
                              void *gv);

// Forward declaration for UCSan solver initialization (thoroupy backend)
extern "C" void InitializeUCSanSolver();

// Ensure dfsan is initialized before ucsan (weak, no-op when standalone)
extern "C" SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE
void __dfsan_ensure_init(int argc, char **argv, char **envp);

// Forward declarations for SymSan bridge functions
// (weak stubs, overridden when linked with SymSan)
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_create_label(uint32_t object_id, uint64_t offset,
                                 uint32_t size_in_bytes);

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_set_arg_tls(uint32_t index, dfsan_label label,
                         uint32_t size_in_bits);

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_set_retval_tls(uint32_t index, dfsan_label label, uint32_t size_in_bits);

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_set_label(dfsan_label label, void *addr, uint64_t size);

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_copy_shadow(void *dst, void *src, uint64_t size);

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_get_ptr_bounds_label(void *ptr, uint64_t lower, uint64_t upper);

//===----------------------------------------------------------------------===//
// Global State
//===----------------------------------------------------------------------===//

namespace __ucsan {

// Global input/taint source
ucsan_input ucsan_tainted;

// Configuration flags
UCSanFlags ucsan_flags_data;

// Debug flag
bool ucsan_debug = false;

// Label management
static atomic_uint32_t __ucsan_last_label;
static ucsan_label_info *__ucsan_label_info = nullptr;

// Object counter
static atomic_uint32_t __ucsan_inited_objects;

// Stack management for bounds tracking
static ucsan_label __alloca_stack_bottom;
static ucsan_label __alloca_stack_top;
static ucsan_label __saved_alloca_stack_top[UCSAN_MAX_SAVED_STACK_ENTRIES];
static int __current_saved_stack_index = 0;

}  // namespace __ucsan

// DSO section markers (linker-provided, must be at global scope with C linkage)
extern "C" {
extern char __dso_handle;
extern char edata;
extern char end;
}

namespace __ucsan {

bool in_data_section(void *p) {
  return (&__dso_handle <= (char*)p && (char*)p <= &end);
}

bool in_bss_section(void *p) {
  return (&edata <= (char*)p && (char*)p <= &end);
}

}  // namespace __ucsan

//===----------------------------------------------------------------------===//
// TLS Variables
//===----------------------------------------------------------------------===//

using __ucsan::ucsan_label;

extern "C" {

SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL ucsan_label
    __ucsan_retval_tls[UCSAN_TLS_SIZE / sizeof(ucsan_label)];

SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL ucsan_label
    __ucsan_arg_tls[UCSAN_TLS_SIZE / sizeof(ucsan_label)];

SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL uint8_t
    __ucsan_wrapped_return_tls[UCSAN_TLS_SIZE];

void* __ucsan_null_deref_flag = nullptr;

}  // extern "C"

//===----------------------------------------------------------------------===//
// Container Implementations (replaces STL)
//===----------------------------------------------------------------------===//

using namespace __ucsan;
using __sanitizer::MmapOrDie;
using __sanitizer::UnmapOrDie;
using __sanitizer::RoundUpTo;
using __sanitizer::GetPageSizeCached;
using __sanitizer::internal_memcpy;
using __sanitizer::internal_memset;

void ByteBuffer::destroy() {
  if (buf) {
    UnmapOrDie(buf, RoundUpTo(cap, GetPageSizeCached()));
    buf = nullptr;
  }
  len = cap = 0;
}

void ByteBuffer::resize(uint32_t new_size) {
  if (new_size > cap) {
    uint32_t new_cap = cap ? cap : 16;
    while (new_cap < new_size) new_cap *= 2;
    uptr old_alloc = RoundUpTo(cap, GetPageSizeCached());
    uptr new_alloc = RoundUpTo(new_cap, GetPageSizeCached());
    if (buf) {
      uptr r = internal_mremap(buf, old_alloc, new_alloc, MREMAP_MAYMOVE, nullptr);
      if (!internal_iserror(r)) {
        buf = (unsigned char *)r;
      } else {
        unsigned char *new_buf = (unsigned char *)MmapOrDie(new_alloc, "ByteBuffer");
        __builtin_memcpy(new_buf, buf, len);
        UnmapOrDie(buf, old_alloc);
        buf = new_buf;
      }
    } else {
      buf = (unsigned char *)MmapOrDie(new_alloc, "ByteBuffer");
    }
    cap = new_cap;
  }
  len = new_size;
}

void ByteBuffer::assign(const unsigned char *src, uint32_t n) {
  resize(n);
  __builtin_memcpy(buf, src, n);
}

void ObjectStorage::destroy() {
  if (items) {
    for (uint32_t i = 0; i < len; i++)
      items[i].data.destroy();
    UnmapOrDie(items, RoundUpTo(cap * sizeof(UCSanObject), GetPageSizeCached()));
    items = nullptr;
  }
  len = cap = 0;
}

void ObjectStorage::resize(uint32_t new_size) {
  if (new_size > cap) {
    uint32_t new_cap = cap ? cap : 4;
    while (new_cap < new_size) new_cap *= 2;
    uptr alloc_size = RoundUpTo(new_cap * sizeof(UCSanObject), GetPageSizeCached());
    UCSanObject *new_items = (UCSanObject *)MmapOrDie(alloc_size, "ObjectStorage");
    if (items) {
      internal_memcpy(new_items, items, len * sizeof(UCSanObject));
      UnmapOrDie(items, RoundUpTo(cap * sizeof(UCSanObject), GetPageSizeCached()));
    }
    items = new_items;
    cap = new_cap;
  }
  // Initialize new entries (MmapOrDie zero-fills, but init ByteBuffer explicitly)
  for (uint32_t i = len; i < new_size; i++) {
    items[i].offset = 0;
    items[i].data.init();
    items[i].origin = {0, 0};
  }
  len = new_size;
}

void ObjectStorage::clear() {
  for (uint32_t i = 0; i < len; i++)
    items[i].data.destroy();
  len = 0;
}

void ObjectStorage::push_back(const UCSanObject &obj) {
  if (len >= cap) {
    resize(len + 1);
    items[len - 1] = obj;
  } else {
    items[len++] = obj;
  }
}

UCSanObject& ObjectStorage::emplace_back(const UCSanObject &obj) {
  push_back(obj);
  return items[len - 1];
}

void ObjectMap::init(uint32_t initial_cap) {
  cap = initial_cap;
  count = 0;
  uptr alloc_size = RoundUpTo(cap * sizeof(ObjectMapEntry), GetPageSizeCached());
  entries = (ObjectMapEntry *)MmapOrDie(alloc_size, "ObjectMap");
  // MmapOrDie returns zero-filled, so occupied=0 for all entries
}

void ObjectMap::destroy() {
  if (entries) {
    UnmapOrDie(entries, RoundUpTo(cap * sizeof(ObjectMapEntry), GetPageSizeCached()));
    entries = nullptr;
  }
  cap = count = 0;
}

uint32_t ObjectMap::hash(uint32_t parent_id, int32_t offset) const {
  uint64_t key = ((uint64_t)parent_id << 32) | (uint32_t)offset;
  key *= 2654435769ULL;
  return (uint32_t)(key & (cap - 1));
}

uint32_t *ObjectMap::find_val(uint32_t parent_id, int32_t offset) {
  if (!entries) return nullptr;
  uint32_t h = hash(parent_id, offset);
  for (uint32_t i = 0; i < cap; i++) {
    uint32_t idx = (h + i) & (cap - 1);
    if (!entries[idx].occupied) return nullptr;
    if (entries[idx].key.first == parent_id && entries[idx].key.second == offset)
      return &entries[idx].value;
  }
  return nullptr;
}

void ObjectMap::insert(uint32_t parent_id, int32_t offset, uint32_t value) {
  if (count * 10 > cap * 7) grow();
  uint32_t h = hash(parent_id, offset);
  for (;;) {
    uint32_t idx = h & (cap - 1);
    if (!entries[idx].occupied) {
      entries[idx].key = {parent_id, offset};
      entries[idx].value = value;
      entries[idx].occupied = 1;
      count++;
      return;
    }
    if (entries[idx].key.first == parent_id && entries[idx].key.second == offset) {
      entries[idx].value = value;
      return;
    }
    h++;
  }
}

void ObjectMap::grow() {
  uint32_t old_cap = cap;
  ObjectMapEntry *old = entries;
  cap *= 2;
  uptr alloc_size = RoundUpTo(cap * sizeof(ObjectMapEntry), GetPageSizeCached());
  entries = (ObjectMapEntry *)MmapOrDie(alloc_size, "ObjectMap");
  count = 0;
  for (uint32_t i = 0; i < old_cap; i++) {
    if (old[i].occupied)
      insert(old[i].key.first, old[i].key.second, old[i].value);
  }
  UnmapOrDie(old, RoundUpTo(old_cap * sizeof(ObjectMapEntry), GetPageSizeCached()));
}

//===----------------------------------------------------------------------===//
// UCSan Input Implementation
//===----------------------------------------------------------------------===//

namespace __ucsan {

// NOTE: ucsan_input uses C-style initialization to avoid constructor ordering issues
// with preinit_array.

static void ucsan_init_input_struct() {
  internal_memset(ucsan_tainted.filename, 0, sizeof(ucsan_tainted.filename));
  ucsan_tainted.fd = -1;
  ucsan_tainted.offset = 0;
  ucsan_tainted.offset_label = 0;
  ucsan_tainted.label = 0;
  ucsan_tainted.size = 0;
  ucsan_tainted.is_stdin = 0;
  ucsan_tainted.is_utmp = 0;
  ucsan_tainted.buf = nullptr;
  ucsan_tainted.buf_size = 0;
  // Allocate C++ objects with constructors dynamically to avoid ordering issues
  if (!ucsan_tainted.objects) {
    ucsan_tainted.objects = new ObjectStorage();
  }
  if (!ucsan_tainted.obj_map) {
    ucsan_tainted.obj_map = new ObjectMap();
    ucsan_tainted.obj_map->init();
  }
  ucsan_tainted.arg_used.val_dont_use = 0;
}

static void ucsan_fini_input_struct() {
  if (ucsan_tainted.objects) {
    ucsan_tainted.objects->destroy();
    delete ucsan_tainted.objects;
    ucsan_tainted.objects = nullptr;
  }
  if (ucsan_tainted.obj_map) {
    ucsan_tainted.obj_map->destroy();
    delete ucsan_tainted.obj_map;
    ucsan_tainted.obj_map = nullptr;
  }
}

char* ucsan_input::dump() {
  uint64_t length = sizeof(uint64_t);
  for (uint32_t i = 0; i < objects->size(); i++) {
    length += objects->at(i).data.size() + sizeof(uint64_t) + sizeof(uint32_t);
  }

  char *ret = static_cast<char*>(malloc(length));
  char *pos = ret;

  // Write object count
  uint64_t tmp = objects->size();
  internal_memcpy(pos, &tmp, sizeof(uint64_t));
  pos += sizeof(uint64_t);

  // Write offsets
  for (uint32_t i = 0; i < objects->size(); i++) {
    uint32_t tmp32 = objects->at(i).offset;
    internal_memcpy(pos, &tmp32, sizeof(uint32_t));
    pos += sizeof(uint32_t);
  }

  // Write sizes
  for (uint32_t i = 0; i < objects->size(); i++) {
    tmp = objects->at(i).data.size();
    internal_memcpy(pos, &tmp, sizeof(uint64_t));
    pos += sizeof(uint64_t);
  }

  // Write data
  for (uint32_t i = 0; i < objects->size(); i++) {
    tmp = objects->at(i).data.size();
    internal_memcpy(pos, objects->at(i).data.data(), tmp);
    pos += tmp;
  }

  buf_size = length;
  return ret;
}

uint64_t ucsan_input::load(const char *buf, size_t file_size) {
  // Parse deseralized objects from buffer:
  // [object_cnt: uint64_t]
  // [offset1: uint32_t, offset2: uint32_t, ...] (object_cnt entries)
  // [size1: uint64_t, size2: uint64_t, ...] (object_cnt entries)
  // [data1, data2, ...] (variable length)
  // [metadata: obj_id + offset pairs] (optional)

  uint64_t *header = (uint64_t *)buf;
  uint64_t object_cnt = *header;
  header++;

  uint32_t *offsets = (uint32_t *)header;
  uint64_t *sizes = (uint64_t *)(offsets + object_cnt);

  const char *cursor = buf + sizeof(uint64_t) + // object_cnt
                       sizeof(uint32_t) * object_cnt + // offset entries
                       sizeof(uint64_t) * object_cnt; // size entries

  // Initialize objects storage
  if (!ucsan_tainted.objects) {
    ucsan_tainted.objects = new ObjectStorage();
  }
  ucsan_tainted.objects->clear();

  for (uint64_t i = 0; i < object_cnt; ++i) {
    UCSanObject obj;
    obj.offset = offsets[i];
    obj.data.init();
    obj.data.assign((const unsigned char *)cursor, (uint32_t)sizes[i]);
    obj.origin = {0, 0};
    ucsan_tainted.objects->push_back(obj);
    cursor += sizes[i];
  }

  // Load metadata if present
  if (cursor < buf + file_size) {
    for (uint64_t i = 0; i < object_cnt && cursor + sizeof(uint64_t) * 2 <= buf + file_size; ++i) {
      ucsan_tainted.objects->at(i).origin.obj_id = *(uint64_t *)cursor;
      cursor += sizeof(uint64_t);
      ucsan_tainted.objects->at(i).origin.offset = *(uint64_t *)cursor;
      cursor += sizeof(uint64_t);
    }
  }

  // Build object map for lookup
  if (object_cnt > 1) {
    ucsan_tainted.build_obj_map();
  }

  ucsan_tainted.buf = buf;
  ucsan_tainted.buf_size = file_size;

  return object_cnt;
}

void ucsan_input::build_obj_map() {
  uint32_t object_id = 1;
  UCSAN_OUT("build_obj_map: objects->size()=%lu\n", (uint64_t)objects->size());

  for (; object_id < objects->size(); ++object_id) {
    ObjectOrigin& object_meta = objects->at(object_id).origin;
    UCSAN_OUT("  obj[%u]: from.obj_id=%u, from.offset=%d\n",
              object_id, object_meta.obj_id, object_meta.offset);
    obj_map->insert(object_meta.obj_id, object_meta.offset, object_id);
  }

  atomic_store(&__ucsan_inited_objects, object_id, memory_order_relaxed);
  UCSAN_OUT("build_obj_map done: __ucsan_inited_objects=%u, obj_map->size()=%lu\n",
            object_id, (uint64_t)obj_map->size());

  // Debug: dump obj_map contents
  UCSAN_OUT("obj_map contents:\n");
  for (uint32_t i = 0; i < obj_map->cap; i++) {
    if (obj_map->entries[i].occupied)
      UCSAN_OUT("  {%u, %d} -> %u\n", obj_map->entries[i].key.first,
                obj_map->entries[i].key.second, obj_map->entries[i].value);
  }
}

//===----------------------------------------------------------------------===//
// Label Management
//===----------------------------------------------------------------------===//

ucsan_label_info* get_label_info(ucsan_label label) {
  return &__ucsan_label_info[label];
}

ucsan_label allocate_label() {
  return atomic_fetch_add(&__ucsan_last_label, 1, memory_order_relaxed) + 1;
}

void check_label(ucsan_label label) {
  if (label >= __alloca_stack_top) {
    Report("FATAL: UCSan: exhausted labels\n");
    Die();
  }
}

//===----------------------------------------------------------------------===//
// Memory Helpers
//===----------------------------------------------------------------------===//

void* customized_malloc(uint64_t size) {
  if (size > UCSAN_OBJECT_SIZE_LIMIT) {
    UCSAN_OUT("Object size too large: %lu\n", size);
    exit(exit_reason::REASON_OBJ_OOB);
  }
  uint64_t gap = Max((uint64_t)UCSAN_SAFE_GAP, UCSAN_ROUNDUPGAP(size));
  uint64_t crafted_size = size + (gap << 1);
  char* ret = (char*)malloc(crafted_size) + gap;
  return (void*)ret;
}

static inline bool is_writeable(void *p) {
  int fd = open("/dev/zero", O_RDONLY);
  if (fd < 0) return false;
  bool writeable = read(fd, p, 1) == 1;
  close(fd);
  return writeable;
}

//===----------------------------------------------------------------------===//
// Object Lookup
//===----------------------------------------------------------------------===//

UCSanObject& lookup_object(ucsan_label label, uint64_t offset, void* return_addr, uint32_t *ret_object_id, uint32_t type_id, uint32_t size) {
  if (label) {
    ucsan_label_info *label_info = get_label_info(label);
    uint32_t object_id = 0;
    // Use wider types for range checking before casting
    uint64_t parent_obj_id_64 = 0;
    int64_t offset_in_parent_64 = 0;

    uint16_t op = label_info->common.op;
    if (op == OP_NONE) {
      // Byte info - look up by (object_id, offset)
      ucsan_byte_info *byte = &label_info->byte;
      UCSAN_OUT("lookup_object: label=%u, op=BYTE, obj_id=%u, offset=%ld\n",
                label, byte->object_id, byte->offset);
      parent_obj_id_64 = byte->object_id;
      offset_in_parent_64 = byte->offset;
    } else if (op == OP_EXTERNAL) {
      // External pointer - look up by (parent_obj_id, offset)
      // This matches dfsan's {op2.i, op1.i} pattern
      ucsan_ptr_info *ptr = &label_info->ptr;
      parent_obj_id_64 = ptr->obj_label;
      offset_in_parent_64 = (int64_t)(uint64_t)ptr->pseudo_base;
      UCSAN_OUT("lookup_object: label=%u, op=EXTERNAL, parent_obj=%lu, offset=%ld\n",
                label, parent_obj_id_64, offset_in_parent_64);
      UCSAN_OUT("  obj_map size=%lu, searching for {%lu, %ld}\n",
                (uint64_t)ucsan_tainted.obj_map->size(), parent_obj_id_64, offset_in_parent_64);
    } else {
      UCSAN_OUT("WARNING: unexpected op=%u label=%u\n", op, label);
    }

    // Range check before casting to narrower types for map key
    if (parent_obj_id_64 > UINT32_MAX) {
      UCSAN_OUT("WARNING: UCSan: parent_obj_id too large: %lu\n", parent_obj_id_64);
      goto out_default;
    }
    if (offset_in_parent_64 > INT32_MAX || offset_in_parent_64 < INT32_MIN) {
      UCSAN_OUT("WARNING: UCSan: offset_in_parent out of range: %ld\n", offset_in_parent_64);
      goto out_default;
    }

    uint32_t parent_obj_id = (uint32_t)parent_obj_id_64;
    int32_t offset_in_parent = (int32_t)offset_in_parent_64;

    uint32_t *found_val = ucsan_tainted.obj_map->find_val(parent_obj_id, offset_in_parent);
    if (found_val) {
      object_id = *found_val;
      UCSAN_OUT("  found object_id=%u\n", object_id);
    } else {
      UCSAN_OUT("  NOT found in obj_map\n");
    }

    bool created = false;
    if (object_id == 0) {
      // Allocate next object ID
      // Counter starts at 1, so first allocation gets ID 1 (object 0 is super object)
      // fetch_add returns old value, then increments for next allocation
      object_id = atomic_fetch_add(&__ucsan_inited_objects, 1, memory_order_relaxed);
      created = true;
    }

    if (object_id >= ucsan_tainted.objects->size()) {
      UCSanObject new_obj;
      new_obj.offset = 0;
      new_obj.data.init();
      new_obj.origin = {0, 0};
      ucsan_tainted.objects->push_back(new_obj);
    }

    // Trace lazy init event if enabled
    if (created && ucsan_flags().trace_object) {
      // Pack object_id (lower 32 bits) and parent_obj_id (upper 32 bits) into uint64_t
      uint64_t info = ((uint64_t)parent_obj_id << 32) | object_id;
      __taint_trace_event_addr(label, EVENT_LAZY_INIT, info, return_addr,
                               (uint32_t)offset_in_parent);
      // Send type/size binding for the newly created object
      // result = object_id (lower 32) | size (upper 32), id = type_id
      uint64_t bind_info = ((uint64_t)size << 32) | object_id;
      __taint_trace_event_addr(label, EVENT_TYPE_BIND, bind_info, return_addr, type_id);
    }

    if (ret_object_id) *ret_object_id = object_id;
    return ucsan_tainted.objects->at(object_id);
  }

out_default:

  // Should not reach here with label == 0
  static UCSanObject empty_object;
  return empty_object;
}

//===----------------------------------------------------------------------===//
// Super Object Label Creation
//===----------------------------------------------------------------------===//

object_info create_label_from_super_object(size_t size, bool is_pointer) {
  uint64_t offset = atomic_fetch_add(&ucsan_tainted.arg_used, size, memory_order_relaxed);
  ucsan_label label = allocate_label();

  ucsan_label_info *label_info = get_label_info(label);

  if (is_pointer) {
    // Create pointer info
    // For lookup purposes, we store parent_obj_id in obj_label and offset in _padding
    // This matches dfsan's approach where op2.i=parent_obj_id and op1.i=offset
    ucsan_ptr_info *ptr = &label_info->ptr;
    ptr->op = OP_EXTERNAL;
    ptr->status = PTR_UNINITIALIZED;
    ptr->obj_label = 0;  // parent object ID (0 = super object)
    ptr->pseudo_base = (void*)offset;  // Repurpose to store offset for lookup
  } else {
    // Create byte info for super object (object 0)
    ucsan_byte_info *byte = &label_info->byte;
    byte->op = OP_NONE;
    byte->object_id = 0;  // super object
    byte->offset = (int64_t)offset;
  }

  return {label, offset};
}

}  // namespace __ucsan

//===----------------------------------------------------------------------===//
// Core UCSan Functions
//===----------------------------------------------------------------------===//

using namespace __ucsan;

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void* ucsan_check_pointer(void* p, ucsan_label label, size_t size, bool dereferencing, uint32_t type_id) {
  UCSAN_OUT("%p: label: %d, size: %zu, dereferencing: %d, type_id: %u\n", p, label, size, dereferencing, type_id);
  __ucsan_null_deref_flag = nullptr;

  // Handle unlabeled or special labels
  if (label < UCSAN_CONST_OFFSET) {
    // Global variable handling - symbolize on first access
    if (in_data_section(p)) {
      ucsan_label *shadow = ucsan_shadow_for(p);
      if (*shadow == 0) {
        bool sent_data = false;
        for (uint64_t i = 0; i < size; ++i) {
          void *byte_addr = (void*)((uint64_t)p + i);
          shadow = ucsan_shadow_for(byte_addr);
          auto ret = create_label_from_super_object(1, false);
          *shadow = ret.label;
          UCSAN_OUT("Symbolize global variable byte @%p with %u from offset %lu\n",
                    ((char*)p+i), ret.label, ret.offset);

          // Bridge to SymSan: create symbolic label for this byte and set shadow
          dfsan_label symsan_label = __taint_create_label(0, ret.offset, 1);
          __taint_set_label(symsan_label, byte_addr, 1);

          // Initialize from seed data if available
          if (ucsan_tainted.objects->size() && ret.offset < ucsan_tainted.objects->at(0).data.size()) {
            *((char*)p + i) = ucsan_tainted.objects->at(0).data.at(ret.offset);
          } else if (!in_bss_section(p) && *((char*)p + i) != 0) {
            sent_data = true;
          }
        }

        // Trace global variable usage
        if (ucsan_flags().trace_object) {
          ucsan_label first_label = *(ucsan_shadow_for(p));
          ucsan_label_info *info = get_label_info(first_label);
          // globals are from super object, so object_id is always 0
          int64_t offset = to_byte_info(info)->offset;
          if (offset > INT32_MAX || offset < INT32_MIN) {
            UCSAN_OUT("WARNING: global variable offset (%ld) too large\n", offset);
          } else {
            __taint_trace_event_addr(*(ucsan_shadow_for(p)), EVENT_USAGE_CITE, type_id,
                                     __builtin_return_address(0), (uint32_t)offset);
          }
        }

        // Send initial data if needed
        if (sent_data) {
          UCSAN_OUT("Sent init data for global variable @%p\n", p);
          __taint_trace_global_var(*(ucsan_shadow_for(p)), size, p);
        }
      }
    }

    // Null dereference checking
    if (dereferencing && ucsan_flags().checker_nullderef) {
      if ((uint64_t)p < size || (uint64_t)p < UCSAN_OBJECT_SIZE_LIMIT) {
        // Trace null dereference event
        __taint_trace_event_addr(label, EVENT_NULL_DEREF, 0, __builtin_return_address(0), 0);
        exit(exit_reason::EVENT_NULL_DEREF);
      } else {
        __ucsan_null_deref_flag = __builtin_return_address(0);
      }
    }
    return p;
  }

  // Use-before-initialization check
  UCSAN_OUT("UBI check: label=%u, kUninitializedLabel=%u, equal=%d, dereferencing=%d\n",
            label, kUninitializedLabel, (label == kUninitializedLabel), dereferencing);
  if (label == kUninitializedLabel) {
    UCSAN_OUT("UBI detected!\n");
    if (dereferencing) {
      // Trace use-before-initialization event
      __taint_trace_event_addr(label, EVENT_UBI, 0, __builtin_return_address(0), 0);
      exit(exit_reason::EVENT_UBI);
    }
    return p;
  }

  ucsan_label_info *label_info = get_label_info(label);

  UCSAN_OUT("label %u: op=%u, trace_bounds=%d\n", label, label_info->common.op, ucsan_flags().trace_bounds);

  // Bounds checking when trace_bounds is enabled
  if (ucsan_flags().trace_bounds) {
    // Check for stack UAF - accessing freed stack allocations
    // Heap labels: UCSAN_CONST_OFFSET to __ucsan_last_label (growing upward)
    // Stack labels: __alloca_stack_top to __alloca_stack_bottom (growing downward from top)
    // Freed stack region: __ucsan_last_label < label < __alloca_stack_top
    ucsan_label last_heap_label = atomic_load(&__ucsan_last_label, memory_order_relaxed);
    if (label > last_heap_label && label < __alloca_stack_top) {
      // Label is in the freed stack region
      UCSAN_OUT("ERROR: Stack UAF detected ptr %p, label = %u (last_heap = %u, stack_top = %u)\n",
                p, label, last_heap_label, __alloca_stack_top);
      if (dereferencing) {
        __taint_trace_event_addr(label, EVENT_UAF, 0, __builtin_return_address(0), 0);
        exit(exit_reason::EVENT_UAF);
      }
      return p;
    }

    // Check for heap UAF - freed heap memory
    if (label_info->common.op == OP_FREE) {
      UCSAN_OUT("ERROR: Heap UAF detected ptr %p, label = %u\n", p, label);
      if (dereferencing) {
        __taint_trace_event_addr(label, EVENT_UAF, 0, __builtin_return_address(0), 0);
        exit(exit_reason::EVENT_UAF);
      }
      return p;
    }

    // Check for OOB - heap/stack allocated memory with bounds tracking
    if (label_info->common.op == OP_ALLOCA) {
      ucsan_obj_info *obj = to_obj_info(label_info);
      void *base = obj->real_ptr;
      uint64_t lower = (uint64_t)base - obj->lower_bound;
      uint64_t upper = (uint64_t)base + obj->upper_bound;

      UCSAN_OUT("OOB check: ptr=%p, base=%p, lower=%p, upper=%p, size=%zu\n",
                p, base, (void*)lower, (void*)upper, size);

      if ((uint64_t)p < lower || (uint64_t)p >= upper ||
          (uint64_t)p + size > upper) {
        UCSAN_OUT("ERROR: OOB access ptr %p, lower = %p, upper = %p, size = %zu, label = %u, deref=%d\n",
                  p, (void*)lower, (void*)upper, size, label, dereferencing);
        if (dereferencing) {
          __taint_trace_event_addr(label, EVENT_OOB, 0, __builtin_return_address(0), 0);
          exit(exit_reason::EVENT_OOB);
        }
      }
      return p;
    }
  }

  ucsan_ptr_info *ptr_info = to_ptr_info(label_info);

  // Mark as external if needed - create a new pointer label for non-pointer types
  if (ptr_info->op != OP_EXTERNAL && ptr_info->op != OP_NONE) {
    ucsan_label new_label = allocate_label();
    check_label(new_label);
    ucsan_label_info *new_info = get_label_info(new_label);
    ucsan_ptr_info *new_ptr = to_ptr_info(new_info);
    new_ptr->op = OP_BITCAST;
    new_ptr->status = PTR_UNINITIALIZED;
    new_ptr->obj_label = UCSAN_CONST_LABEL;
    new_ptr->pseudo_base = nullptr;
    ptr_info = new_ptr;
  }

  if (ptr_info->op == OP_NONE || ptr_info->op == OP_BITCAST) {
    ptr_info->op = OP_EXTERNAL;
    ptr_info->status = PTR_UNINITIALIZED;
  }

  // Handle uninitialized pointer - lazy initialization
  if (ptr_info->status == PTR_UNINITIALIZED) {
    UCSAN_OUT("check pointer: uninit pointer\n");

    uint32_t object_id;
    void *return_addr = __builtin_return_address(0);
    auto& obj = lookup_object(label, 0, return_addr, &object_id, type_id, (uint32_t)size);
    size_t object_size = obj.data.size();

    UCSAN_OUT("Find object_id: %u (size = %zu) for label %u, addr %p\n",
              object_id, object_size, label, return_addr);

    if (type_id == 0 && size == 0) {
      // Typeless with unknown length (e.g. strcmp): ensure at least 1 byte '\0'
      // If seed data populated the object, use that size instead
      if (obj.data.size() == 0) {
        obj.data.resize(1);
        obj.data[0] = '\0';
      }
    } else if (obj.data.size() < size) {
      obj.data.resize(size);
    }
    object_size = obj.data.size();

    // Create object label
    ucsan_label obj_label = allocate_label();
    check_label(obj_label);

    void* np = customized_malloc(object_size);
    internal_memcpy(np, obj.data.data(), object_size);

    ucsan_obj_info *obj_label_info = to_obj_info(get_label_info(obj_label));
    obj_label_info->lower_bound = obj.offset;
    obj_label_info->upper_bound = (uint32_t)object_size - obj.offset;
    obj_label_info->real_ptr = (char*)np + obj.offset;
    obj_label_info->op = OP_RESERVED_OBJ;
    obj_label_info->object_id = object_id;

    ptr_info->obj_label = obj_label;
    ptr_info->pseudo_base = p;  // Store original pseudo pointer in ptr_info

    // Create labels for each byte in the object and set up shadow memory
    for (uint64_t offset = 0; offset < object_size; ++offset) {
      ucsan_label byte_label = allocate_label();
      check_label(byte_label);

      ucsan_label_info *byte_info = get_label_info(byte_label);
      ucsan_byte_info *byte = to_byte_info(byte_info);
      byte->op = OP_NONE;
      byte->object_id = object_id;
      byte->offset = offset - obj.offset;

      void *nptr = (void*)((uint64_t)np + offset);
      ucsan_label *shadow = ucsan_shadow_for(nptr);
      *shadow = byte_label;

      // Bridge to SymSan: create symbolic label for this byte and set shadow
      dfsan_label symsan_label = __taint_create_label(object_id, byte->offset, 1);
      __taint_set_label(symsan_label, nptr, 1);
    }

    ptr_info->status = PTR_INITIALIZED;
    return (char*)np + obj.offset;

  } else if (ptr_info->status == PTR_INITIALIZED) {
    UCSAN_OUT("check pointer: pointer allocated\n");

    ucsan_label obj_label = ptr_info->obj_label;
    ucsan_obj_info *obj_label_info = to_obj_info(get_label_info(obj_label));
    uint32_t object_id = obj_label_info->object_id;

    void *obj_base = obj_label_info->real_ptr;
    int64_t pseudo_base = (int64_t)ptr_info->pseudo_base;  // Read from ptr_info
    int64_t desired_offset = (int64_t)p - pseudo_base;

    if (ucsan_flags().no_upcast && desired_offset < 0) {
      UCSAN_OUT("Upcast disallowed by no_upcast flag\n");
      exit(exit_reason::EVENT_OOB_UPCAST);
    }

    // Fast path: within current bounds
    int64_t lower_bound = pseudo_base - obj_label_info->lower_bound;
    int64_t upper_bound = pseudo_base + obj_label_info->upper_bound;

    if (lower_bound <= (int64_t)p && (int64_t)p + (int64_t)size <= upper_bound) {
      void* target = (void*)((int64_t)obj_base + desired_offset);
      UCSAN_OUT("Fast path: returning %p\n", target);
      return target;
    }

    /*
      remarkable offsets in an ascending order:
      ---------------------
      0                     -> new lowest offset
      ---------------------
      extended_lower        -> extended bytes in the lower bound
      ---------------------
      new_lower_bound       -> the new lower bound, the data between extended_lower 
                              and new_lower_bound is copied from the original object
      [new_size]            -> e.g. array access to the previous element, like a[-1]
      ---------------------
      original_size         -> the original size, the data from new_lower_bound to 
                              this is copied from the original object
      ---------------------
      [new_size]            -> e.g. use container_of access to a larger object
      ---------------------
    */

    // Slow path: need to enlarge object
    uint64_t original_size = obj_label_info->lower_bound + obj_label_info->upper_bound;
    uint64_t extended_lower = 0;
    uint64_t new_lower_bound = obj_label_info->lower_bound;

    if (desired_offset < 0 && desired_offset < -(int64_t)new_lower_bound) {
      extended_lower = -desired_offset - new_lower_bound;
      new_lower_bound = -desired_offset;
      UCSAN_OUT("Extended lower bound: %lu, new lower bound: %lu\n",
                extended_lower, new_lower_bound);
      if (ucsan_flags().trace_object) {
        __taint_trace_event_addr(label, EVENT_EXTENSION, object_id,
                                 __builtin_return_address(0),
                                 (uint32_t)new_lower_bound);
        {
          uint64_t bind_info = ((uint64_t)size << 32) | object_id;
          __taint_trace_event_addr(label, EVENT_TYPE_BIND, bind_info,
                                   __builtin_return_address(0), type_id);
        }
      }
    }

    uint64_t new_size = new_lower_bound + Max(desired_offset + (int64_t)size,
                                         (int64_t)obj_label_info->upper_bound);

    if (new_size > UCSAN_OBJECT_SIZE_LIMIT) {
      UCSAN_OUT("Object size too large: %lu\n", new_size);
      exit(exit_reason::REASON_OBJ_OOB);
    }

    void *np = customized_malloc(new_size);
    UCSAN_OUT("Enlarged object: np=%p, new_size=%lu\n", np, new_size);

    // Copy and extend shadow memory
    // Padding the left lower bounds with new labels
    for (uint64_t offset = 0; offset < extended_lower; ++offset) {
      ucsan_label byte_label = allocate_label();
      check_label(byte_label);

      ucsan_label_info *byte_info = get_label_info(byte_label);
      ucsan_byte_info *byte = to_byte_info(byte_info);
      byte->op = OP_NONE;
      byte->object_id = object_id;
      byte->offset = (int64_t)offset - (int64_t)new_lower_bound;

      void *nptr = (void*)((uint64_t)np + offset);
      *ucsan_shadow_for(nptr) = byte_label;

      // Bridge to SymSan: create symbolic label for this byte and set shadow
      dfsan_label symsan_label = __taint_create_label(object_id, byte->offset, 1);
      __taint_set_label(symsan_label, nptr, 1);
    }

    // Copy shadow memory from original object
    void *dst_addr = (void*)((int64_t)np + extended_lower);
    ucsan_label *shadow = ucsan_shadow_for(dst_addr);
    internal_memcpy(shadow, ucsan_shadow_for(obj_base), original_size * sizeof(ucsan_label));

    // Bridge to SymSan: copy shadow memory
    __taint_copy_shadow(dst_addr, obj_base, original_size);

    // Copy original data
    internal_memcpy((char*)np + extended_lower, obj_base, original_size);

    // Padding the right upper bounds with new labels
    for (uint64_t offset = extended_lower + original_size; offset < new_size; ++offset) {
      ucsan_label byte_label = allocate_label();
      check_label(byte_label);

      ucsan_label_info *byte_info = get_label_info(byte_label);
      ucsan_byte_info *byte = to_byte_info(byte_info);
      byte->op = OP_NONE;
      byte->object_id = object_id;
      byte->offset = offset - new_lower_bound;

      void *nptr = (void*)((uint64_t)np + offset);
      *ucsan_shadow_for(nptr) = byte_label;

      // Bridge to SymSan: create symbolic label for this byte and set shadow
      dfsan_label symsan_label = __taint_create_label(object_id, byte->offset, 1);
      __taint_set_label(symsan_label, nptr, 1);
    }

    // Update object info
    obj_label_info->lower_bound = (uint32_t)new_lower_bound;
    obj_label_info->upper_bound = (uint32_t)(new_size - new_lower_bound);
    obj_label_info->real_ptr = (char*)np + new_lower_bound;

    return (void*)((int64_t)np + desired_offset);
  }

  UCSAN_OUT("Unknown pointer state: %d\n", ptr_info->status);
  return nullptr;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_check_ptr_arg(ucsan_label *label, uint32_t arg_index, void* ret_addr) {
  if (label[0] == kUninitializedLabel) {
    // Trace use-before-initialization event
    __taint_trace_event_addr(label[0], EVENT_UBI, arg_index, ret_addr, 0);
    exit(exit_reason::EVENT_UBI);
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_check_ubi(ucsan_label label) {
  UCSAN_OUT("ucsan_check_ubi: label=%u, kUninitializedLabel=%u\n", label, kUninitializedLabel);
  if (label == kUninitializedLabel) {
    UCSAN_OUT("UBI detected in scalar load!\n");
    // Trace use-before-initialization event
    __taint_trace_event_addr(label, EVENT_UBI, 0, __builtin_return_address(0), 0);
    exit(exit_reason::EVENT_UBI);
  }
}

// Combine two labels for binary operations
// Returns kUninitializedLabel if either operand is uninitialized
// Warns if a pointer label is used in arithmetic
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
ucsan_label ucsan_combine_label(ucsan_label l1, ucsan_label l2) {
  // If either label is uninitialized, propagate it
  if (l1 == kUninitializedLabel || l2 == kUninitializedLabel) {
    UCSAN_OUT("ucsan_combine_label: propagating kUninitializedLabel (l1=%u, l2=%u)\n", l1, l2);
    return kUninitializedLabel;
  }

  // Check if a pointer is used with a non-zero non-pointer value
  // Pointer with zero is fine (comparison or null-offset arithmetic)
  bool l1_is_ptr = false, l2_is_ptr = false;
  if (l1 != 0) {
    ucsan_label_info *info = get_label_info(l1);
    l1_is_ptr = info && (info->common.op == OP_EXTERNAL || info->common.op == OP_ALLOCA);
    if (info->common.op == OP_NONE && !l2) {
      // l1 is under-constrained and l2 is concrete, allow it
      return l1;
    }
  }
  if (l2 != 0) {
    ucsan_label_info *info = get_label_info(l2);
    l2_is_ptr = info && (info->common.op == OP_EXTERNAL || info->common.op == OP_ALLOCA);
    if (info->common.op == OP_NONE && !l1) {
      // l2 is under-constrained and l1 is concrete, allow it
      return l2;
    }
  }
  // Warn only if pointer is combined with non-zero non-pointer
  if (l1_is_ptr && l2 != 0 && !l2_is_ptr) {
    UCSAN_OUT("WARNING: pointer label %u used in binary operation with non-pointer %u\n", l1, l2);
  }
  if (l2_is_ptr && l1 != 0 && !l1_is_ptr) {
    UCSAN_OUT("WARNING: pointer label %u used in binary operation with non-pointer %u\n", l2, l1);
  }

  // Return 0 - we don't track symbolic expressions in standalone mode
  return 0;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
ucsan_label ucsan_load_pointer_shadow(ucsan_label *ls, uint64_t n, bool is_pointer) {
  if (ls == nullptr) return 0;

  ucsan_label label0 = ls[0];

  UCSAN_OUT("load_pointer_shadow: *label(%p)=%d is_pointer=%d, size=%lu\n",
            ls, label0, is_pointer, n);

  // Allow loading kUninitializedLabel for UBI detection
  if (label0 == kUninitializedLabel) {
    return label0;
  }

  ucsan_label_info *label_info = get_label_info(label0);

  if (is_pointer) {
    if (label0 >= UCSAN_CONST_OFFSET && label_info->common.op == OP_NONE) {
      // Convert byte label to pointer label
      ucsan_ptr_info *ptr = to_ptr_info(label_info);
      ptr->op = OP_EXTERNAL;
      ptr->status = PTR_UNINITIALIZED;
    }
    return label0;
  }

  // Load pointer but not as pointer type
  if (label0 >= UCSAN_CONST_OFFSET &&
      (label_info->common.op == OP_EXTERNAL || label_info->common.op == OP_NONE ||
       label_info->common.op == OP_ALLOCA || label_info->common.op == OP_FREE) &&
      n == sizeof(void*)) {
    return label0;
  }

  return 0;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_store_pointer_shadow(ucsan_label l, ucsan_label *ls, uint64_t n) {
  UCSAN_OUT("store_pointer_shadow: label=%d, n=%lu, ls=%p\n", l, n, ls);

  if (l == 0 || l == kUninitializedLabel) {
    for (uint64_t i = 0; i < n; ++i) ls[i] = l;
    return;
  }

  ucsan_label_info *label_info = get_label_info(l);
  if (label_info->common.op == OP_EXTERNAL ||
      label_info->common.op == OP_NONE ||
      label_info->common.op == OP_ALLOCA ||
      label_info->common.op == OP_FREE) {
    assert(n == sizeof(void*));
    ls[0] = l;
    return;
  }

  Report("WARNING: storing non-pointer label %d (op=%d) shadow\n", l, label_info->common.op);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_set_label(ucsan_label label, void *addr, uint64_t size) {
  UCSAN_OUT("ucsan_set_label: label=%d, addr=%p, size=%lu\n", label, addr, size);

  // Get shadow address for the memory region
  ucsan_label *shadow = ucsan_shadow_for(addr);

  // Set the label for each byte in the region
  for (uint64_t i = 0; i < size; ++i) {
    shadow[i] = label;
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void* ucsan_set_label_for_args(uint32_t index, uint32_t size_in_bits, uint8_t is_pointer, uint64_t given) {
  UCSAN_OUT("set_label_for_args: index=%u, size_in_bits=%u, is_pointer=%d\n",
            index, size_in_bits, is_pointer);

  size_t size_in_bytes = (size_in_bits + 7) / 8;
  auto ret = create_label_from_super_object(size_in_bytes, is_pointer);

  UCSAN_OUT("set label %u for index %u\n", ret.label, index);

  // Handle truncation if size_in_bits < size_in_bytes * 8
  // Note: UCSan doesn't have union operations, truncation is implicit
  // The label represents the full byte(s), actual bit size is tracked elsewhere

  __ucsan_arg_tls[index] = ret.label;

  // Bridge to SymSan: create symbolic label and set arg TLS
  // object_id=0 for function arguments, offset from super object
  dfsan_label symsan_label = __taint_create_label(0, ret.offset, size_in_bytes);
  __taint_set_arg_tls(index, symsan_label, size_in_bits);

  uint64_t last_offset = ret.offset;

  // Ensure objects is allocated
  if (!ucsan_tainted.objects) {
    ucsan_tainted.objects = new ObjectStorage();
  }

  if (ucsan_tainted.objects->size() &&
      last_offset + size_in_bytes <= ucsan_tainted.objects->at(0).data.size()) {
    uint64_t result = *((uint64_t*)(ucsan_tainted.objects->at(0).data.data() + last_offset));
    UCSAN_OUT("Returning: 0x%lx\n", result);
    return (void*)result;
  }

  if (!ucsan_tainted.objects->size()) ucsan_tainted.objects->resize(1);
  ucsan_tainted.objects->at(0).data.resize(last_offset + size_in_bytes);

  return (void*)given;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
ucsan_label ucsan_resign_shadow(void *ptr, ucsan_label *orig_label, uint64_t n, void *ret_addr) {
  ucsan_label label_for_ptr = *orig_label;

  if (ptr == nullptr && label_for_ptr == 0) {
    UCSAN_OUT("Resigning null pointer, skip\n");
    return UCSAN_CONST_LABEL;
  }

  if (label_for_ptr != 0) {
    ucsan_label_info *orig = get_label_info(label_for_ptr);

    if (orig->common.op == OP_ALLOCA) {
      // Handle alloca case - symbolize uninitialized bytes in the allocated region
      UCSAN_OUT("Resign alloca object\n");
      ucsan_obj_info *obj_info = to_obj_info(orig);

      // Calculate bounds: real_ptr is the base, lower_bound is bytes before, upper_bound is bytes after
      char *lower = (char*)obj_info->real_ptr - obj_info->lower_bound;
      char *upper = (char*)obj_info->real_ptr + obj_info->upper_bound;
      ucsan_label *lp = ucsan_shadow_for(lower);
      ucsan_label *le = ucsan_shadow_for(upper);
      char *obj_ptr = lower;

      for (; lp < le; ++lp, ++obj_ptr) {
        if (*lp == kUninitializedLabel) {
          // Allocate a byte from super object
          auto ret = create_label_from_super_object(1, false);
          UCSAN_OUT("resign alloca ret: %u %lu\n", ret.label, ret.offset);
          *lp = ret.label;

          // Bridge to SymSan: create symbolic label for this byte
          dfsan_label symsan_label = __taint_create_label(0, ret.offset, 1);
          __taint_set_label(symsan_label, obj_ptr, 1);

          if (ucsan_tainted.objects->size() && ret.offset < ucsan_tainted.objects->at(0).data.size()) {
            UCSAN_OUT("resign alloca super object: %u\n", ucsan_tainted.objects->at(0).data.at(ret.offset));
            *obj_ptr = ucsan_tainted.objects->at(0).data.at(ret.offset);
          } else {
            *obj_ptr = 0;
          }
        }
      }
      return label_for_ptr;
    } else if (orig->common.op == OP_FREE) {
      // Freed memory - return as-is for UAF detection
      UCSAN_OUT("Resign freed object\n");
      return label_for_ptr;
    } else {
      // Mark as external pointer
      ucsan_ptr_info *ptr_info = to_ptr_info(orig);
      ptr_info->op = OP_EXTERNAL;
      ptr_info->status = PTR_UNINITIALIZED;
    }
    return label_for_ptr;

  } else {
    if (!is_writeable(ptr)) {
      return UCSAN_CONST_LABEL;
    }

    if (ret_addr == nullptr) {
      ret_addr = __builtin_return_address(0);
    }

    UCSAN_OUT("Concrete external object: p=%p, size=%lu\n", ptr, n);

    // allocate from super object
    auto ret = create_label_from_super_object(n, true);
    uint32_t object_id = 0;
    auto& object = lookup_object(ret.label, 0, ret_addr, &object_id);

    // Set up shadow memory for object bytes
    ucsan_label *shadow = ucsan_shadow_for(ptr);
    for (uptr i = 0; i < n; ++i) {
      ucsan_label next_label = allocate_label();
      check_label(next_label);

      shadow[i] = next_label;
      ucsan_label_info *new_label_info = get_label_info(next_label);
      ucsan_byte_info *byte = to_byte_info(new_label_info);
      byte->op = OP_NONE;
      byte->object_id = object_id;
      byte->offset = i;

      // Bridge to SymSan: create symbolic label for this byte and set shadow
      void *byte_addr = (void*)((uint64_t)ptr + i);
      dfsan_label symsan_label = __taint_create_label(object_id, byte->offset, 1);
      __taint_set_label(symsan_label, byte_addr, 1);
    }

    if (object.data.size() < n) object.data.resize(n);

    for (uptr i = 0; i < n; ++i) {
      ((uint8_t*)ptr)[i] = object.data[i];
    }

    return ret.label;
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void* ucsan_wrap_retval(uint64_t size, ucsan_label *ret_label, bool is_ptr, void* ret_addr) {
  uint64_t bits = size;
  size = (size + 7) >> 3;  // Round up to bytes

  if (ret_addr == nullptr) ret_addr = __builtin_return_address(0);

  // Treat pointer-sized non-pointers as pointers for lazy init
  bool treat_as_ptr = is_ptr || size == sizeof(void*);
  auto lbl = create_label_from_super_object(size, treat_as_ptr);
  ucsan_label label = lbl.label;
  uint64_t last_offset = lbl.offset;

  UCSAN_OUT("Ret object created: label=%u, offset=%lu\n", label, last_offset);

  // Note: create_label_from_super_object already initializes the label_info
  // with the correct op (OP_EXTERNAL for pointers, OP_NONE for bytes)
  // and stores offset/object_id in byte_info or sets up ptr_info

  // TODO: Handle truncation if bits < size * 8

  *ret_label = label;

  // Bridge to SymSan: create symbolic label and set retval TLS at correct index
  // Calculate index from pointer offset into __ucsan_retval_tls
  uint32_t retval_tls_index = (uint32_t)(ret_label - __ucsan_retval_tls);
  dfsan_label symsan_label = __taint_create_label(0, last_offset, (uint32_t)size);
  __taint_set_retval_tls(retval_tls_index, symsan_label, (uint32_t)bits);

  if (ucsan_tainted.objects->size() &&
      last_offset + size <= ucsan_tainted.objects->at(0).data.size()) {
    UCSAN_OUT("offset (%lu + %lu) in the seed\n", last_offset, size);
    for (uptr i = 0; i < size; ++i) {
      __ucsan_wrapped_return_tls[i] = ucsan_tainted.objects->at(0).data[last_offset + i];
    }
  } else {
    for (uptr i = 0; i < size; ++i) {
      __ucsan_wrapped_return_tls[i] = 0;
    }
  }

  return (void*)__ucsan_wrapped_return_tls;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
ucsan_label ucsan_trace_alloca(uint64_t size, uint64_t elem_size, uint64_t addr) {
  // Track stack allocation bounds using stack-based label allocation
  // Labels are allocated from __alloca_stack_top (top of label space, growing downward)
  // and automatically freed when the function exits via __taint_pop_stack_frame
  //
  // size: array size (number of elements)
  // elem_size: size of each element in bytes
  // addr: address of the stack allocation

  if (ucsan_flags().trace_bounds) {
    uint64_t total_size = size * elem_size;
    void *ptr = (void*)addr;

    // Allocate label from stack top (grows downward)
    __alloca_stack_top -= 1;
    ucsan_label label = __alloca_stack_top;

    UCSAN_OUT("ucsan_trace_alloca: label=%u, base=%p, size=%lu, elem_size=%lu, total=%lu\n",
              label, ptr, size, elem_size, total_size);

    ucsan_label_info *info = get_label_info(label);
    ucsan_obj_info *obj = to_obj_info(info);

    // Set up bounds tracking for stack allocation
    obj->op = OP_ALLOCA;
    obj->_reserved = 0;
    obj->object_id = 0;  // Not tracked in objects array (stack allocation)
    obj->real_ptr = ptr;
    obj->lower_bound = 0;           // No bytes before base
    obj->upper_bound = (uint32_t)total_size;   // Total size in bytes

    UCSAN_OUT("  created stack label %u: ptr=%p, lower=0, upper=%u\n",
              label, ptr, obj->upper_bound);

    // Set shadow memory to kUninitializedLabel for UBI detection
    ucsan_label *shadow = ucsan_shadow_for(ptr);
    for (uptr i = 0; i < total_size; i++) {
      shadow[i] = kUninitializedLabel;
    }

    return label;
  } else {
    return 0;
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_push_stack_frame() {
  // Save current stack top when entering a function
  // This allows automatic cleanup of stack allocation labels on function exit
  if (ucsan_flags().trace_bounds) {
    if (__current_saved_stack_index < UCSAN_MAX_SAVED_STACK_ENTRIES) {
      __saved_alloca_stack_top[++__current_saved_stack_index] = __alloca_stack_top;
      UCSAN_OUT("ucsan_push_stack_frame: saved index=%d, stack_top=%u\n",
                __current_saved_stack_index, __alloca_stack_top);
    } else {
      Report("WARNING: UCSan: stack frame save index overflow\n");
    }
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_pop_stack_frame() {
  // Restore stack top when exiting a function
  // This automatically frees all stack allocation labels created in this function
  if (ucsan_flags().trace_bounds) {
    if (__current_saved_stack_index > 0) {
      __alloca_stack_top = __saved_alloca_stack_top[__current_saved_stack_index--];
      UCSAN_OUT("ucsan_pop_stack_frame: restored index=%d, stack_top=%u\n",
                __current_saved_stack_index, __alloca_stack_top);
    } else {
      Report("WARNING: UCSan: stack frame save index underflow\n");
    }
  }
}

//===----------------------------------------------------------------------===//
// Initialization
//===----------------------------------------------------------------------===//

void UCSanFlags::SetDefaults() {
#define UCSAN_FLAG(Type, Name, DefaultValue, Description) Name = DefaultValue;
#include "ucsan_flags.inc"
#undef UCSAN_FLAG
}

static void RegisterUCSanFlags(FlagParser *parser, UCSanFlags *f) {
#define UCSAN_FLAG(Type, Name, DefaultValue, Description) \
  RegisterFlag(parser, #Name, Description, &f->Name);
#include "ucsan_flags.inc"
#undef UCSAN_FLAG
}

static void ucsan_parse_flags() {
  // Set common flags defaults
  SetCommonFlagsDefaults();

  // Set UCSan-specific flag defaults
  ucsan_flags_data.SetDefaults();

  // Create flag parser and register flags
  FlagParser parser;
  RegisterCommonFlags(&parser);
  RegisterUCSanFlags(&parser, &ucsan_flags_data);

  // Parse UCSAN_OPTIONS environment variable
  parser.ParseString(GetEnv("UCSAN_OPTIONS"));

  // Initialize common flags
  InitializeCommonFlags();

  // Report unrecognized flags if verbose
  if (Verbosity()) ReportUnrecognizedFlags();

  // Print help if requested
  if (common_flags()->help) parser.PrintFlagDescriptions();

  // Set debug flag
  ucsan_debug = ucsan_flags_data.debug;
}

static void ucsan_init_shadow_memory() {
  // Map UCSan shadow memory region
  // Shadow: kShadowBase (0x480000000000) to kUnionTableAddr (0x680000000000)
  uptr shadow_size = kUnionTableAddr - kShadowBase;
  if (!MmapFixedSuperNoReserve(kShadowBase, shadow_size)) {
    Printf("FATAL: UCSan: failed to map shadow memory\n");
    Die();
  }

  // Map UCSan union table
  if (!MmapFixedSuperNoReserve(kUnionTableAddr, kUnionTableSize)) {
    Printf("FATAL: UCSan: failed to map union table\n");
    Die();
  }

  // Initialize label info pointer
  __ucsan_label_info = (ucsan_label_info *)kUnionTableAddr;

  // Initialize constant label (label 0)
  internal_memset(&__ucsan_label_info[UCSAN_CONST_LABEL], 0, sizeof(ucsan_label_info));

  // Initialize label counter (start from 1, 0 is CONST_LABEL)
  atomic_store(&__ucsan_last_label, UCSAN_CONST_OFFSET, memory_order_relaxed);

  // Initialize object counter
  atomic_store(&__ucsan_inited_objects, 1, memory_order_relaxed);

  // Initialize alloca stack for bounds tracking
  uptr num_labels = kUnionTableSize / sizeof(ucsan_label_info);
  __alloca_stack_top = __alloca_stack_bottom = (ucsan_label)(num_labels - 2);
}

static void ucsan_fini_internal() {
  UCSAN_OUT("UCSan runtime finalized\n");

  // Clean up input struct
  ucsan_fini_input_struct();
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_init() {
  // Initialize input struct first (C-style init for preinit_array safety)
  ucsan_init_input_struct();

  // Parse options
  ucsan_parse_flags();

  // Initialize shadow memory and label table
  ucsan_init_shadow_memory();

  // Load input file if specified
  if (ucsan_flags_data.input_file && ucsan_flags_data.input_file[0] != '\0') {
    ucsan_init_input(ucsan_flags_data.input_file);
  }

  // Initialize UCSan solver (thoroupy backend)
  InitializeUCSanSolver();

  // Register cleanup callback
  Atexit(ucsan_fini_internal);
  AddDieCallback(ucsan_fini_internal);

  UCSAN_OUT("UCSan runtime initialized\n");
  UCSAN_OUT("  Shadow:      0x%lx - 0x%lx\n", (uint64_t)kShadowBase, (uint64_t)kUnionTableAddr);
  UCSAN_OUT("  UnionTable:  0x%lx (size: 0x%lx)\n", (uint64_t)kUnionTableAddr, (uint64_t)kUnionTableSize);
  UCSAN_OUT("  Max labels:  %lu\n", (uint64_t)(kUnionTableSize / sizeof(ucsan_label_info)));
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_fini() {
  ucsan_fini_internal();
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_init_input(const char *filename) {
  UCSAN_OUT("ucsan_init_input: %s\n", filename);

  if (!filename || internal_strlen(filename) == 0) {
    return;
  }

  // Map input file
  uptr file_size;
  char *buf = (char *)MapFileToMemory(filename, &file_size);
  if (!buf) {
    Report("WARNING: UCSan: failed to map input file %s\n", filename);
    return;
  }

  uint64_t object_cnt = ucsan_tainted.load(buf, file_size);

  UCSAN_OUT("Loaded %lu objects from %s\n", object_cnt, filename);
}

//===----------------------------------------------------------------------===//
// Preinit Array for Automatic Initialization
//===----------------------------------------------------------------------===//

// Internal init function with standard signature for preinit_array
static void ucsan_init_internal(int argc, char **argv, char **envp) {
  // When linked with dfsan, ensure it is initialized before ucsan
  // (ucsan's fork server must not fork before dfsan_init completes)
  __dfsan_ensure_init(argc, argv, envp);
  ucsan_init();
}

#if SANITIZER_CAN_USE_PREINIT_ARRAY
__attribute__((section(".preinit_array"), used))
static void (*ucsan_init_ptr)(int, char **, char **) = ucsan_init_internal;
#endif

//===----------------------------------------------------------------------===//
// Weak Definitions for Trace Callbacks
//===----------------------------------------------------------------------===//

// These are weak definitions that allow the solver (e.g., thoroupy.cpp) to
// override them with actual implementations. If no solver is linked, these
// empty stubs are used.

extern "C" {

// Weak definition for event tracing
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_event_addr,
                             __ucsan::ucsan_label, uint32_t, uint64_t, void*,
                             uint32_t) {}

// Weak definition for global variable tracing
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_global_var,
                             __ucsan::ucsan_label, uint64_t, void*) {}

// Weak definition for basic block tracing
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_basic_block,
                             uint32_t, uint32_t) {}

// Weak definition for UCSan solver initialization
SANITIZER_INTERFACE_WEAK_DEF(void, InitializeUCSanSolver, void) {}

// Weak definition for dfsan init ordering (overridden by dfsan.cpp when linked)
SANITIZER_INTERFACE_WEAK_DEF(void, __dfsan_ensure_init, int, char**, char**) {}

//===----------------------------------------------------------------------===//
// SymSan Bridge - Weak Stubs
//===----------------------------------------------------------------------===//
// These weak definitions are overridden by SymSan's dfsan.cpp when linked.
// When UCSan runs standalone, these are no-ops.

// Create a SymSan label for input bytes
// @param object_id: input source identifier (fd, socket, etc.)
// @param offset: byte offset within the source
// @param size_in_bytes: size of the input in bytes
// @return: SymSan label (0 when standalone)
SANITIZER_INTERFACE_WEAK_DEF(dfsan_label, __taint_create_label, uint32_t, uint64_t, uint32_t) {
  return 0;  // CONST_LABEL when standalone
}

// Set SymSan arg TLS entry
// @param index: argument index
// @param label: SymSan label to set
// @param size_in_bits: size of argument in bits (for truncation)
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_set_arg_tls, uint32_t, dfsan_label, uint32_t) {}

// Set SymSan retval TLS entry
// @param index: index into retval TLS array (for struct elements)
// @param label: SymSan label to set
// @param size_in_bits: size of return value in bits (for truncation)
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_set_retval_tls, uint32_t, dfsan_label, uint32_t) {}

// Set SymSan shadow memory for a region
// @param label: SymSan label to set
// @param addr: memory address
// @param size: size in bytes
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_set_label, dfsan_label, void*, uint64_t) {}

// Copy SymSan shadow memory from src to dst
// @param dst: destination address
// @param src: source address
// @param size: size in bytes
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_copy_shadow, void*, void*, uint64_t) {}

// Move SymSan shadow memory from src to dst (handles overlapping regions)
// @param dst: destination address
// @param src: source address
// @param size: size in bytes
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_move_shadow, void*, void*, uint64_t) {}

// Get or create an Alloca bounds label for a pointer
// @param ptr: pointer (NULL to always create new)
// @param lower: lower bound address
// @param upper: upper bound address
// @return: Alloca label (0 when standalone)
SANITIZER_INTERFACE_WEAK_DEF(dfsan_label, __taint_get_ptr_bounds_label, void*, uint64_t, uint64_t) {
  return 0;
}

}  // extern "C"
