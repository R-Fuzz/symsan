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
#include "ucsan_containers.h"
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
void __taint_trace_event_addr(uint32_t label, uint32_t event_id,
                              uint64_t info, void* addr, uint32_t info2);

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_trace_global_var(uint32_t obj_id, uint64_t offset, uint64_t size, void *gv);

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
dfsan_label __taint_union(dfsan_label l1, dfsan_label l2, uint16_t op,
                          uint16_t size, uint64_t op1, uint64_t op2);

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_copy_shadow(void *dst, void *src, uint64_t size);

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_verify_input_bytes(const void *addr, uptr n, void *site);

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

// Address range map for __ucsan_symbolize_input pointer relationship discovery
static AddrRangeMap __symbolize_addr_map;
static bool __symbolize_addr_map_inited = false;

// Address range map for fixed-size global object bounds.
static AddrRangeMap __global_bounds_map;
static bool __global_bounds_map_inited = false;

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
  // Include metadata: origin info per object (obj_id, offset, target_offset)
  length += objects->size() * 3 * sizeof(uint64_t);

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

  // Write metadata: origin info (obj_id, offset, target_offset) per object
  for (uint32_t i = 0; i < objects->size(); i++) {
    tmp = objects->at(i).origin.obj_id;
    internal_memcpy(pos, &tmp, sizeof(uint64_t));
    pos += sizeof(uint64_t);
    tmp = (uint64_t)(int64_t)objects->at(i).origin.offset;
    internal_memcpy(pos, &tmp, sizeof(uint64_t));
    pos += sizeof(uint64_t);
    tmp = objects->at(i).origin.target_offset;
    internal_memcpy(pos, &tmp, sizeof(uint64_t));
    pos += sizeof(uint64_t);
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
    obj.origin = {0, 0, 0};
    ucsan_tainted.objects->push_back(obj);
    cursor += sizes[i];
  }

  // Load metadata if present
  if (cursor < buf + file_size) {
    // Determine metadata entry size: 3 uint64_t (with target_offset) or 2 (legacy)
    size_t remaining = (buf + file_size) - cursor;
    size_t meta_entry_size = (remaining >= object_cnt * sizeof(uint64_t) * 3)
                             ? sizeof(uint64_t) * 3 : sizeof(uint64_t) * 2;
    for (uint64_t i = 0; i < object_cnt && cursor + meta_entry_size <= buf + file_size; ++i) {
      ucsan_tainted.objects->at(i).origin.obj_id = *(uint64_t *)cursor;
      cursor += sizeof(uint64_t);
      ucsan_tainted.objects->at(i).origin.offset = *(uint64_t *)cursor;
      cursor += sizeof(uint64_t);
      if (meta_entry_size == sizeof(uint64_t) * 3) {
        uint64_t target_offset = *(uint64_t *)cursor;
        cursor += sizeof(uint64_t);
        ucsan_tainted.objects->at(i).origin.target_offset = (uint32_t)target_offset;
        // Override obj.offset with target_offset from metadata if non-zero
        if (target_offset > 0) {
          ucsan_tainted.objects->at(i).offset = (uint32_t)target_offset;
        }
      }
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

void check_label(ucsan_label label) {
  if (label >= __alloca_stack_top) {
    Report("FATAL: UCSan: exhausted labels\n");
    Die();
  }
}

ucsan_label allocate_label() {
  ucsan_label label = atomic_fetch_add(&__ucsan_last_label, 1, memory_order_relaxed) + 1;
  check_label(label);
  return label;
}

//===----------------------------------------------------------------------===//
// Memory Helpers
//===----------------------------------------------------------------------===//

// A lazily created object never moves.  It used to be copied to a larger
// buffer when an access fell outside it, and a real address already handed
// out -- a check_pointer result the pass reuses for later accesses
// (CheckedPtrMap), one hoisted to a dominating block, a pointer a wrapper
// returned -- kept pointing into the old buffer: writes through it were lost
// to the object and reads were stale, silently.  Instead each object gets a
// window twice the object size limit with its offset 0 in the middle, so it
// can grow either way in place up to the limit, which bounds its total size.
// Windows come from large no-reserve mappings: only touched pages cost
// memory.  Returns the window's middle, the object's offset 0.
// (plus the page offset of the pseudo pointer the object is created for, so
// a real address is the pseudo one's equal modulo the page: code aligns a
// pointer by its value -- i915_unaligned_memcpy_from_wc rounds src up to 16
// bytes, from the pseudo pointer, before movntdqa, which faults on an
// address that is not, and offset_in_page/PTR_ALIGN do the same)
static char *object_window(void *pseudo) {
  static char *cur, *end;
  uptr page = GetPageSizeCached();
  uptr half = RoundUpTo(ucsan_object_size_limit(), page);
  uptr window = 2 * half + page;
  if (!cur || cur + window > end) {
    uptr chunk = Max((uptr)1 << 30, window);
    cur = (char *)MmapNoReserveOrDie(chunk, "UCSan object windows");
    end = cur + chunk;
  }
  char *mid = cur + half + ((uptr)pseudo & (page - 1));
  cur += window;
  return mid;
}

void* customized_malloc(uint64_t size) {
  if (size > ucsan_object_size_limit()) {
    UCSAN_OUT("Object size too large: %lu\n", size);
    exit(exit_reason::REASON_OBJ_OOB);
  }
  uint64_t gap = Max((uint64_t)UCSAN_SAFE_GAP, UCSAN_ROUNDUPGAP(size));
  uint64_t crafted_size = size + (gap << 1);
  char* ret = (char*)malloc(crafted_size) + gap;
  return (void*)ret;
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

// Check for out-of-bounds access to global variable (label: its bounds, from
// ucsan_trace_global)
static void check_global_bounds(void *p, ucsan_label label, uint64_t size,
                                bool dereferencing, void *return_addr) {
  ucsan_label_info *label_info = get_label_info(label);
  ucsan_obj_info *obj = to_obj_info(label_info);
  void *base = obj->real_ptr;
  uint64_t base_addr = (uint64_t)base;
  uint64_t ptr_addr = (uint64_t)p;
  uint64_t upper_bound = (uint64_t)obj->upper_bound;
  uint64_t offset = ptr_addr - base_addr;
  if (ucsan_flags().trace_bounds &&
      (ptr_addr < base_addr ||
       offset > upper_bound ||
       size > upper_bound - offset)) {
    UCSAN_OUT("ERROR: Out-of-bounds access to global variable @%p, label=%u, access size=%lu, object size=%u\n",
              p, label, size, obj->upper_bound);
    if (dereferencing) {
      __taint_trace_event_addr(label, EVENT_OOB, 0, return_addr, (uint32_t)obj->upper_bound);
      exit(exit_reason::EVENT_OOB);
    }
  }
}

// The destination of a memory intrinsic inside a global is not given to
// ucsan_check_pointer: it needs no symbolizing, it is written.  Its length
// is still bounded by the global.  __early_make_pgtable memsets
// early_dynamic_pgts[i] for ptrs_per_p4d * 8 bytes, a symbolized global's
// value, and wrote gigabytes of shadow past the 256 KB array.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_check_global_bounds(void *p, ucsan_label label, uint64_t size) {
  if (label < UCSAN_CONST_OFFSET || label == kUninitializedLabel ||
      get_label_info(label)->common.op != OP_ALLOCA)
    return;
  check_global_bounds(p, label, size, true, __builtin_return_address(0));
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void* ucsan_check_pointer(void* p, ucsan_label label, size_t size, bool dereferencing, uint32_t type_id) {
  UCSAN_OUT("%p: label: %d, size: %zu, dereferencing: %d, type_id: %u\n", p, label, size, dereferencing, type_id);
  __ucsan_null_deref_flag = nullptr;

  // Global variable handling
  // Only for a pointer the program got from a global itself: no label, or
  // the bounds label ucsan_trace_global gives a fixed-size global (OP_ALLOCA).
  // Any other label is a UC pointer -- a value from seed bytes -- and goes
  // through the mapping below whatever its value, as it did before the
  // section test was moved ahead of the label test for the bounds check:
  // a value the solver picked can land in the image, mid-global and odd
  // (unregister_nmi_handler's list head `next`, 33 bytes before nmi_desc),
  // and was taken as a real global address.
  if (in_data_section(p) &&
      (label < UCSAN_CONST_OFFSET ||
       (label != kUninitializedLabel &&
        get_label_info(label)->common.op == OP_ALLOCA))) {
    // if label is not zero, perform bounds check
    if (label >= UCSAN_CONST_OFFSET) {
      check_global_bounds(p, label, size, dereferencing,
                          __builtin_return_address(0));
    } else if (size > ucsan_object_size_limit()) {
      UCSAN_OUT("WARNING: global variable size too large: %lu\n", size);
      size = ucsan_object_size_limit();
    }
    // Symbolize global variable on first access (label == 0)
    ucsan_label *shadow = ucsan_shadow_for(p);
    if (*shadow == 0 && dereferencing) {
      // only symbolize on deref
      bool sent_data = false;
      uint64_t first_byte_offset = 0;
      for (uint64_t i = 0; i < size; ++i) {
        void *byte_addr = (void*)((uint64_t)p + i);
        shadow = ucsan_shadow_for(byte_addr);
        auto ret = create_label_from_super_object(1, false);
        *shadow = ret.label;
        if (i == 0) first_byte_offset = ret.offset;
        UCSAN_OUT("Symbolize global variable byte @%p with %u from offset %lu\n",
                  ((char*)p+i), ret.label, ret.offset);

        // Bridge to SymSan: create symbolic label for this byte and set shadow
        dfsan_label symsan_label = __taint_create_label(0, ret.offset, 1);
        __taint_set_label(symsan_label, byte_addr, 1);

        // Initialize from seed data if available
        if (ucsan_tainted.objects->size() && ret.offset < ucsan_tainted.objects->at(0).data.size()) {
          *((char*)p + i) = ucsan_tainted.objects->at(0).data.at(ret.offset);
        } else if (*((char*)p + i) != 0) {
          // Not gated on in_bss_section(): a BSS global is only zero until
          // something writes it without updating the shadow (inline asm, an
          // uninstrumented library), and then the solver's input cache would
          // assume 0 against a non-zero concrete value.
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
        __taint_trace_global_var(0, first_byte_offset, size, p);
        // and keep this run's copy of the seed in step, as the manager puts
        // the bytes into its seed and the parser's input (GV_TYPE): what
        // __ucsan_seed_byte reads for verify_inputs.  (Object 0 need not
        // exist yet: an entry function without arguments, on an empty seed,
        // makes none -- ucsan_set_label_for_args creates it the same way.)
        if (!ucsan_tainted.objects->size()) ucsan_tainted.objects->resize(1);
        auto &data = ucsan_tainted.objects->at(0).data;
        if (data.size() < first_byte_offset + size)
          data.resize(first_byte_offset + size);
        for (uint64_t i = 0; i < size; ++i)
          data[first_byte_offset + i] = ((uint8_t *)p)[i];
      }
    }
    return p;
  }

  // if non-global yet without label, can't do much
  if (label < UCSAN_CONST_OFFSET) {
    // ... except refuse an access larger than any object UCSan would create,
    // as the lazy-init path below does.  Without an object there is nothing
    // to bound it by, and a solver-chosen length would otherwise have the
    // caller (a memset's ucsan_set_label) touch that many bytes of shadow.
    if (dereferencing && size > ucsan_object_size_limit()) {
      UCSAN_OUT("Access size too large for an untracked pointer %p: %zu\n", p, size);
      exit(exit_reason::REASON_OBJ_OOB);
    }
    // Null dereference checking
    if (dereferencing && ucsan_flags().checker_nullderef) {
      if ((uint64_t)p < size || (uint64_t)p < ucsan_object_size_limit()) {
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

  // Alloca labels are emitted even when bounds tracing is disabled.  They
  // describe the concrete stack object; they are not under-constrained
  // pointer labels and must never fall through to the external-pointer path.
  // The bounds-enabled path below still performs stack-UAF and OOB checks.
  if (!ucsan_flags().trace_bounds && label_info->common.op == OP_ALLOCA)
    return p;

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

      uint64_t ptr_addr = (uint64_t)p;
      uint64_t offset = ptr_addr - lower;
      uint64_t object_size = upper - lower;
      if (ptr_addr < lower || offset >= object_size ||
          size > object_size - offset) {
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

    // The same limit as for an allocated pointer below, and it must come
    // first: sizes are 32-bit past this point (lookup_object, data.resize),
    // so 1 << 37 truncates to an empty object that customized_malloc accepts,
    // and the caller's memset then writes 128 GB of memory and shadow from it
    // (kvmclock_init_mem, 59 GB RSS before the OOM killer).
    if (size > ucsan_object_size_limit()) {
      UCSAN_OUT("Object access size too large: %zu\n", size);
      exit(exit_reason::REASON_OBJ_OOB);
    }

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

    // Seed data can make an object larger than the size limit
    if (object_size > ucsan_object_size_limit()) {
      UCSAN_OUT("Object size too large: %zu\n", object_size);
      exit(exit_reason::REASON_OBJ_OOB);
    }

    // Create object label
    ucsan_label obj_label = allocate_label();

    // offset 0 at the window's middle (see object_window); np is the lowest
    // byte, obj.offset below it
    void* np = object_window(p) - obj.offset;
    internal_memcpy(np, obj.data.data(), object_size);

    ucsan_obj_info *obj_label_info = to_obj_info(get_label_info(obj_label));
    obj_label_info->lower_bound = obj.offset;
    obj_label_info->upper_bound = (uint32_t)object_size - obj.offset;
    obj_label_info->real_ptr = (char*)np + obj.offset;
    obj_label_info->op = OP_RESERVED_OBJ;
    obj_label_info->type_id = (uint16_t)type_id;
    obj_label_info->object_id = object_id;

    ptr_info->obj_label = obj_label;
    ptr_info->pseudo_base = p;  // Store original pseudo pointer in ptr_info

    // Create labels for each byte in the object and set up shadow memory
    // (for a large object, the object's own label: its bytes get theirs when
    // first read, see ucsan_labels_on_demand; the SymSan labels are eager)
    bool on_demand = ucsan_labels_on_demand(object_size);
    for (uint64_t offset = 0; offset < object_size; ++offset) {
      void *nptr = (void*)((uint64_t)np + offset);
      ucsan_label *shadow = ucsan_shadow_for(nptr);
      int64_t rel = (int64_t)offset - (int64_t)obj.offset;
      if (on_demand) {
        *shadow = obj_label;
      } else {
        ucsan_label byte_label = allocate_label();

        ucsan_label_info *byte_info = get_label_info(byte_label);
        ucsan_byte_info *byte = to_byte_info(byte_info);
        byte->op = OP_NONE;
        byte->object_id = object_id;
        byte->offset = rel;

        *shadow = byte_label;
      }

      // Bridge to SymSan: use 0-based offset so offsets stay consistent
      // across seed re-executions regardless of obj.offset growth
      // (now: relative to offset 0 like the UCSan label above, negative below
      // it.  A 0-based offset is one into the seed as executed, and shifts by
      // the amount the object has grown backwards: enlargement numbers the
      // bytes it adds relative to offset 0, so a run that grows the object
      // mixed the two, and the manager, converting back with the length the
      // growth had just changed, put solutions on the wrong bytes.  Relative
      // offsets never move; the parser and the manager take the origin from
      // the seed.)
      dfsan_label symsan_label = __taint_create_label(object_id, rel, 1);
      __taint_set_label(symsan_label, nptr, 1);
    }

    ptr_info->status = PTR_INITIALIZED;
    return (char*)np + obj.offset;

  } else if (ptr_info->status == PTR_INITIALIZED) {
    UCSAN_OUT("check pointer: pointer allocated\n");

    ucsan_label obj_label = ptr_info->obj_label;
    ucsan_obj_info *obj_label_info = to_obj_info(get_label_info(obj_label));
    uint32_t object_id = obj_label_info->object_id;

    // the object freed through another of its pointer labels: this label's
    // own op is still OP_EXTERNAL (see ucsan_obj_freed)
    if (ucsan_flags().trace_bounds && dereferencing &&
        ucsan_obj_freed(obj_label)) {
      UCSAN_OUT("ERROR: Heap UAF detected ptr %p, label = %u (object label %u freed)\n",
                p, label, obj_label);
      __taint_trace_event_addr(label, EVENT_UAF, 0, __builtin_return_address(0), 0);
      exit(exit_reason::EVENT_UAF);
    }

    void *obj_base = obj_label_info->real_ptr;
    int64_t pseudo_base = (int64_t)ptr_info->pseudo_base;  // Read from ptr_info
    int64_t desired_offset = (int64_t)p - pseudo_base;

    if (size > ucsan_object_size_limit()) {
      UCSAN_OUT("Object access size too large: %zu\n", size);
      exit(exit_reason::REASON_OBJ_OOB);
    }

    int64_t access_size = (int64_t)size;
    if (desired_offset > INT64_MAX - access_size) {
      UCSAN_OUT("Object access offset overflow: offset=%ld, size=%zu\n",
                desired_offset, size);
      exit(exit_reason::REASON_OBJ_OOB);
    }
    int64_t desired_end = desired_offset + access_size;

    if (ucsan_flags().no_upcast && desired_offset < 0) {
      UCSAN_OUT("Upcast disallowed by no_upcast flag\n");
      exit(exit_reason::EVENT_OOB_UPCAST);
    }

    // Fast path: within current bounds
    int64_t lower_bound = -(int64_t)obj_label_info->lower_bound;
    int64_t upper_bound = (int64_t)obj_label_info->upper_bound;

    if (lower_bound <= desired_offset && desired_end <= upper_bound) {
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
    // (now: nothing is copied.  The object keeps its window and its offset 0,
    // and only the bytes between the old and the new bounds are added, in
    // place: see object_window.)

    // Slow path: need to enlarge object
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

    uint64_t new_size = new_lower_bound + Max(desired_end,
                                         (int64_t)obj_label_info->upper_bound);

    if (new_size > ucsan_object_size_limit()) {
      UCSAN_OUT("Object size too large: %lu\n", new_size);
      exit(exit_reason::REASON_OBJ_OOB);
    }

    // Grow in place (see object_window): offset 0 stays where it is, the new
    // bytes on either side get labels and zeroes -- the value the manager
    // gives them in the seed (EVENT_EXTENSION) -- and nothing moves.  Byte
    // labels are numbered relative to offset 0, as before.
    char *base = (char *)obj_base;
    int64_t old_lower = -(int64_t)obj_label_info->lower_bound;
    int64_t old_upper = (int64_t)obj_label_info->upper_bound;
    int64_t new_upper = (int64_t)new_size - (int64_t)new_lower_bound;
    UCSAN_OUT("Enlarged object in place: [%ld, %ld) -> [%ld, %ld)\n",
              old_lower, old_upper, -(int64_t)new_lower_bound, new_upper);

    // (on demand once the object is large, see ucsan_labels_on_demand)
    bool on_demand = ucsan_labels_on_demand(new_size);
    auto label_new_byte = [&](int64_t rel) {
      void *nptr = base + rel;
      *(char *)nptr = 0;
      if (on_demand) {
        *ucsan_shadow_for(nptr) = obj_label;
      } else {
        ucsan_label byte_label = allocate_label();
        ucsan_label_info *byte_info = get_label_info(byte_label);
        ucsan_byte_info *byte = to_byte_info(byte_info);
        byte->op = OP_NONE;
        byte->object_id = object_id;
        byte->offset = rel;
        *ucsan_shadow_for(nptr) = byte_label;
      }

      // Bridge to SymSan: offset relative to offset 0 (negative below it)
      dfsan_label symsan_label = __taint_create_label(object_id, rel, 1);
      __taint_set_label(symsan_label, nptr, 1);
    };
    // Padding the left lower bounds with new labels
    for (int64_t rel = -(int64_t)new_lower_bound; rel < old_lower; ++rel)
      label_new_byte(rel);
    // Padding the right upper bounds with new labels
    for (int64_t rel = old_upper; rel < new_upper; ++rel)
      label_new_byte(rel);

    // Update object info (real_ptr, offset 0, does not change)
    obj_label_info->lower_bound = (uint32_t)new_lower_bound;
    obj_label_info->upper_bound = (uint32_t)new_upper;

    return (void*)((int64_t)base + desired_offset);
  }

  UCSAN_OUT("Unknown pointer state: %d\n", ptr_info->status);
  return nullptr;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void* ucsan_uncheck_pointer(void* real_ptr, ucsan_label label) {
  // Inverse of ucsan_check_pointer for an already-initialized UC pointer.
  // ucsan_check_pointer maps pseudo -> real as:
  //   real = obj_base + (pseudo - pseudo_base)
  // so the inverse maps real -> pseudo as:
  //   pseudo = pseudo_base + (real - obj_base)
  // This is pure pointer arithmetic (like phys_to_virt): no object is
  // allocated, provisioned, or grown here.
  if (real_ptr == nullptr || label < UCSAN_CONST_OFFSET)
    return real_ptr;

  ucsan_label_info *info = get_label_info(label);
  // Only translate genuine UC (external/pseudo) pointers. File-mode pointers
  // (no ptr_info) pass through unchanged.
  if (info->common.op != OP_EXTERNAL)
    return real_ptr;

  ucsan_ptr_info *ptr_info = to_ptr_info(info);
  // We only uncheck a pointer that was previously resolved by
  // ucsan_check_pointer, so it must already have a backing object.
  if (ptr_info->status != PTR_INITIALIZED) {
    Report("BUG: ucsan_uncheck_pointer on uninitialized UC pointer "
           "(label=%u, status=%d)\n", label, ptr_info->status);
    return real_ptr;
  }

  ucsan_obj_info *obj_label_info = to_obj_info(get_label_info(ptr_info->obj_label));
  int64_t offset = (int64_t)real_ptr - (int64_t)obj_label_info->real_ptr;
  void *pseudo = (void*)((int64_t)ptr_info->pseudo_base + offset);
  UCSAN_OUT("uncheck_pointer: real=%p label=%u -> pseudo=%p (obj_base=%p, pseudo_base=%p, off=%ld)\n",
            real_ptr, label, pseudo, obj_label_info->real_ptr, ptr_info->pseudo_base, offset);
  return pseudo;
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

// Check if a copy operation can overflow the destination buffer.
// Phase 1: if src object already exceeds dst bound, exit with OOB.
// Phase 2: if src type is variable-size (type_id==0), ask thoroupy to
//          enlarge the src object past dst bound for the next run.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_check_copy_bounds(void *dst, ucsan_label dst_label,
                             void *src, ucsan_label src_label,
                             uint64_t gv_dst_bound) {
  UCSAN_OUT("ucsan_check_copy_bounds: dst=%p (label=%u), src=%p (label=%u), gv_dst_bound=%lu\n",
            dst, dst_label, src, src_label, gv_dst_bound);

  // Get dst bound: from alloca label or from compile-time GV size
  uint64_t dst_bound = 0;
  if (dst_label >= UCSAN_CONST_OFFSET) {
    ucsan_label_info *dst_info = get_label_info(dst_label);
    if (dst_info->common.op == OP_ALLOCA) {
      ucsan_obj_info *dst_obj = to_obj_info(dst_info);
      dst_bound = dst_obj->upper_bound;
    }
  } else dst_bound = gv_dst_bound;
  if (dst_bound == 0) return;

  // src must be under-constrained (OP_EXTERNAL)
  if (src_label < UCSAN_CONST_OFFSET) return;
  ucsan_label_info *src_info = get_label_info(src_label);
  if (src_info->common.op != OP_EXTERNAL) return;

  ucsan_ptr_info *src_ptr = to_ptr_info(src_info);
  if (src_ptr->status != PTR_INITIALIZED) return;

  // Get src object info
  ucsan_label src_obj_label = src_ptr->obj_label;
  if (src_obj_label < UCSAN_CONST_OFFSET) return;
  ucsan_label_info *src_obj_info = get_label_info(src_obj_label);
  if (src_obj_info->common.op != OP_RESERVED_OBJ) return;

  ucsan_obj_info *src_obj = to_obj_info(src_obj_info);
  uint32_t src_object_id = src_obj->object_id;
  uint64_t src_size = src_obj->lower_bound + src_obj->upper_bound;

  UCSAN_OUT("  dst_bound=%lu, src_object_id=%u, src_size=%lu, src_type_id=%u\n",
            dst_bound, src_object_id, src_size, src_obj->type_id);

  // Phase 1: src already exceeds dst bound → OOB witness
  if (src_size > dst_bound) {
    UCSAN_OUT("  COPY OVERFLOW: src_size=%lu > dst_bound=%lu\n", src_size, dst_bound);
    __taint_trace_event_addr(src_label, EVENT_OOB, 0,
                             __builtin_return_address(0), 0);
    exit(exit_reason::EVENT_OOB);
  }

  // Phase 2: request enlargement for variable-size or char-typed objects
  if (src_obj->type_id == 0 || src_obj->type_id == 2) {
    __taint_trace_event_addr(src_label, EVENT_COPY_OVERFLOW, src_object_id,
                             __builtin_return_address(0), (uint32_t)dst_bound);
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
  // A pointer with a non-pointer operand stays that pointer, as a GEP keeps
  // its base whatever the index: the kernel rebuilds pointers in integers --
  // a tag masked off (keyring_ptr_to_key, `p & ~3`), page_address()'s offset
  // arithmetic, per_cpu_ptr()'s `p + __per_cpu_offset[cpu]` with a
  // symbolized offset -- and returning 0 here dropped the label, so a NULL
  // from the seed reached its dereference unlabeled and faulted instead of
  // being materialized.  (visitCmpInst does the same for a comparison with
  // null.)  Two pointers still combine to nothing.
  if (l1_is_ptr && !l2_is_ptr) {
    if (l2 != 0)
      UCSAN_OUT("pointer label %u used in binary operation with non-pointer %u\n", l1, l2);
    return l1;
  }
  if (l2_is_ptr && !l1_is_ptr) {
    if (l1 != 0)
      UCSAN_OUT("pointer label %u used in binary operation with non-pointer %u\n", l2, l1);
    return l2;
  }

  // Return 0 - we don't track symbolic expressions in standalone mode
  return 0;
}

namespace __ucsan {

ucsan_label ucsan_materialize_byte(ucsan_label *ls, void *addr) {
  ucsan_label l = *ls;
  if (l < UCSAN_CONST_OFFSET || l == kUninitializedLabel)
    return l;
  ucsan_label_info *info = get_label_info(l);
  if (info->common.op != OP_RESERVED_OBJ)
    return l;
  // the object's label: this byte has none yet
  ucsan_obj_info *obj = to_obj_info(info);
  ucsan_label byte_label = allocate_label();
  ucsan_byte_info *byte = to_byte_info(get_label_info(byte_label));
  byte->op = OP_NONE;
  byte->object_id = obj->object_id;
  byte->offset = (int64_t)addr - (int64_t)obj->real_ptr;
  UCSAN_OUT("materialize: object %u offset %ld -> label %u\n",
            obj->object_id, (long)byte->offset, byte_label);
  *ls = byte_label;
  return byte_label;
}

}  // namespace __ucsan

// Give every byte of [addr, addr + n) that has no UCSan label yet its label,
// before its shadow is copied somewhere else: a copied marker would name the
// source object at the destination's address.  Called by the shadow copies
// (memcpy/memmove intrinsics, the __dfsw_ copy wrappers).
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_materialize_range(void *addr, uint64_t n) {
  if (!addr)
    return;
  ucsan_label *ls = ucsan_shadow_for(addr);
  for (uint64_t i = 0; i < n; ++i)
    ucsan_materialize_byte(&ls[i], (char *)addr + i);
}

// The byte of the seed as sent, at `offset` from input's origin: what the
// parser assumes an input label's byte is (cached_input_byte, with the
// origins the manager gives it -- the header's per-object origin, len(lvalue),
// not obj.offset, which the metadata's target_offset may override).  For
// __taint_verify_input_bytes.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
bool __ucsan_seed_byte(uint32_t input, int64_t offset, uint8_t *out) {
  const char *buf = ucsan_tainted.buf;
  if (buf == nullptr || ucsan_tainted.buf_size < sizeof(uint64_t) ||
      !ucsan_tainted.objects)
    return false;
  uint64_t cnt = *(const uint64_t *)buf;
  if (input >= cnt || input >= ucsan_tainted.objects->size())
    return false;
  // the seed's bytes as loaded, plus what this run has told the manager
  // since (a global's initial value, see the global symbolization); the
  // origin is the header's
  const uint32_t *origins = (const uint32_t *)(buf + sizeof(uint64_t));
  auto &data = ucsan_tainted.objects->at(input).data;
  int64_t idx = (int64_t)origins[input] + (int32_t)offset;
  if (idx < 0 || (uint64_t)idx >= data.size())
    return false;
  *out = data[idx];
  return true;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
ucsan_label ucsan_load_pointer_shadow(ucsan_label *ls, uint64_t n, bool is_pointer,
                                      void *concrete_addr) {
  if (ls == nullptr) return 0;

  // Only the first byte's label is ever used, and only for a pointer or a
  // pointer-sized value (below): that is the one byte to label on demand.
  if (is_pointer || n == sizeof(void*))
    ucsan_materialize_byte(ls, concrete_addr);
  ucsan_label label0 = ls[0];

  if (ucsan_flags().verify_inputs)
    __taint_verify_input_bytes(concrete_addr, n, __builtin_return_address(0));

  UCSAN_OUT("load_pointer_shadow: *label(%p)=%d is_pointer=%d, size=%lu\n",
            ls, label0, is_pointer, n);

  // Allow loading kUninitializedLabel for UBI detection
  if (label0 == kUninitializedLabel) {
    return label0;
  }

  ucsan_label_info *label_info = get_label_info(label0);

  if (is_pointer) {
    if (label0 >= UCSAN_CONST_OFFSET && label_info->common.op == OP_NONE) {
      // Check if the concrete pointer value points to a symbolize_input object
      if (__symbolize_addr_map_inited && concrete_addr && n == sizeof(void*)) {
        void *concrete_val = *(void **)concrete_addr;
        if (concrete_val) {
          uint32_t target_id, target_offset;
          ucsan_label target_ptr_label;
          if (__symbolize_addr_map.find(concrete_val, &target_id, &target_offset,
                                         &target_ptr_label)) {
            UCSAN_OUT("load_pointer_shadow: symbolize_input hit: target_id=%u, "
                      "target_offset=%u, ptr_label=%u\n",
                      target_id, target_offset, target_ptr_label);

            // Populate obj_map for lookup_object to find later
            ucsan_byte_info *byte = to_byte_info(label_info);
            uint32_t parent_id = byte->object_id;
            int32_t parent_offset = (int32_t)byte->offset;
            ucsan_tainted.obj_map->insert(parent_id, parent_offset, target_id);

            // Set target's origin
            if (target_id < ucsan_tainted.objects->size()) {
              ucsan_tainted.objects->at(target_id).origin = {
                parent_id, parent_offset, target_offset
              };
            }

            // Return the saved ptr_label instead of converting to OP_EXTERNAL
            if (target_ptr_label) {
              return target_ptr_label;
            }
          }
        }
      }

      // Default: convert byte label to pointer label
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
    for (uint64_t i = 0; i < n; ++i) ls[i] = l;
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

  if (!ucsan_tainted.objects->size()) ucsan_tainted.objects->resize(1);
  auto &data = ucsan_tainted.objects->at(0).data;
  // A seed can cover only part of the argument: the solver writes the bytes a
  // constraint mentions and nothing past them, so `x & 0x101` on an int leaves
  // a seed that ends two bytes into it.  Take what is there and read the rest
  // as 0, which is what the parser assumes for bytes past the end.  Requiring
  // the whole argument used to drop the seed's bytes along with the missing
  // ones, so the target ran on `given` while the parser evaluated the seed,
  // and every branch on the argument was rejected as a value mismatch.
  bool in_seed = last_offset < data.size();
  if (data.size() < last_offset + size_in_bytes)
    data.resize(last_offset + size_in_bytes);
  if (in_seed) {
    uint64_t result = 0;
    internal_memcpy(&result, data.data() + last_offset,
                    size_in_bytes < sizeof(result) ? size_in_bytes : sizeof(result));
    UCSAN_OUT("Returning: 0x%lx\n", result);
    return (void*)result;
  }

  return (void*)given;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __ucsan_symbolize_input(void *ptr, size_t size, int id) {
  UCSAN_OUT("symbolize_input: ptr=%p, size=%zu, id=%d\n", ptr, size, id);

  if (!ptr || size == 0) return;

  uint32_t object_id = (uint32_t)id;  // direct 1-based mapping

  // Read the pointer's label from arg_tls (stored by UCSanPass at call site)
  ucsan_label ptr_label = __ucsan_arg_tls[0];
  UCSAN_OUT("symbolize_input: ptr_label=%u\n", ptr_label);

  // Ensure objects storage is allocated and large enough
  if (!ucsan_tainted.objects) {
    ucsan_tainted.objects = new ObjectStorage();
  }
  while (ucsan_tainted.objects->size() <= object_id) {
    UCSanObject empty;
    empty.offset = 0;
    empty.data.init();
    empty.origin = {0, 0, 0};
    ucsan_tainted.objects->push_back(empty);
  }

  // Bump __ucsan_inited_objects to avoid collision with lazy alloc
  uint32_t current = atomic_load(&__ucsan_inited_objects, memory_order_relaxed);
  while (current <= object_id) {
    if (atomic_compare_exchange_weak(&__ucsan_inited_objects,
          &current, object_id + 1, memory_order_relaxed))
      break;
  }

  // Ensure obj_map is initialized
  if (!ucsan_tainted.obj_map) {
    ucsan_tainted.obj_map = new ObjectMap();
    ucsan_tainted.obj_map->init();
  }

  // Seed data handling
  UCSanObject &obj = ucsan_tainted.objects->at(object_id);
  bool first_run = (obj.data.size() == 0);
  if (!first_run && obj.data.size() >= (uint32_t)size) {
    // Re-run: solver provided data, overwrite ptr
    internal_memcpy(ptr, obj.data.data(), size);
    UCSAN_OUT("symbolize_input: re-run, overwrote ptr with solver data\n");
  } else {
    // First run: snapshot concrete bytes as initial seed
    obj.data.assign((const unsigned char *)ptr, (uint32_t)size);
    UCSAN_OUT("symbolize_input: first run, snapshotted %zu bytes\n", size);
  }

  // Initialize addr range map if needed
  if (!__symbolize_addr_map_inited) {
    __symbolize_addr_map.init();
    __symbolize_addr_map_inited = true;
  }

  // Register in addr range map for lazy pointer relationship discovery
  __symbolize_addr_map.insert(ptr, size, object_id, ptr_label);

  // Label every byte OP_NONE — same pattern as ucsan_check_pointer:861-879
  ucsan_label *shadow = ucsan_shadow_for(ptr);
  for (size_t offset = 0; offset < size; ++offset) {
    ucsan_label byte_label = allocate_label();

    ucsan_label_info *byte_info = get_label_info(byte_label);
    ucsan_byte_info *byte = to_byte_info(byte_info);
    byte->op = OP_NONE;
    byte->object_id = object_id;
    byte->offset = offset;

    shadow[offset] = byte_label;

    // Bridge to SymSan
    void *byte_addr = (void *)((uintptr_t)ptr + offset);
    dfsan_label symsan_label = __taint_create_label(object_id, offset, 1);
    __taint_set_label(symsan_label, byte_addr, 1);
  }

  // Trace object usage event so thoroupy knows about this object
  if (ucsan_flags().trace_object) {
    ucsan_label first_label = *(ucsan_shadow_for(ptr));
    uint64_t cite_info = ((uint64_t)size << 32) | object_id;
    __taint_trace_event_addr(first_label, EVENT_USAGE_CITE, cite_info,
                             __builtin_return_address(0), 0);
  }

  // Send initial concrete data to solver (first run only)
  if (first_run) {
    __taint_trace_global_var(object_id, 0, size, ptr);
  }

  UCSAN_OUT("symbolize_input: done, labeled %zu bytes for object %u\n", size, object_id);
}

// Find a live stack alloca whose [base, base+size) contains ptr. Opaque
// pointers leave resign call sites with n=0; the pointer's UCSan label (or
// this address scan) is the sole size oracle — do not ask SymSan.
static ucsan_label find_alloca_containing(void *ptr) {
  if (!ptr || __alloca_stack_top > __alloca_stack_bottom)
    return 0;
  uptr addr = (uptr)ptr;
  for (ucsan_label label = __alloca_stack_top; label <= __alloca_stack_bottom;
       ++label) {
    ucsan_label_info *info = get_label_info(label);
    if (info->common.op != OP_ALLOCA)
      continue;
    ucsan_obj_info *obj = to_obj_info(info);
    uptr lower = (uptr)obj->real_ptr - obj->lower_bound;
    uptr upper = (uptr)obj->real_ptr + obj->upper_bound;
    if (addr >= lower && addr < upper)
      return label;
  }
  return 0;
}

// A label naming an allocation the out-of-scope callee can still write: a
// heap object the function allocated, or a stack object of a frame that is
// still live (a popped frame's labels lie between the heap labels and
// __alloca_stack_top, see the stack UAF check in ucsan_check_pointer).
static bool is_live_alloca_label(ucsan_label l) {
  if (l < UCSAN_CONST_OFFSET || l == kUninitializedLabel)
    return false;
  ucsan_label last_heap = atomic_load(&__ucsan_last_label, memory_order_relaxed);
  if (l > last_heap && l < __alloca_stack_top)
    return false;
  return get_label_info(l)->common.op == OP_ALLOCA;
}

static const int kResignMaxDepth = 4;
static const int kResignMaxObjects = 64;

static ucsan_label resign_alloca_object(ucsan_label label_for_ptr,
                                        ucsan_label *seen, int *nseen,
                                        int depth);

static ucsan_label resign_alloca_object(ucsan_label label_for_ptr) {
  ucsan_label seen[kResignMaxObjects];
  int nseen = 0;
  return resign_alloca_object(label_for_ptr, seen, &nseen, 0);
}

static ucsan_label resign_alloca_object(ucsan_label label_for_ptr,
                                        ucsan_label *seen, int *nseen,
                                        int depth) {
  UCSAN_OUT("Resign alloca object\n");
  for (int i = 0; i < *nseen; ++i)
    if (seen[i] == label_for_ptr)
      return label_for_ptr;
  if (*nseen < kResignMaxObjects)
    seen[(*nseen)++] = label_for_ptr;
  ucsan_label_info *orig = get_label_info(label_for_ptr);
  ucsan_obj_info *obj_info = to_obj_info(orig);

  // Calculate bounds: real_ptr is the base, lower_bound is bytes before, upper_bound is bytes after
  char *lower = (char*)obj_info->real_ptr - obj_info->lower_bound;
  char *upper = (char*)obj_info->real_ptr + obj_info->upper_bound;
  size_t alloca_size = upper - lower;
  if (alloca_size > ucsan_object_size_limit()) {
    UCSAN_OUT("WARNING: alloca resign size %zu exceeds limit %lu, capping\n",
              alloca_size, ucsan_object_size_limit());
    upper = lower + ucsan_object_size_limit();
  }
  ucsan_label *lp = ucsan_shadow_for(lower);
  ucsan_label *le = ucsan_shadow_for(upper);
  char *obj_ptr = lower;

  // A run of uninitialized bytes longer than eager_label_size gets one
  // on-demand marker, as a large lazily created object does (see
  // ucsan_labels_on_demand): unlzo hands two 40 KB buffers to out-of-scope
  // callees, and a label per byte exhausted the 16-bit labels.  The bytes
  // keep the super object offsets, one each, consecutive within the run, so
  // the marker's real_ptr is placed for addr - real_ptr to be that offset.
  ucsan_label run_marker = 0;
  ucsan_label *run_end = lp;
  for (; lp < le; ++lp, ++obj_ptr) {
    if (*lp != kUninitializedLabel)
      continue;
    if (lp >= run_end) {
      run_marker = 0;
      for (run_end = lp; run_end < le && *run_end == kUninitializedLabel;)
        ++run_end;
      uint64_t run_len = run_end - lp;
      if (ucsan_labels_on_demand(run_len)) {
        uint64_t base = atomic_load(&ucsan_tainted.arg_used, memory_order_relaxed);
        run_marker = allocate_label();
        ucsan_obj_info *marker = to_obj_info(get_label_info(run_marker));
        marker->op = OP_RESERVED_OBJ;
        marker->type_id = 0;
        marker->object_id = 0;  // super object
        marker->real_ptr = obj_ptr - base;
        marker->lower_bound = (uint32_t)base;
        marker->upper_bound = (uint32_t)run_len;
        UCSAN_OUT("resign alloca run: %p +%lu at super offset %lu, marker %u\n",
                  obj_ptr, run_len, base, run_marker);
      }
    }
    {
      object_info ret;
      if (run_marker) {
        // the byte's offset, its label given when first read
        ret.offset = atomic_fetch_add(&ucsan_tainted.arg_used, 1, memory_order_relaxed);
        ret.label = run_marker;
      } else {
        // Allocate a byte from super object
        ret = create_label_from_super_object(1, false);
      }
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

  // The callee also writes what it reaches through the object: a buffer whose
  // address the caller stored in it (i2c_msg.buf, msghdr.msg_name,
  // printk_record.info).  Resigning only the object passed left that buffer
  // uninitialized, and the caller's first read of it a UBI.  A stored pointer
  // carries its allocation's label in all of its shadow bytes
  // (ucsan_store_pointer_shadow).
  if (depth >= kResignMaxDepth)
    return label_for_ptr;
  char *slot = (char *)RoundUpTo((uptr)lower, sizeof(void *));
  for (; slot + sizeof(void *) <= upper; slot += sizeof(void *)) {
    ucsan_label *ls = ucsan_shadow_for(slot);
    ucsan_label l = ls[0];
    if (l == label_for_ptr || !is_live_alloca_label(l))
      continue;
    bool whole = true;
    for (uptr i = 1; i < sizeof(void *); ++i)
      whole &= ls[i] == l;
    if (!whole)
      continue;
    UCSAN_OUT("Resign alloca %u reached through %p in alloca %u\n",
              l, slot, label_for_ptr);
    resign_alloca_object(l, seen, nseen, depth + 1);
  }
  return label_for_ptr;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
ucsan_label ucsan_resign_shadow(void *ptr, ucsan_label *orig_label, uint64_t n, void *ret_addr) {
  ucsan_label label_for_ptr = *orig_label;

  if (ptr == nullptr && label_for_ptr == 0) {
    UCSAN_OUT("Resigning null pointer, skip\n");
    return UCSAN_CONST_LABEL;
  }

  // Opaque pointers can leave n=0 even when the pointer lands in a tracked
  // stack object whose label did not travel with the arg (e.g. some GEPs).
  if (label_for_ptr == 0 && ptr != nullptr) {
    label_for_ptr = find_alloca_containing(ptr);
    if (label_for_ptr != 0)
      UCSAN_OUT("Resign recovered alloca label %u for %p\n", label_for_ptr, ptr);
  }

  bool in_alloca = false;  // the overlay below is inside a live alloca
  if (label_for_ptr != 0) {
    ucsan_label_info *orig = get_label_info(label_for_ptr);

    if (orig->common.op == OP_ALLOCA) {
      // With trace_bounds, memory was painted uninit: only fill holes (UBI).
      // Without it, the alloca label is just a size oracle for opaque pointers;
      // fall through to concrete overlay using the tracked object size — same
      // as the old sizeof(*T) resign path that external.c relies on.
      if (ucsan_flags().trace_bounds)
        return resign_alloca_object(label_for_ptr);

      ucsan_obj_info *obj_info = to_obj_info(orig);
      char *lower = (char *)obj_info->real_ptr - obj_info->lower_bound;
      char *upper = (char *)obj_info->real_ptr + obj_info->upper_bound;
      // (the overlay writes from ptr, so only a ptr inside the alloca; one
      // outside it used to overlay the alloca's whole size starting there)
      if ((char *)ptr < lower || (char *)ptr >= upper) {
        UCSAN_OUT("Resign alloca: p=%p is outside it, skip\n", ptr);
        return label_for_ptr;
      }
      n = (uint64_t)(upper - (char *)ptr);
      in_alloca = true;
      UCSAN_OUT("Resign alloca as concrete: p=%p, size=%lu\n", ptr, n);
      // Continue into concrete overlay below.
    } else if (orig->common.op == OP_FREE) {
      // Freed memory - return as-is for UAF detection
      UCSAN_OUT("Resign freed object\n");
      return label_for_ptr;
    } else {
      // Mark as external pointer
      // (only a pointer not dereferenced yet -- a byte label, or an external
      // pointer still uninitialized -- as ucsan_check_pointer would on first
      // use.  An initialized one keeps its object: lazy init has reused the
      // fields lookup_object finds the object by, (parent, offset), for
      // (obj_label, pseudo_base), so marking it uninitialized re-created the
      // object from a label number and a pseudo pointer: an object the seed
      // does not have, and the branches on it value mismatches.  An object
      // label (an unmaterialized byte's marker) is not a pointer at all.)
      ucsan_ptr_info *ptr_info = to_ptr_info(orig);
      if (orig->common.op == OP_NONE ||
          (orig->common.op == OP_EXTERNAL &&
           ptr_info->status == PTR_UNINITIALIZED)) {
        ptr_info->op = OP_EXTERNAL;
        ptr_info->status = PTR_UNINITIALIZED;
      }
      return label_for_ptr;
    }
  }

  {
    // No UCSan object and no compile-time size: nothing to overlay. Avoid
    // minting a zero-byte "concrete external" object (opaque-ptr dangle stubs).
    if (n == 0) {
      UCSAN_OUT("Concrete external object: p=%p, size unknown, skip\n", ptr);
      return UCSAN_CONST_LABEL;
    }

    // What the overlay may write is known, not probed: the alloca above, or
    // else -- a pointer with no UCSan label that is in no live alloca -- a
    // global, the image's writable data (in_data_section, as
    // ucsan_check_pointer's global model).  Anything else is read-only data
    // or code, or a value that is no object of ours (a pointer built from
    // integers), and a callee writes none of it.  The probe this replaces
    // read /dev/zero into ptr, zeroing the byte it tested -- even when n was
    // 0 and nothing was overlaid -- behind the labels of a global already
    // symbolized (init_hugetlbfs_fs's default_hstate_idx).
    if (!in_alloca &&
        !(in_data_section(ptr) && in_data_section((char *)ptr + n - 1))) {
      UCSAN_OUT("Concrete external object: p=%p is not writable data, skip\n", ptr);
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

  // byte by byte, and 0 past the end of the seed: a seed that covers only part
  // of the value must still deliver that part (see ucsan_set_label_for_args)
  uptr seed_size = ucsan_tainted.objects->size() ?
                   ucsan_tainted.objects->at(0).data.size() : 0;
  UCSAN_OUT("offset (%lu + %lu), seed has %lu\n", last_offset, size, seed_size);
  for (uptr i = 0; i < size; ++i) {
    __ucsan_wrapped_return_tls[i] = last_offset + i < seed_size ?
        ucsan_tainted.objects->at(0).data[last_offset + i] : 0;
  }
  // The caller loads the value as its own type, so a bool is one byte that
  // must be 0 or 1: LLVM's i1 load leaves the other bits undefined and the
  // branch tests the whole byte, while SymSan truncates the label to `bits`
  // (__taint_set_retval_tls).  A seed byte of 2 was a false bool the target
  // took as true, and the branch on it a value mismatch.
  if (bits % 8)
    __ucsan_wrapped_return_tls[size - 1] &= (1u << (bits % 8)) - 1;

  return (void*)__ucsan_wrapped_return_tls;
}

namespace __ucsan {
static u64 ucsan_freed_objs[(1u << (8 * sizeof(ucsan_label))) / 64];

bool ucsan_obj_freed(ucsan_label obj_label) {
  return (ucsan_freed_objs[obj_label / 64] >> (obj_label % 64)) & 1;
}

void ucsan_mark_obj_freed(ucsan_label obj_label) {
  ucsan_freed_objs[obj_label / 64] |= 1ULL << (obj_label % 64);
}
}  // namespace __ucsan

// A UC pointer: an external pointer, or a byte label (a pointer loaded from
// a UC object or a global and not dereferenced yet, which ucsan_check_pointer
// turns into one).  Not a real pointer (no label, an alloca, a global's
// address).
static bool is_uc_pointer_label(ucsan_label l) {
  if (l < UCSAN_CONST_OFFSET || l == kUninitializedLabel)
    return false;
  uint16_t op = get_label_info(l)->common.op;
  return op == OP_EXTERNAL || op == OP_NONE;
}

// The object of an initialized UC pointer label, or 0
static ucsan_label uc_pointer_object(ucsan_label l) {
  if (!is_uc_pointer_label(l))
    return 0;
  ucsan_ptr_info *pi = to_ptr_info(get_label_info(l));
  if (pi->op != OP_EXTERNAL || pi->status != PTR_INITIALIZED)
    return 0;
  return pi->obj_label;
}

// SymSan's opcodes for the index expression (dfsan.h's, from the same .def)
namespace {
enum symsan_binary_op : uint16_t {
#define HANDLE_BINARY_INST(num, opcode, Class) SYMSAN_##opcode = num,
#include "llvm/IR/Instruction.def"
#undef HANDLE_BINARY_INST
};
}  // namespace

// A pointer bound into another's object by a pointer difference (see
// __dfsw_ucsan_ptr_index).  The pointer label keeps its own number -- its
// copies in memory and registers are not touched -- and its ptr_info names
// the other's object, so an object can have more than one pointer label; what
// a label alone cannot say is that its offset in the object is symbolic:
// c + i * elem, with i the fresh index (its SymSan label and the value it had).
// Recorded here, so that a later difference of the two is i again, not a new
// fresh index.  Bindings are rare (one per unrelated difference that binds).
struct ucsan_ptr_binding {
  ucsan_label label;
  dfsan_label index;
  int64_t index_value;
  int64_t elem;
};
static ucsan_ptr_binding ucsan_ptr_bindings[64];
static unsigned ucsan_num_ptr_bindings;

static const ucsan_ptr_binding *find_ptr_binding(ucsan_label l) {
  for (unsigned i = 0; i < ucsan_num_ptr_bindings; ++i)
    if (ucsan_ptr_bindings[i].label == l)
      return &ucsan_ptr_bindings[i];
  return nullptr;
}

// `p - q` (UCSanVisitor::visitBinaryOperator): whether the index the program
// computes from p and q's pseudo-pointers is not the one it means, and
// __dfsw_ucsan_ptr_index has to give it.  Two UC pointers with no known
// relation: their pseudo-pointers' difference is any number.  Two pointer
// labels of the same UC object (one bound into the other's by an earlier
// difference): their pseudo-pointers have unrelated bases, the difference
// of their offsets in the object is the one.  Real pointers, and two through
// the same label, are related as the program has them.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
bool ucsan_ptr_diff_rewrite(void *p, ucsan_label lp, void *q, ucsan_label lq) {
  bool up = is_uc_pointer_label(lp), uq = is_uc_pointer_label(lq);
  if (!up && !uq)
    return false;
  if (lp == lq)
    return false;
  UCSAN_OUT("ptr_diff: %p (label %u) and %p (label %u) need the index\n",
            p, lp, q, lq);
  return true;
}

// The SymSan label of x's offset in its object, as rest + label * scale:
// 0 for a pointer that is not bound, whose offset is concrete.  Sets *rest
// to the concrete part, x's offset less the index's.
static dfsan_label pointer_offset_term(void *x, ucsan_label l, int64_t *rest,
                                       int64_t *scale) {
  ucsan_ptr_info *pi = to_ptr_info(get_label_info(l));
  *rest = (int64_t)x - (int64_t)pi->pseudo_base;
  *scale = 0;
  const ucsan_ptr_binding *b = find_ptr_binding(l);
  if (!b)
    return 0;
  *rest -= b->index_value * b->elem;
  *scale = b->elem;
  return b->index;
}

// The element index of two pointer labels of one object: the difference of
// their offsets in it, divided by elem, concrete and -- when either is bound
// -- symbolic, in the index it was bound by.  The binding's own subtraction
// again (counter_show reads `attr - counter_attrs` twice) is exactly the
// index's label.
static int64_t same_object_index(int64_t elem, void *p, void *q,
                                 ucsan_label lp, ucsan_label lq) {
  int64_t rp, rq, sp, sq;
  dfsan_label ip = pointer_offset_term(p, lp, &rp, &sp);
  dfsan_label iq = pointer_offset_term(q, lq, &rq, &sq);
  ucsan_ptr_info *pi = to_ptr_info(get_label_info(lp));
  ucsan_ptr_info *qi = to_ptr_info(get_label_info(lq));
  int64_t diff = ((int64_t)p - (int64_t)pi->pseudo_base) -
                 ((int64_t)q - (int64_t)qi->pseudo_base);
  int64_t index = diff / elem;
  dfsan_label label = 0;
  // label = (rp - rq) / elem + ip * sp / elem - iq * sq / elem, when every
  // part is a whole number of elements; otherwise the program's sdiv exact
  // is poison and the index is left concrete
  if ((ip || iq) && (rp - rq) % elem == 0 && sp % elem == 0 &&
      sq % elem == 0) {
    int64_t ival = 0, jval = 0;
    if (const ucsan_ptr_binding *b = find_ptr_binding(lp)) ival = b->index_value;
    if (const ucsan_ptr_binding *b = find_ptr_binding(lq)) jval = b->index_value;
    int64_t kp = sp / elem, kq = sq / elem;
    // ip * kp
    dfsan_label tp = ip && kp != 1
        ? __taint_union(ip, 0, SYMSAN_Mul, 64, ival, kp) : ip;
    int64_t vp = ival * kp;
    dfsan_label tq = iq && kq != 1
        ? __taint_union(iq, 0, SYMSAN_Mul, 64, jval, kq) : iq;
    int64_t vq = jval * kq;
    // tp - tq
    label = tq ? __taint_union(tp, tq, SYMSAN_Sub, 64, vp, vq) : tp;
    // + (rp - rq) / elem
    int64_t c = (rp - rq) / elem;
    if (label && c)
      label = __taint_union(label, 0, SYMSAN_Add, 64, vp - vq, c);
  }
  __taint_set_retval_tls(0, label, 64);
  UCSAN_OUT("ptr_diff: same object, index %ld (SymSan label %u)\n",
            index, label);
  return index;
}

// The element index `p - q` that ucsan_ptr_diff_rewrite says the program does
// not compute.  For two pointer labels of one object, the difference of their
// offsets (same_object_index).  For two unrelated UC pointers, what the
// program assumes they are, p == &q[i], with i a fresh symbolic value -- from
// the super object, as a wrapped return value is -- and its SymSan label in
// the retval TLS (TaintPass reads it there for a __dfsw_ call from UCSan).  p
// is then bound into q's object at element i, so that what is written through
// one is seen through the other, and freeing one frees the other's object;
// only while p has no object of its own, and only into a UC object (a real q
// -- lock_classes in match_held_lock -- is not one).
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
int64_t __dfsw_ucsan_ptr_index(bool rewrite, int64_t elem, void *p, void *q,
                               ucsan_label lp, ucsan_label lq) {
  if (!rewrite)
    return 0;
  ucsan_label op = uc_pointer_object(lp);
  if (op && op == uc_pointer_object(lq))
    return same_object_index(elem, p, q, lp, lq);

  auto ret = create_label_from_super_object(sizeof(int64_t), false);
  dfsan_label index_label = __taint_create_label(0, ret.offset, sizeof(int64_t));
  __taint_set_retval_tls(0, index_label, 64);
  // byte by byte, 0 past the end of the seed (as ucsan_wrap_retval)
  uint64_t index = 0;
  uptr seed_size = ucsan_tainted.objects->size() ?
                   ucsan_tainted.objects->at(0).data.size() : 0;
  for (uptr i = 0; i < sizeof(index); ++i)
    if (ret.offset + i < seed_size)
      index |= (uint64_t)ucsan_tainted.objects->at(0).data[ret.offset + i] << (8 * i);
  UCSAN_OUT("ptr_diff: index %ld from offset %lu (element size %ld)\n",
            (int64_t)index, ret.offset, elem);

  if (is_uc_pointer_label(lp) && is_uc_pointer_label(lq)) {
    ucsan_ptr_info *pi = to_ptr_info(get_label_info(lp));
    if (pi->op == OP_EXTERNAL && pi->status == PTR_INITIALIZED) {
      UCSAN_OUT("ptr_diff: %p already has its object, not bound\n", p);
    } else if (ucsan_num_ptr_bindings == ARRAY_SIZE(ucsan_ptr_bindings)) {
      UCSAN_OUT("ptr_diff: too many bindings, %p not bound\n", p);
    } else {
      // q's object, created now if it was not yet
      ucsan_check_pointer(q, lq, 1, false, 0);
      ucsan_ptr_info *qi = to_ptr_info(get_label_info(lq));
      if (qi->op == OP_EXTERNAL && qi->status == PTR_INITIALIZED) {
        // p - pseudo_base is p's offset in the object: q's, plus i elements
        int64_t qoff = (int64_t)q - (int64_t)qi->pseudo_base;
        pi->op = OP_EXTERNAL;
        pi->status = PTR_INITIALIZED;
        pi->obj_label = qi->obj_label;
        pi->pseudo_base = (void *)((int64_t)p - qoff - (int64_t)index * elem);
        ucsan_ptr_bindings[ucsan_num_ptr_bindings++] =
            {lp, index_label, (int64_t)index, elem};
        UCSAN_OUT("ptr_diff: %p bound to element %ld of %p's object\n",
                  p, (int64_t)index, q);
      }
    }
  }
  return (int64_t)index;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
ucsan_label ucsan_trace_alloca(uint64_t size, uint64_t elem_size, uint64_t addr) {
  // Track stack allocation bounds using stack-based label allocation
  // Labels are allocated from __alloca_stack_top (top of label space, growing downward)
  // and automatically freed when the function exits via ucsan_pop_stack_frame
  //
  // size: array size (number of elements)
  // elem_size: size of each element in bytes
  // addr: address of the stack allocation
  //
  // Always record bounds: opaque pointers no longer give resign a pointee
  // sizeof, so the OP_ALLOCA label is the size oracle for KO_RESIGN_PTRARGS.
  // Painting memory as uninitialized (UBI) stays gated on trace_bounds.

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
  obj->type_id = 0;
  obj->object_id = 0;  // Not tracked in objects array (stack allocation)
  obj->real_ptr = ptr;
  obj->lower_bound = 0;           // No bytes before base
  obj->upper_bound = (uint32_t)total_size;   // Total size in bytes

  UCSAN_OUT("  created stack label %u: ptr=%p, lower=0, upper=%u\n",
            label, ptr, obj->upper_bound);

  if (ucsan_flags().trace_bounds) {
    // Set shadow memory to kUninitializedLabel for UBI detection
    ucsan_label *shadow = ucsan_shadow_for(ptr);
    for (uptr i = 0; i < total_size; i++) {
      shadow[i] = kUninitializedLabel;
    }
  }

  return label;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
ucsan_label ucsan_trace_global(uint64_t addr, uint64_t size) {
  if (!ucsan_flags().trace_bounds || addr == 0 || size == 0)
    return 0;

  if (size > UINT32_MAX) {
    UCSAN_OUT("WARNING: global bounds size %lu exceeds limit %u, capping\n",
              size, UINT32_MAX);
    size = UINT32_MAX;
  }

  void *ptr = (void *)addr;
  if (!__global_bounds_map_inited) {
    __global_bounds_map.init();
    __global_bounds_map_inited = true;
  }

  uint32_t object_id = 0;
  uint32_t offset = 0;
  ucsan_label label = 0;
  if (__global_bounds_map.find(ptr, &object_id, &offset, &label)) {
    UCSAN_OUT("ucsan_trace_global: reuse label=%u, base=%p, size=%lu\n",
              label, ptr, size);
    return label;
  }

  label = allocate_label();
  UCSAN_OUT("ucsan_trace_global: label=%u, base=%p, size=%lu\n",
            label, ptr, size);

  ucsan_label_info *info = get_label_info(label);
  ucsan_obj_info *obj = to_obj_info(info);
  obj->op = OP_ALLOCA;
  obj->type_id = 0;
  obj->object_id = 0;
  obj->real_ptr = ptr;
  obj->lower_bound = 0;
  obj->upper_bound = (uint32_t)size;

  __global_bounds_map.insert(ptr, (size_t)size, 0, label);
  return label;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_push_stack_frame() {
  // Save current stack top when entering a function
  // This allows automatic cleanup of stack allocation labels on function exit.
  // Always on: ucsan_trace_alloca always allocates labels now.
  if (__current_saved_stack_index < UCSAN_MAX_SAVED_STACK_ENTRIES) {
    __saved_alloca_stack_top[++__current_saved_stack_index] = __alloca_stack_top;
    UCSAN_OUT("ucsan_push_stack_frame: saved index=%d, stack_top=%u\n",
              __current_saved_stack_index, __alloca_stack_top);
  } else {
    Report("WARNING: UCSan: stack frame save index overflow\n");
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_pop_stack_frame() {
  // Restore stack top when exiting a function
  // This automatically frees all stack allocation labels created in this function
  if (__current_saved_stack_index > 0) {
    __alloca_stack_top = __saved_alloca_stack_top[__current_saved_stack_index--];
    UCSAN_OUT("ucsan_pop_stack_frame: restored index=%d, stack_top=%u\n",
              __current_saved_stack_index, __alloca_stack_top);
  } else {
    Report("WARNING: UCSan: stack frame save index underflow\n");
  }
}

/// scan shadow for ptr labels and recursively mark
void ucsan_scan_mark_reachable(void *base, uint64_t size) {

  UCSAN_OUT("ucsan_scan_mark_reachable: base=%p, size=%lu\n", base, size);

  ucsan_label *shadow = ucsan_shadow_for(base);
  for (uptr i = 0; i < size; ++i) {
    // ptr labels can occupy multiple bytes, but once marked reachable,
    // the duplicated ones will be skipped
    ucsan_label label = shadow[i];
    if (label >= UCSAN_CONST_OFFSET) {
      ucsan_label_info *info = get_label_info(label);
      if (info->common.op == OP_EXTERNAL) {
        // external pointer, find the real object and continue scanning
        // Mark this object as reachable by setting op to OP_FREE
        info->common.op = OP_FREE;
        ucsan_ptr_info *ptr_info = to_ptr_info(info);
        if (ptr_info->status == PTR_INITIALIZED) {
          ucsan_label obj_label = ptr_info->obj_label;
          if (obj_label >= UCSAN_CONST_OFFSET) {
            ucsan_label_info *obj_info = get_label_info(obj_label);
            // (a freed object's contents keep nothing reachable)
            if (ucsan_obj_freed(obj_label)) {
            } else if (obj_info->common.op == OP_RESERVED_OBJ) {
              ucsan_obj_info *obj = to_obj_info(obj_info);
              // object spans [real_ptr - lower_bound, real_ptr + upper_bound)
              ucsan_scan_mark_reachable((char*)obj->real_ptr - obj->lower_bound,
                                        obj->lower_bound + obj->upper_bound);
            } else {
              UCSAN_OUT("WARNING: expected obj label %u, got op %d\n",
                        obj_label, obj_info->common.op);
            }
          } else {
            UCSAN_OUT("WARNING: expected obj label %u, got non-pointer label\n", obj_label);
          }
        } // else uninitialized pointer, skip
      } else if (info->common.op == OP_ALLOCA) {
        // explicitly allocated object, mark as reachable and continue scanning
        info->common.op = OP_FREE;
        ucsan_obj_info *obj = to_obj_info(info);
        // object spans [real_ptr - lower_bound, real_ptr + upper_bound)
        ucsan_scan_mark_reachable((char*)obj->real_ptr - obj->lower_bound,
                                  obj->lower_bound + obj->upper_bound);
      }
    }
  }
}

/// mark and sweep style detector for unreachable memory regions
void ucsan_scan_shadow_for_leaks() {
  // This function can be called at program exit to detect memory leaks
  // by scanning the shadow memory for objects that are still live (not freed)
  // yet unreachable.

  UCSAN_OUT("ucsan_scan_shadow_for_leaks: scanning shadow memory for leaks\n");
  uint32_t last_label = atomic_load(&__ucsan_last_label, memory_order_relaxed);

  // step 1: mark reachable objects as freed
  // first set of roots: global variables
  if (__global_bounds_map_inited) {
    for (auto &entry : __global_bounds_map) {
      ucsan_label label = entry.ptr_label;
      void *base = (void*)entry.start;
      ucsan_label_info *info = get_label_info(label);
      UCSAN_OUT("global var: label=%u, base=%p, size=%lu, op=%d\n",
                label, base, entry.size, info->common.op);
      if (info->common.op != OP_ALLOCA) {
        UCSAN_OUT("WARNING: unexpected global var label op %d\n", info->common.op);
        continue;
      }
      info->common.op = OP_FREE; // mark as freed to indicate reachable
      ucsan_scan_mark_reachable(base, entry.size);
    }
  }

  // second set of roots: pseudo pointers in the union table
  for (unsigned i = 0; i <= last_label; ++i) {
    ucsan_label_info *info = get_label_info(i);
    if (info->common.op == OP_EXTERNAL) {
      // external pointer, find the real object and continue scanning
      info->common.op = OP_FREE; // mark as freed to indicate reachable
      ucsan_ptr_info *ptr_info = to_ptr_info(info);
      if (ptr_info->status == PTR_INITIALIZED) {
        ucsan_label obj_label = ptr_info->obj_label;
        if (obj_label >= UCSAN_CONST_OFFSET) {
          ucsan_label_info *obj_info = get_label_info(obj_label);
          // (a freed object's contents keep nothing reachable)
          if (ucsan_obj_freed(obj_label)) {
          } else if (obj_info->common.op == OP_RESERVED_OBJ) {
            ucsan_obj_info *obj = to_obj_info(obj_info);
            // object spans [real_ptr - lower_bound, real_ptr + upper_bound)
            ucsan_scan_mark_reachable((char*)obj->real_ptr - obj->lower_bound,
                                      obj->lower_bound + obj->upper_bound);
          } else {
            UCSAN_OUT("WARNING: expected obj label %u, got op %d\n",
                      obj_label, obj_info->common.op);
          }
        } else {
          UCSAN_OUT("WARNING: expected obj label %u, got non-pointer label\n", obj_label);
        }
      }
    }
  }

  // third set of root: return value labels in TLS
  {
    // FIXME: assume scalar return value for now
    ucsan_label retval_label = __ucsan_retval_tls[0];
    if (retval_label >= UCSAN_CONST_OFFSET) {
      ucsan_label_info *info = get_label_info(retval_label);
      if (info->common.op == OP_ALLOCA) {
        // external pointer, find the real object and continue scanning
        info->common.op = OP_FREE; // mark as freed to indicate reachable
        ucsan_obj_info *obj = to_obj_info(info);
        // object spans [real_ptr - lower_bound, real_ptr + upper_bound)
        ucsan_scan_mark_reachable((char*)obj->real_ptr - obj->lower_bound,
                                  obj->lower_bound + obj->upper_bound);
      }
    }
  }

  // step 2: report any remaining non-freed objects as leaks
  for (unsigned i = 0; i <= last_label; ++i) {
    ucsan_label_info *info = get_label_info(i);
    if (info->common.op == OP_ALLOCA) {
      ucsan_obj_info *obj = to_obj_info(info);
      UCSAN_OUT("ERROR: MEMLEAK detected: label=%u, ptr=%p, size=%u\n",
                i, obj->real_ptr, obj->lower_bound + obj->upper_bound);
      __taint_trace_event_addr(i, EVENT_MEMLEAK, 0, obj->real_ptr, 0);
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
  // Labels are 16-bit and kUninitializedLabel (0xFFFF) is reserved, so the
  // table's 174,762 entries cannot all be named.  The cast used to wrap
  // num_labels - 2 to 43,688, a third of what a label can address, and big
  // kernel structs (struct kvm_vmx, 40 KB, one label per byte) exhausted it.
  uptr top = num_labels - 2;
  if (top > (uptr)kUninitializedLabel - 1)
    top = (uptr)kUninitializedLabel - 1;
  __alloca_stack_top = __alloca_stack_bottom = (ucsan_label)top;
}

static void ucsan_fini_internal() {
  UCSAN_OUT("UCSan runtime finalized (labels used: %u of %u)\n",
            (unsigned)atomic_load(&__ucsan_last_label, memory_order_relaxed),
            (unsigned)__alloca_stack_bottom);

  if (ucsan_flags().check_memleak) {
    ucsan_scan_shadow_for_leaks();
  }

  if (__global_bounds_map_inited) {
    __global_bounds_map.destroy();
    __global_bounds_map_inited = false;
  }
  if (__symbolize_addr_map_inited) {
    __symbolize_addr_map.destroy();
    __symbolize_addr_map_inited = false;
  }

  // Clean up input struct
  ucsan_fini_input_struct();
}

// UCSanPass lowers %gs:-relative inline asm (the kernel's percpu accesses)
// to plain memory accesses, which is only the same memory while the %gs base
// is 0 -- the default for a process that never sets it.  Checked once, so a
// harness that does set it fails loudly instead of reading the wrong memory.
static void ucsan_check_gs_base() {
  uptr base = 0;
  long ret;
  // arch_prctl(ARCH_GET_GS, &base); this runtime is not instrumented
  __asm__ __volatile__("syscall"
                       : "=a"(ret)
                       : "a"(158 /* SYS_arch_prctl */), "D"(0x1004 /* ARCH_GET_GS */),
                         "S"(&base)
                       : "rcx", "r11", "memory");
  if (ret == 0 && base != 0) {
    Report("ERROR: UCSan: %%gs base is %p, but percpu inline asm was lowered "
           "assuming 0\n", (void *)base);
    Die();
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_init() {
  // Initialize input struct first (C-style init for preinit_array safety)
  ucsan_init_input_struct();

  // Parse options
  ucsan_parse_flags();

  ucsan_check_gs_base();

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

// A kernel WARN() (a _BUG_FLAGS ud2 with BUGFLAG_WARNING), which UCSanPass
// replaces with this call: the kernel would report it and continue, so the
// run continues and the manager gets an EVENT_WARN with the line and flags,
// at the call site's address.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void ucsan_trace_warn(const char *file, uint32_t line, uint32_t flags) {
  UCSAN_OUT("WARN at %s:%u (flags %#x)\n", file ? file : "?", line, flags);
  __taint_trace_event_addr(0, EVENT_WARN, line, __builtin_return_address(0),
                           flags);
}

// VMX: the VMCS the kernel's vmread/vmwrite act on, modeled as memory.
// UCSanPass lowers `vmread field, dst` to a load from ucsan_vmcs_field(field)
// and `vmwrite src, field` to a store to it, so a field read before any write
// is symbolized from the seed on first access, like any global, and a read
// after a write returns what was written, label included.  A slot per field:
// the encoding's width (bits 14:13), type (11:10) and index (9:1) select it,
// and the high-access bit (0) the upper half of a 64-bit field.  Richer VMX
// semantics (read-only exit information, a VM exit on vmlaunch/vmresume)
// belong here.
static u64 ucsan_vmcs[1 << 13];

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void *ucsan_vmcs_field(u64 field) {
  u64 idx = (((field >> 13) & 3) << 11) | (((field >> 10) & 3) << 9) |
            ((field >> 1) & 0x1ff);
  char *slot = (char *)&ucsan_vmcs[idx];
  return (field & 1) ? slot + 4 : slot;
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
                             uint32_t, uint32_t, uint64_t, void*,
                             uint32_t) {}

// Weak definition for global variable tracing
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_global_var,
                             uint32_t, uint64_t, uint64_t, void*) {}

// Weak definition for basic block tracing
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_bb,
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

// Make a SymSan expression label (op over l1/op1 and l2/op2)
// @return: SymSan label (0 when standalone)
SANITIZER_INTERFACE_WEAK_DEF(dfsan_label, __taint_union, dfsan_label, dfsan_label,
                             uint16_t, uint16_t, uint64_t, uint64_t) {
  return 0;
}

// Copy SymSan shadow memory from src to dst
// @param dst: destination address
// @param src: source address
// @param size: size in bytes
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_copy_shadow, void*, void*, uint64_t) {}

// Check loaded input bytes against the seed (verify_inputs; dfsan.cpp)
// @return: void (no-op when standalone: no SymSan labels to check)
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_verify_input_bytes, const void*, uptr, void*) {}

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

// Extend a SymSan label to a wider bit width via ZExt or SExt.
// @param label: input label (typically narrow, e.g. 8-bit byte label)
// @param sign_extend: true for SExt, false for ZExt
// @param new_size_in_bits: target bit width (must be > current size)
// @return: extended label (0 when standalone, or unchanged label if input is 0)
SANITIZER_INTERFACE_WEAK_DEF(dfsan_label, __taint_extend_label, dfsan_label, bool, uint16_t) {
  return 0;
}

}  // extern "C"
