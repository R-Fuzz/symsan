typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long i64;
typedef void* uptr;
typedef unsigned char u8;
struct pipe_msg {
  u16 msg_type;
  u16 flags;
  u32 instance_id;
  uptr addr;
  u32 context;
  u32 id;
  u32 label;
  u64 result;
} __attribute__((packed));

struct gep_msg {
  u32 ptr_label;
  u32 index_label;
  uptr ptr;
  i64 index;
  u64 num_elems;
  u64 elem_size;
  i64 current_offset;
} __attribute__((packed));

struct memcmp_msg {
  u32 label;
  u8 content[0];
} __attribute__((packed));
