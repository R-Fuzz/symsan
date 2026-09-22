typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef void* uptr;
typedef u32 dfsan_label;
typedef u64 data;

struct model_msg{
  u64 len;
  u32 flag;
  u32 status;
  u8 contents[0];
} __attribute__((packed));

struct model_describer {
  u32 object_id;
  long long offset;
  u8 value;
} __attribute__((packed));