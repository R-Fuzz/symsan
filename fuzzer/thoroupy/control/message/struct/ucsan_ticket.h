typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef void* uptr;
typedef u32 dfsan_label;
typedef u64 data;

struct ucsan_ticket {
  u32 msg_type; // 0 = exit, 1 = start w/o init, 2 = start w/ content
  u32 instance_id;
  u32 session_id;
  u64 payload_size;
  u8 payload[0];
} __attribute__((packed));
