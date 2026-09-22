typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef void* uptr;
typedef u32 dfsan_label;
typedef u64 data;

struct dfsan_label_info {
  dfsan_label l1;
  dfsan_label l2;
  data op1;
  data op2;
  // data op3; // FIXME: not sure if it's necessary to add this
  u16 op;
  u16 size; // FIXME: this limit the size of the operand to 65535 bits or bytes (in case of memcmp)
  u32 hash;
} __attribute__((aligned (8), packed));