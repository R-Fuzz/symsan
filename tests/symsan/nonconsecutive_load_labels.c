// A compact Load must preserve actual byte labels, not just their offsets.
// Compile without instrumentation to control allocation order precisely.
// RUN: clang -O0 -c %s -o %t.o
// RUN: env KO_USE_FASTGEN=1 %ko-clang %t.o -o %t
// RUN: %t | FileCheck %s
// CHECK: contiguous load invariants: PASS
#include <stdint.h>
#include <stdio.h>

typedef uint32_t label;
typedef struct {
  label l1, l2;
  uint64_t op1, op2;
  uint16_t op, size;
  uint32_t hash;
} __attribute__((aligned(8), packed)) info;
extern label dfsan_create_label(uint64_t, uint64_t, uint32_t);
extern void dfsan_set_label(label, void *, unsigned long);
extern label dfsan_read_label(const void *, unsigned long);
extern info *dfsan_get_label_info(label);
extern label dfsan_union(label, label, uint16_t, uint16_t, uint64_t, uint64_t);
enum { SUB = 15, LOAD = 32, TRUNC = 38, CONCAT = 72 };

static unsigned failures;
static void check(int condition, const char *name) {
  if (!condition) {
    fprintf(stderr, "FAIL: %s\n", name);
    ++failures;
  }
}

static label read_pair(label a, label b) {
  static unsigned char bytes[2] __attribute__((aligned(2))) = {0x11, 0x22};
  dfsan_set_label(a, bytes, 1);
  dfsan_set_label(b, bytes + 1, 1);
  return dfsan_read_label(bytes, 2);
}

static void check_concat(label a, label b, const char *name) {
  const info *i = dfsan_get_label_info(read_pair(a, b));
  check(i->op == CONCAT && i->size == 16 && i->l1 == a && i->l2 == b, name);
}

int main(void) {
  label a = dfsan_create_label(0, 100, 1);
  (void)dfsan_create_label(0, 900, 1);
  label b = dfsan_create_label(0, 101, 1);
  check(b == a + 2, "interleaved allocation setup");
  check_concat(a, b, "consecutive offsets with nonconsecutive IDs");

  a = dfsan_create_label(0, 200, 1);
  b = dfsan_create_label(1, 201, 1);
  check(b == a + 1, "different-input setup");
  check_concat(a, b, "consecutive IDs and offsets from different inputs");

  a = dfsan_create_label(0, 300, 1);
  b = dfsan_create_label(0, 302, 1);
  check_concat(a, b, "nonconsecutive input offsets");

  // The concrete-value slot of an expression is not an input-byte offset.
  a = dfsan_create_label(0, 400, 1);
  b = dfsan_union(0, a, SUB, 8, 401, 1);
  check(b == a + 1 && dfsan_get_label_info(b)->op1 == 401,
        "derived-label setup");
  check_concat(a, b, "derived expression resembling a consecutive offset");

  // A two-byte raw label must not be interpreted as a one-byte input label.
  a = dfsan_create_label(0, 500, 2);
  check(read_pair(a, a) == a, "multi-byte raw label");

  a = dfsan_create_label(0, 510, 1);
  b = dfsan_create_label(0, 511, 2);
  const info *wide = dfsan_get_label_info(read_pair(a, b));
  check(wide->op == CONCAT && wide->size == 16 && wide->l1 == a,
        "wide second operand is not a raw byte");
  if (wide->op == CONCAT) {
    const info *trunc = dfsan_get_label_info(wide->l2);
    check(trunc->op == TRUNC && trunc->size == 8 && trunc->l1 == b,
          "wide second operand is truncated to the loaded byte");
  }

  // The valid fast path must still use the compact Load representation.
  a = dfsan_create_label(2, 600, 1);
  b = dfsan_create_label(2, 601, 1);
  const info *i = dfsan_get_label_info(read_pair(a, b));
  check(i->op == LOAD && i->size == 16 && i->l1 == a && i->l2 == 2,
        "valid contiguous input uses compact Load");
  static unsigned char byte;
  dfsan_set_label(a, &byte, 1);
  check(dfsan_read_label(&byte, 1) == a, "single-byte load preserves label");
  check(read_pair(a, UINT32_MAX) == 0,
        "uninitialized marker after a symbolic byte is preserved");

  if (failures) return 1;
  puts("contiguous load invariants: PASS");
  return 0;
}
