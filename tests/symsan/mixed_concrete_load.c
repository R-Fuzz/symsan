// Runtime-level regression: evaluate reconstructed byte expressions against
// application memory, including concrete prefixes wider than an operand slot.
// Compile without instrumentation so only the explicit input labels vary.
// RUN: clang -O0 -c %s -o %t.o
// RUN: env KO_USE_FASTGEN=1 %ko-clang %t.o -o %t
// RUN: %t | FileCheck %s
// CHECK: mixed concrete loads: PASS
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

enum { INPUT = 0, LOAD = 32, CONCAT = 72 };

// Concat operand 1 contains the low bits.
static void evaluate(label l, unsigned char *out) {
  info *i = dfsan_get_label_info(l);
  if (i->op == INPUT) {
    assert(i->size == 8);
    out[0] = i->op2 == 1 ? (i->op1 * 31 + 17) & 255 : 0x47;
    return;
  }
  // Load: consecutive input-byte labels.
  if (i->op == LOAD) {
    for (unsigned j = 0; j < i->l2; ++j) evaluate(i->l1 + j, out + j);
    return;
  }
  assert(i->op == CONCAT);
  assert(i->l1 || i->l2); // no valueless constant-only Concat nodes
  unsigned left = i->l1 ? dfsan_get_label_info(i->l1)->size
                        : i->size - dfsan_get_label_info(i->l2)->size;
  unsigned right = i->size - left;
  if (i->l1) evaluate(i->l1, out);
  else {
    assert(left <= 64);
    for (unsigned j = 0; j < left / 8; ++j)
      out[j] = i->op1 >> (j * 8);
  }
  if (i->l2) evaluate(i->l2, out + left / 8);
  else {
    assert(right <= 64);
    for (unsigned j = 0; j < right / 8; ++j)
      out[left / 8 + j] = i->op2 >> (j * 8);
  }
}

int main(void) {
  static unsigned char bytes[16] __attribute__((aligned(16)));
  unsigned char reconstructed[16];
  for (unsigned size = 2; size <= 16; ++size) {
    for (unsigned symbolic = 0; symbolic < size; ++symbolic) {
      for (unsigned offset = 1; offset <= 100; offset += 99) {
        dfsan_set_label(0, bytes, sizeof(bytes));
        for (unsigned j = 0; j < size; ++j)
          bytes[j] = 0x83 + j; // includes high-bit concrete bytes
        bytes[symbolic] = 0x47;
        dfsan_set_label(dfsan_create_label(0, offset, 1),
                        bytes + symbolic, 1);
        label l = dfsan_read_label(bytes, size);
        assert(l && dfsan_get_label_info(l)->size == size * 8);
        memset(reconstructed, 0, sizeof(reconstructed));
        evaluate(l, reconstructed);
        assert(memcmp(bytes, reconstructed, size) == 0);
      }
    }
  }
  dfsan_set_label(0, bytes, sizeof(bytes));
  assert(dfsan_read_label(bytes, sizeof(bytes)) == 0);
  // Exercise multiple symbolic bytes, adjacent and separated, and reuse the
  // same input labels with changed concrete bytes to check expression dedup.
  label input[10];
  for (unsigned j = 0; j < 10; ++j)
    input[j] = dfsan_create_label(1, j + 1, 1);
  for (unsigned size = 2; size <= 10; ++size) {
    for (unsigned mask = 1; mask < (1U << size); ++mask) {
      for (unsigned salt = 0; salt < 2; ++salt) {
        dfsan_set_label(0, bytes, sizeof(bytes));
        for (unsigned j = 0; j < size; ++j) {
          bytes[j] = (mask & (1U << j)) ? ((j + 1) * 31 + 17) & 255
                                       : (131 + 127 * salt + 7 * j) & 255;
          if (mask & (1U << j)) dfsan_set_label(input[j], bytes + j, 1);
        }
        label l = dfsan_read_label(bytes, size);
        assert(l && dfsan_get_label_info(l)->size == size * 8);
        memset(reconstructed, 0, sizeof(reconstructed));
        evaluate(l, reconstructed);
        assert(memcmp(bytes, reconstructed, size) == 0);
      }
    }
  }
  // The public read API converts an uninitialized-byte marker to zero.
  for (unsigned j = 0; j < sizeof(bytes); ++j) {
    dfsan_set_label(0, bytes, sizeof(bytes));
    dfsan_set_label(UINT32_MAX, bytes + j, 1);
    assert(dfsan_read_label(bytes, sizeof(bytes)) == 0);
  }
  puts("mixed concrete loads: PASS");
  return 0;
}
