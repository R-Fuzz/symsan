// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x00\x00\x00\x00' * 4)" > %t.bin
// RUN: clang -fsanitize=implicit-integer-truncation -o %t.ubsan %s
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-0 2>&1 FileCheck %s --check-prefix=CHECK-V0
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-3 2>&1 FileCheck %s --check-prefix=CHECK-V1
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-4 2>&1 FileCheck %s --check-prefix=CHECK-V2
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-7 2>&1 FileCheck %s --check-prefix=CHECK-V3

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

// Test plan:
//  * Two types - int and char
//  * Two signs - signed and unsigned
//  * Square that - we have input and output types.
// Thus, there are total of (2*2)^2 == 16 tests.
// These are all the possible variations/combinations of casts.
// However, not all of them should result in the check.
// So here, we *only* check which should and which should not result in checks.

uint32_t convert_unsigned_int_to_unsigned_int(uint32_t x) {
#line 100
  return x;
}

uint8_t convert_unsigned_char_to_unsigned_char(uint8_t x) {
#line 200
  return x;
}

int32_t convert_signed_int_to_signed_int(int32_t x) {
#line 300
  return x;
}

int8_t convert_signed_char_to_signed_char(int8_t x) {
#line 400
  return x;
}

uint8_t convert_unsigned_int_to_unsigned_char(uint32_t x) {
#line 500
  return x;
}

uint32_t convert_unsigned_char_to_unsigned_int(uint8_t x) {
#line 600
  return x;
}

int32_t convert_unsigned_char_to_signed_int(uint8_t x) {
#line 700
  return x;
}

int32_t convert_signed_char_to_signed_int(int8_t x) {
#line 800
  return x;
}

int32_t convert_unsigned_int_to_signed_int(uint32_t x) {
#line 900
  return x;
}

uint32_t convert_signed_int_to_unsigned_int(int32_t x) {
#line 1000
  return x;
}

uint8_t convert_signed_int_to_unsigned_char(int32_t x) {
#line 1100
  return x;
}

uint8_t convert_signed_char_to_unsigned_char(int8_t x) {
#line 1200
  return x;
}

int8_t convert_unsigned_char_to_signed_char(uint8_t x) {
#line 1300
  return x;
}

uint32_t convert_signed_char_to_unsigned_int(int8_t x) {
#line 1400
  return x;
}

int8_t convert_unsigned_int_to_signed_char(uint32_t x) {
#line 1500
  return x;
}

int8_t convert_signed_int_to_signed_char(int32_t x) {
#line 1600
  return x;
}

#line 1111 // !!!

int main (int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return 0;
  }

  FILE* fp = chk_fopen(argv[1], "rb");
  int x[4] = {0};

  chk_fread(x, sizeof(x), 1, fp);
  fclose(fp);

  convert_unsigned_int_to_unsigned_char((unsigned)x[0]);
// CHECK-V0: ubsan_trunc.c:500:10: runtime error: implicit conversion from type '{{.*}}' (aka 'unsigned int') of value {{.*}} (32-bit, unsigned) to type '{{.*}}' (aka 'unsigned char') changed the value to {{.*}} (8-bit, unsigned)
  convert_signed_int_to_unsigned_char(x[1]);
// CHECK-V1: ubsan_trunc.c:1100:10: runtime error: implicit conversion from type '{{.*}}' (aka 'int') of value {{.*}} (32-bit, signed) to type '{{.*}}' (aka 'unsigned char') changed the value to {{.*}} (8-bit, unsigned)
  convert_unsigned_int_to_signed_char((unsigned)x[2]);
// CHECK-V2: ubsan_trunc.c:1500:10: runtime error: implicit conversion from type '{{.*}}' (aka 'unsigned int') of value {{.*}} (32-bit, unsigned) to type '{{.*}}' (aka '{{(signed )?}}char') changed the value to {{.*}} (8-bit, signed)
  convert_signed_int_to_signed_char(x[3]);
// CHECK-V3: ubsan_trunc.c:1600:10: runtime error: implicit conversion from type '{{.*}}' (aka 'int') of value {{.*}} (32-bit, signed) to type '{{.*}}' (aka '{{(signed )?}}char') changed the value to {{.*}} (8-bit, signed)

  return 0;
}
