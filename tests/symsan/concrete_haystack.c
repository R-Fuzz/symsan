// String-theory: the haystack is a program constant and the NEEDLE is the
// symbolic side -- the mirror image of every other strchr test here, where the
// buffer is symbolic and the needle is a literal.  Nothing can be planted,
// because no byte of "deadbeef" is writable; the move is to choose a character
// the haystack already contains.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("AAA:BB")' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.out/id-0-0-3 | FileCheck --check-prefix=CHECK-GEN3 %s
// RUN: %t.uninstrumented %t.out/id-0-0-4 | FileCheck --check-prefix=CHECK-GEN4 %s
//
// The RGD path (afltest -> parsers/rgd-parser.cpp -> i2s) is the stack a fuzzer
// runs, and it solves tests 1 and 2 here: input[0] and input[1] are each driven
// to a character of "deadbeef", nearest-first from the 'A' already there.
// Tests 3 and 4 are NOT solved on this path and no arm asserts them -- their
// needles are symbolic *strings* wrapped in a SubStr, which i2s declines, so
// only three inputs come out and the third is the `strchr(&input[2], ':')`
// clause shared with the other strchr tests.  Own output directory, because
// both stacks write id-0-0-0.
// RUN: rm -rf %t.rgd.out
// RUN: mkdir -p %t.rgd.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.rgd.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.rgd.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.rgd.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [file]\n", argv[0]);
        return -1;
    }

    char *haystack = "deadbeef\0";  // Concrete haystack
    char input[256] = {0};

    FILE* fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open\n");
        return -1;
    }
    size_t n = fread(input, 1, sizeof(input) - 1, fp);
    fclose(fp);
    input[n] = '\0';

    // Test 1: strchr with concrete haystack + symbolic needle
    char *pos = strchr(haystack, input[0]);
    if (pos) {
        // CHECK-GEN1: strchr: Found
        printf("strchr: Found '%c' at position %ld\n", input[0], pos - haystack);
        exit(0);
    }

    // Test 2: strrchr with concrete haystack + symbolic needle
    char *rpos = strrchr(haystack, input[1]);
    if (rpos) {
        // CHECK-GEN2: strrchr: Found
        printf("strrchr: Found '%c' at position %ld\n", input[1], rpos - haystack);
        exit(0);
    }

    char *sep = strchr(&input[2], ':');
    if (sep) {
        *sep = '\0'; // split input for strstr/strpbrk tests
    } else {
        printf("Missing ':' separator\n");
        exit(1);
    }

    // Test 3: strstr
    char *spos = strstr(haystack, &input[2]);
    if (spos) {
        // CHECK-GEN3: strstr: Found
        printf("strstr: Found substring at position %ld\n", spos - haystack);
        exit(0);
    }

    // Test 4: strpbrk
    char *pbrk_pos = strpbrk(haystack, sep + 1);
    if (pbrk_pos) {
        // CHECK-GEN4: strpbrk: Found
        printf("strpbrk: Found character '%c' at position %ld\n", *pbrk_pos, pbrk_pos - haystack);
        exit(0);
    }

    // CHECK-ORIG: Not found
    printf("Not found\n");

    return 0;
}
