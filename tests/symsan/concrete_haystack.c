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
