// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c "print('3' * ord('3'))" > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

void TestSimpleLoopWithConcreteBreakEdge(const char *input_path);
void TestSimpleLoopWithSymbolicBreakEdge(const char *input_path);
void TestNestedLoop(const char *input_path);
void TestRecursiveLoop(const char *input_path);
void TestMutipleExitsLoop(const char *input_path);

typedef void (*TestCaseFunc)(const char *);

typedef struct {
    const char *name;
    TestCaseFunc test_func;
} TestCase;

// To create an input, use the following script:
// python -c "print('3' * ord('3'))" > %t.bin
// where '3' can be any character.
TestCase test_cases[] = {
    // case 1: the loop exiting branch is a concrete branch
    {"SimpleLoopWithConcreteBreakEdge", TestSimpleLoopWithConcreteBreakEdge},
    // case 2: the loop exiting branch is a symbolic branch
    {"SimpleLoopWithSymbolicBreakEdge", TestSimpleLoopWithSymbolicBreakEdge},
    // case 3: nested loop
    {"NestedLoop", TestNestedLoop},
    // case 4: loop in a recursion
    {"RecursiveLoop", TestRecursiveLoop},
    // case 5: the loop have multiple exit points
    {"MutipleExitsLoop", TestMutipleExitsLoop},
};

void EnterLoop(const char* context, const int count){
    printf("%s: entering loop, loop counter: %d\n", context, count);
}

void ExitLoop(const char* context, const int count){
    printf("%s: exiting loop, loop counter: %d\n", context, count);
}

void ContextCat(const char* context_A, const char* context_B, char* context){
    strcpy(context, context_A);
    strcat(context, context_B);
}

int ReadLoopCount(const char* input_path){
    char buf;
    FILE* fp = chk_fopen(input_path, "rb");
    chk_fread(&buf, 1, 1, fp);
    fclose(fp);
    return buf - '0';
}

void SimpleLoop(const char* context, const int count) __attribute__((optnone)) {
    char fun_name[] = "_SimpleLoop";
    char new_context[strlen(context) + strlen(fun_name) + 1];
    ContextCat(context, fun_name, new_context);
    int i = 0;
    while(1){
        EnterLoop(new_context, i);
        if (i >= count){
            ExitLoop(new_context, i);
            break;
        }
        ++i;
    }
}

void NestedLoop(const char* context, const int count) __attribute__((optnone)) {
    // the inner loop and the outer loop have the same loop count.
    int i = 0;
    while(1){
        char outer_loop[] = "_OuterLoop";
        char outer_loop_context[strlen(context) + strlen(outer_loop) + 1];
        ContextCat(context, outer_loop, outer_loop_context);
        EnterLoop(outer_loop_context, i);
        if (i >= count){
            ExitLoop(outer_loop_context, i);
            break;
        }
        int j = 0;
        while(1){
            char inner_loop[] = "_InnerLoop";
            char inner_loop_context[strlen(context) + strlen(inner_loop) + 1];
            ContextCat(context, inner_loop, inner_loop_context);
            EnterLoop(inner_loop_context, j);
            if (j >= count){
                ExitLoop(inner_loop_context, j);
                break;
            }
            ++j;
        }
        ++i;
    }
}

void MutipleExitsLoop(const char* context, const int count, const char* data) __attribute__((optnone)) {
    int i = 0;
    printf("Loop starts.\n");
    while(1){
        EnterLoop(context, i);
        if (i >= count || data[i] == '\0'){
            // Exit point 1: break statement
            // python -c "print('3' * ord('3'))" > i.bin
            ExitLoop(context, i);
            break;
        } else if (data[i] > 'z') {
            // Exit point 2: return statement
            // python -c "print('{' * ord('{'))" > i.bin
            ExitLoop(context, i);
            return;
        } else if (data[i] <= '0') {
            // Exit point 3: exit statement
            // python -c "print('.' * ord('.'))" > i.bin
            ExitLoop(context, i);
            exit(0);
        } else if ( data[i] % 97 == 0) {
            // Exit point 4: goto statement.
            // python -c "print('a' * ord('a'))" > i.bin 
            ExitLoop(context, i);
            goto end;
        }
        else{
            ++i;
        }
    }
    printf("Loop normal ended.\n");
end:
    return;
}

void RecursiveLoop(const char* context, int depth, int count) __attribute__((optnone)) {
    if (depth == 0) {
        return;
    }
    char level[] = "_";
    char new_context[strlen(context) + strlen(level) + 1];
    ContextCat(context, level, new_context);
    int i = 0;
    while(1){
        EnterLoop(new_context, i);
        if (i >= count){
            ExitLoop(new_context, i);
            break;
        }
        RecursiveLoop(new_context, depth - 1, count);
        ++i;
    }
}

void TestSimpleLoopWithConcreteBreakEdge(const char *input_path){
    char buf[2];
    FILE* fp = chk_fopen(input_path, "rb");
    chk_fread(buf, 1, 1, fp);
    fclose(fp);
    buf[1] = '\0';
    SimpleLoop("ConcreteBreakEdge", atoi(buf));
}

void TestSimpleLoopWithSymbolicBreakEdge(const char *input_path){
    int c = ReadLoopCount(input_path);
    SimpleLoop("SymbolicBreakEdge", c);
}

void TestNestedLoop(const char *input_path){
    int c = ReadLoopCount(input_path);
    NestedLoop("NestedLoop", c);
}

void TestRecursiveLoop(const char *input_path){
    int c = ReadLoopCount(input_path);
    // Test the recursive function with depth of 'c', and loop count of 'c'.
    RecursiveLoop("RecursiveLoop", c, c);
}

void TestMutipleExitsLoop(const char *input_path){
    int c = ReadLoopCount(input_path) + 48; // add '0' back
    char buf[c+1];
    FILE* fp = chk_fopen(input_path, "rb");
    chk_fread(buf, 1, c, fp);
    fclose(fp);
    buf[c] = '\0';
    MutipleExitsLoop("MutipleExitsLoop", c, buf);
}

int main (int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [file]\n", argv[0]);
        return -1;
    }
    const char *input_path = argv[1];

    for (size_t i = 0; i < sizeof(test_cases) / sizeof(TestCase); i++) {
        printf("Running test: %s\n", test_cases[i].name);
        test_cases[i].test_func(input_path);
        printf("\n");
    }
    return 0;
}
