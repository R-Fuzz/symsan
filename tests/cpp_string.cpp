// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang++-12 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_CXX=clang++-12 KO_USE_FASTGEN=1 %ko-clang++ -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg @@
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

// doesn't work with in-process z3 solver

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  char buf[20];
  size_t ret;

  FILE* fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf) - 1, fp);
  buf[sizeof(buf) - 1] = '\0'; 
  fclose(fp);

  // if (contents.substr(0, 7) == "iamback") {
  //   std::cout <<" hhe\n";
  //   abort();
  // }

  // if (contents[1] == 'y' && contents[2] == 'x') {
  //   abort();
  // }

  std::string val(buf);
  
  // if (val.compare("deadbeef") == 0) {
  // if (val == "deadbeef") {
  if (strcmp(val.c_str(), "deadbeef") == 0) {
    // CHECK-GEN: Good
    std::cout << "Good\n";
  } else {
    // CHECK-ORIG: Bad
    std::cout << "Bad\n";
  }

  return 0;
}
