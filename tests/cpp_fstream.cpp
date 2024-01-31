// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang++-12 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_CXX=clang++-12 KO_USE_FASTGEN=1 %ko-clang++ -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg @@
// RUN: cp %t.out/id-0-0-0 %t.bin
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg @@
// RUN: cp %t.out/id-0-0-1 %t.bin
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg @@
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN %s

// doesn't work with in-process z3 solver

#include <string>
#include <cstdio>
#include <cerrno>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cstring>

int main (int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << "[file]\n";
    return -1;
  }

  std::fstream in_file;
  in_file.open(argv[1], std::ios::in | std::ios::binary);
  if (!in_file.is_open()) return 0;

  in_file.seekg (0, in_file.end);
  int length = in_file.tellg();
  in_file.seekg (0, in_file.beg);

  if (length <= 3) {
    std::cerr << "Input too short\n";
    return 0;
  }

  char *val = new char[length];
  in_file.read(val, length);

  if (val[0] == 'z' && val[1] == 'a' && val[2] == 'c') {
    // CHECK-GEN: Good
    std::cout << "Good\n";
  } else {
    // CHECK-ORIG: Bad
    std::cout << "Bad\n";
  }

  return 0;
}
