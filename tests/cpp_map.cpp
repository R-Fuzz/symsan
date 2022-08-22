// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: clang++ -o %t.uninstrumented %s
// RUN: %t.uninstrumented | FileCheck --check-prefix=CHECK-BUG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang++ -o %t.fg %s
// RUN: %t.fg | FileCheck --check-prefix=CHECK-BUG %s

#include <map>
#include <string>
#include <iostream>
#include <cassert>

int main() {
  std::map<std::string, std::string> mymap;
  std::string k1("key1");
  std::string k2("key2");

  mymap[k1] = "xx1";
  mymap[k2] = "xx2";
  
  if (mymap["key1"] == "xx1" && mymap[k2] == "xx2" && mymap[k1] != mymap["k2"]) {
    // CHECK-BUG: Good
    std::cout << "Good\n";
  } else {
    std::cout << "Bad\n";
  }

  return 0;
}
