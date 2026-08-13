// METADATA: note.yaml
// FLAG: 200 201 202
// ENV: KO_WRAP_INDIRECT_CALL KO_TRACE_BB KO_RESIGN_PTRARGS


int bar(int a) {
  return a + 5;
}

int (*foo(void))(int) {
  static struct {
    // a function pointer to bar
    int (*a)(int);
  } s = { .a = bar };
  return s.a;
}

int cal(int (*a)(int, int*)) {
  int sum = 0;
  if (sum > 0) {
    __builtin_trap();
  }
  if (a(sum, &sum) > 1) { // sum will be reassigned after this call
    exit(200);
  };
  if (sum > 5) { // sum > 5 to fullfill this branch
    exit(201);
  } else { // sum <= 5 to fullfill this branch
    if (foo()(sum) >= 9) { // need to solve this indirect call, should yield (sum + 5) >= 9
      if (sum == 3) { // if sum == 3, then (sum + 5) == 8, should not reach here
        exit(199); // should not reach here
      }
      if (sum == 4) { // if sum == 4, then (sum + 5) == 9, should reach here
        exit(202);
      }
    }
  };
  return sum;
}