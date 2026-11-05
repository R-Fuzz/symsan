/* library code: no labels for its frames.  One per callee, as TaintPass
   counts a library function's recursion too. */
#define CALL(k) void lib_call##k(void (*f)(int), int n) { f(n); }
CALL(0) CALL(1) CALL(2) CALL(3) CALL(4) CALL(5) CALL(6) CALL(7) CALL(8)
