enum exit_reason {
  /* internal */
  REASON_INVALID_INPUT = 122, // the input breaks an invariant the code relies on (__dfsw_ucsan_assume)
  REASON_LOOP_OOB = 123,
  REASON_OBJ_OOB = 124,
  REASON_STACK_OOB = 125,
  REASON_MISALIGNED = 126,    // a faulting access whose alignment no placement of its UC object satisfies

  /* checker */
  EVENT_UBI = 150,
  EVENT_UAF = 151,
  EVENT_OOB = 152,
  EVENT_NULL_DEREF = 153,
  EVENT_DIV_BY_ZERO = 154,
  EVENT_INT_OVERFLOW = 155,
  EVENT_DOUBLE_FREE = 156,
  EVENT_MEMLEAK = 157,
  EVENT_INVALID_FREE = 158,   // free of an address inside an object
  EVENT_INEXACT_DIV = 159,    // a udiv/sdiv/lshr/ashr exact with a remainder

  EVENT_OOB_UPCAST = 161,

  EVENT_PANIC = 171,

  /* assumption assertion errors */
  EVENT_CONTRACTION = 201,
};
