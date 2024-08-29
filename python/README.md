Provide a python binding to launch symsan-instrumented binary, receive events, parse constraints, and solve constraints.

```
static PyMethodDef SymSanMethods[] = {
  {"init", SymSanInit, METH_VARARGS, "initialize symsan target"},
  {"config", (PyCFunction)SymSanConfig, METH_VARARGS | METH_KEYWORDS, "config symsan"},
  {"run", (PyCFunction)SymSanRun, METH_VARARGS | METH_KEYWORDS, "run symsan target, optional stdin=file"},
  {"read_event", SymSanReadEvent, METH_VARARGS, "read a symsan event"},
  {"terminate", (PyCFunction)SymSanTerminate, METH_NOARGS, "terminate current symsan instance"},
  {"destroy", (PyCFunction)SymSanDestroy, METH_NOARGS, "destroy symsan target"},
  {"reset_input", InitParser, METH_VARARGS, "reset the symbolic expression parser with a new input"},
  {"parse_cond", ParseCond, METH_VARARGS, "parse trace_cond event into solving tasks"},
  {"parse_gep", ParseGEP, METH_VARARGS, "parse trace_gep event into solving tasks"},
  {"add_constraint", AddConstraint, METH_VARARGS, "add a constraint"},
  {"record_memcmp", RecordMemcmp, METH_VARARGS, "record a memcmp event"},
  {"solve_task", SolveTask, METH_VARARGS, "solve a task"},
  {NULL, NULL, 0, NULL}  /* Sentinel */
};
```

Currently only z3 solver is supported, will merge jigsaw and i2s later.
