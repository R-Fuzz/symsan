#include "defs.h"
#include "debug.h"
#include "version.h"

#include "dfsan/dfsan.h"

extern "C" {
#include "launch.h"
}

#include "parse-z3.h"

#include <z3++.h>

#include <memory>
#include <utility>
#include <vector>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fcntl.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

// z3parser
static z3::context __z3_context;
symsan::Z3ParserSolver *__z3_parser = nullptr;


static PyObject* SymSanInit(PyObject *self, PyObject *args) {
  const char *program;
  unsigned long long ut_size = uniontable_size;

  if (!PyArg_ParseTuple(args, "s|K", &program, &ut_size)) {
    return NULL;
  }

  // setup launcher
  void *shm_base = symsan_init(program, ut_size);
  if (shm_base == (void *)-1) {
    fprintf(stderr, "Failed to map shm: %s\n", strerror(errno));
    return PyErr_SetFromErrno(PyExc_OSError);
  }

  // setup parser
  __z3_parser = new symsan::Z3ParserSolver(shm_base, ut_size, __z3_context);
  if (__z3_parser == nullptr) {
    fprintf(stderr, "Failed to initialize parser\n");
    return PyErr_NoMemory();
  }

  return PyCapsule_New(shm_base, "dfsan_label_info", NULL);
}

static PyObject* SymSanConfig(PyObject *self, PyObject *args, PyObject *keywds) {
  static const char *kwlist[] = {"input", "args", "debug", "bounds", NULL};
  const char *input = NULL;
  PyObject *iargs = NULL;
  int debug = 0;
  int bounds = 0;

  if (!PyArg_ParseTupleAndKeywords(args, keywds, "s|O!ii",
      const_cast<char**>(kwlist), &input, &PyList_Type, &iargs, &debug, &bounds)) {
    return NULL;
  }

  if (input == NULL) {
    PyErr_SetString(PyExc_ValueError, "missing input");
    return NULL;
  }

  if (symsan_set_input(input) != 0) {
    PyErr_SetString(PyExc_ValueError, "invalid input");
    return NULL;
  }

  if (args != NULL) {
    Py_ssize_t argc = PyList_Size(iargs);
    char *argv[argc];
    for (Py_ssize_t i = 0; i < argc; i++) {
      PyObject *item = PyList_GetItem(iargs, i);
      if (item == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "failed to retrieve args list");
        return NULL;
      }
      if (!PyUnicode_Check(item)) {
        PyErr_SetString(PyExc_TypeError, "args must be a list of strings");
        return NULL;
      }
      argv[i] = const_cast<char*>(PyUnicode_AsUTF8(item));
    }
    if (symsan_set_args(argc, argv) != 0) {
      PyErr_SetString(PyExc_ValueError, "invalid args");
      return NULL;
    }
  }

  if (symsan_set_debug(debug) != 0) {
    PyErr_SetString(PyExc_ValueError, "invalid debug");
    return NULL;
  }

  if (symsan_set_bounds_check(bounds) != 0) {
    PyErr_SetString(PyExc_ValueError, "invalid bounds");
    return NULL;
  }

  Py_RETURN_NONE;
}

static PyObject* SymSanRun(PyObject *self, PyObject *args, PyObject *keywds) {
  static const char *kwlist[] = {"stdin", NULL};
  const char *file = NULL;
  int fd = 0;

  if (!PyArg_ParseTupleAndKeywords(args, keywds, "|s", const_cast<char**>(kwlist), &file)) {
    return NULL;
  }

  if (file) {
    fd = open(file, O_RDONLY);
    if (fd < 0) {
      PyErr_SetFromErrno(PyExc_OSError);
      return NULL;
    }
  }

  int ret = symsan_run(fd);

  if (file) {
    close(fd);
  }
  
  if (ret < 0) {
    PyErr_SetString(PyExc_ValueError, "failed to launch target");
    return NULL;
  }

  Py_RETURN_NONE;
}

static PyObject* SymSanReadEvent(PyObject *self, PyObject *args) {
  PyObject *ret;
  char *buf;
  Py_ssize_t size;
  unsigned timeout = 0;

  if (!PyArg_ParseTuple(args, "n|I", &size, &timeout)) {
    return NULL;
  }

  if (size <= 0) {
    PyErr_SetString(PyExc_ValueError, "invalid buffer size");
    return NULL;
  }

  buf = (char *)malloc(size);

  ssize_t read = symsan_read_event(buf, size, timeout);
  if (read < 0) {
    PyErr_SetFromErrno(PyExc_OSError);
    free(buf);
    return NULL;
  }

  ret = PyBytes_FromStringAndSize(buf, read);
  free(buf);

  return ret;
}

static PyObject* SymSanTerminate(PyObject *self) {
  if (symsan_terminate() != 0) {
    PyErr_SetString(PyExc_RuntimeError, "failed to terminate target");
    return NULL;
  }

  int status, is_killed;
  is_killed = symsan_get_exit_status(&status);

  PyObject *ret = PyTuple_New(2);
  PyTuple_SetItem(ret, 0, PyLong_FromLong(status));
  PyTuple_SetItem(ret, 1, PyLong_FromLong(is_killed));

  return ret;
}

static PyObject* SymSanDestroy(PyObject *self) {
  if (__z3_parser != nullptr) {
    delete __z3_parser;
    symsan_destroy();
    __z3_parser = nullptr;
  }
  Py_RETURN_NONE;
}

static PyObject* InitParser(PyObject *self, PyObject *args) {
  if (__z3_parser == nullptr) {
    PyErr_SetString(PyExc_RuntimeError, "parser not initialized");
    return NULL;
  }

  std::vector<symsan::input_t> inputs;
  PyObject *iargs = NULL;

  if (!PyArg_ParseTuple(args, "O!", &PyList_Type, &iargs)) {
    return NULL;
  }

  Py_ssize_t argc = PyList_Size(iargs);
  for (Py_ssize_t i = 0; i < argc; i++) {
    PyObject *item = PyList_GetItem(iargs, i);
    if (item == NULL) {
      PyErr_SetString(PyExc_RuntimeError, "failed to retrieve args list");
      return NULL;
    }
    if (!PyBytes_Check(item)) {
      PyErr_SetString(PyExc_TypeError, "args must be a list of bytes");
      return NULL;
    }
    Py_ssize_t size;
    char *data;
    if (PyBytes_AsStringAndSize(item, &data, &size) != 0) {
      // exception should have been set?
      return NULL;
    }
    inputs.push_back({(uint8_t*)data, size});
  }

  if (__z3_parser->restart(inputs) != 0) {
    PyErr_SetString(PyExc_RuntimeError, "failed to restart parser");
    return NULL;
  }

  Py_RETURN_NONE;
}

static PyObject* ParseCond(PyObject *self, PyObject *args) {
  if (__z3_parser == nullptr) {
    PyErr_SetString(PyExc_RuntimeError, "parser not initialized");
    return NULL;
  }

  PyObject *ret;
  dfsan_label label = 0;
  uint64_t result = 0;
  uint16_t flags = 0;

  if (!PyArg_ParseTuple(args, "IKH", &label, &result, &flags)) {
    return NULL;
  }

  std::vector<uint64_t> tasks;
  if (__z3_parser->parse_cond(label, result, flags & F_ADD_CONS, tasks) != 0) {
    PyErr_SetString(PyExc_RuntimeError, "failed to parse condition");
    return NULL;
  }

  ret = PyList_New(tasks.size());
  for (size_t i = 0; i < tasks.size(); i++) {
    PyObject *task = PyLong_FromUnsignedLongLong(tasks[i]);
    PyList_SetItem(ret, i, task);
  }

  return ret;
}

static PyObject* ParseGEP(PyObject *self, PyObject *args) {
  if (__z3_parser == nullptr) {
    PyErr_SetString(PyExc_RuntimeError, "parser not initialized");
    return NULL;
  }

  PyObject *ret;
  dfsan_label ptr_label = 0;
  uptr ptr = 0;
  dfsan_label index_label = 0;
  int64_t index = 0;
  uint64_t num_elems = 0;
  uint64_t elem_size = 0;
  int64_t current_offset = 0;
  bool enum_index = false; // XXX: default to false?

  if (!PyArg_ParseTuple(args, "IKILKKLp", &ptr_label, &ptr, &index_label, &index,
      &num_elems, &elem_size, &current_offset, &enum_index)) {
    return NULL;
  }

  std::vector<uint64_t> tasks;
  if (__z3_parser->parse_gep(ptr_label, ptr, index_label, index, num_elems,
                             elem_size, current_offset, enum_index, tasks) != 0) {
    PyErr_SetString(PyExc_RuntimeError, "failed to parse GEP");
    return NULL;
  }

  ret = PyList_New(tasks.size());
  for (size_t i = 0; i < tasks.size(); i++) {
    PyObject *task = PyLong_FromUnsignedLongLong(tasks[i]);
    PyList_SetItem(ret, i, task);
  }

  return ret;
}

static PyObject* AddConstraint(PyObject *self, PyObject *args) {
  if (__z3_parser == nullptr) {
    PyErr_SetString(PyExc_RuntimeError, "parser not initialized");
    return NULL;
  }

  dfsan_label label = 0;
  uint64_t val = 0;

  if (!PyArg_ParseTuple(args, "IL", &label, &val)) {
    return NULL;
  }

  if (__z3_parser->add_constraints(label, val) != 0) {
    PyErr_SetString(PyExc_RuntimeError, "failed to add constraint");
    return NULL;
  }

  Py_RETURN_NONE;
}

static PyObject* RecordMemcmp(PyObject *self, PyObject *args) {
  if (__z3_parser == nullptr) {
    PyErr_SetString(PyExc_RuntimeError, "parser not initialized");
    return NULL;
  }

  dfsan_label label = 0;
  PyObject *buf = NULL;

  if (!PyArg_ParseTuple(args, "IS", &label, &buf)) {
    return NULL;
  }

  Py_ssize_t size;
  char *data;
  if (PyBytes_AsStringAndSize(buf, &data, &size) != 0) {
    // exception should have been set?
    return NULL;
  }

  if (__z3_parser->record_memcmp(label, (uint8_t*)data, size) != 0) {
    PyErr_SetString(PyExc_RuntimeError, "failed to record memcmp");
    return NULL;
  }

  Py_RETURN_NONE;
}

static PyObject* SolveTask(PyObject *self, PyObject *args) {
  if (__z3_parser == nullptr) {
    PyErr_SetString(PyExc_RuntimeError, "parser not initialized");
    return NULL;
  }

  uint64_t id = 0;
  unsigned timeout = 5000;
  if (!PyArg_ParseTuple(args, "K|I", &id, &timeout)) {
    return NULL;
  }

  symsan::Z3ParserSolver::solution_t solutions;
  int status = __z3_parser->solve_task(id, timeout, solutions);

  PyObject *sols = PyList_New(solutions.size());
  for (size_t i = 0; i < solutions.size(); i++) {
    PyObject *sol = PyTuple_New(3);
    auto val = solutions[i];
    PyTuple_SetItem(sol, 0, PyLong_FromUnsignedLong(val.id));
    PyTuple_SetItem(sol, 1, PyLong_FromUnsignedLong(val.offset));
    PyTuple_SetItem(sol, 2, PyLong_FromUnsignedLong(val.val));
    PyList_SetItem(sols, i, sol);
  }

  PyObject *ret = PyTuple_New(2);
  PyTuple_SetItem(ret, 0, PyLong_FromLong(status));
  PyTuple_SetItem(ret, 1, sols);

  return ret;
}

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

static char SymSanDoc[] = "Python3 wrapper over SymSan launch, parser, and solver.";

static PyModuleDef SymSanModule = {
  PyModuleDef_HEAD_INIT,
  "symsan",   /* name of module */
  SymSanDoc,  /* module documentation, may be NULL */
  -1,         /* size of per-interpreter state of the module,
                 or -1 if the module keeps state in global variables. */
  SymSanMethods
};

PyMODINIT_FUNC
PyInit_symsan(void) {
  // check if initialized before?
  if (__z3_parser != nullptr) {
    delete __z3_parser;
    symsan_destroy();
  }
  return PyModule_Create(&SymSanModule);
}
