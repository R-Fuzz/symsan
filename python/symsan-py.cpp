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
#include <sys/mman.h>
#include <errno.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

// For attach mode - track mapped shm for cleanup
static void *__attached_shm = nullptr;
static size_t __attached_shm_size = 0;

// z3parser
static z3::context __z3_context;
symsan::Z3ParserSolver *__z3_parser = nullptr;


static PyObject* SymSanInit(PyObject *self, PyObject *args, PyObject *keywds) {
  static const char *kwlist[] = {"program", "shm_size", "init_solver", NULL};
  const char *program;
  unsigned long long ut_size = uniontable_size;
  int init_solver = 1;  // default True

  if (!PyArg_ParseTupleAndKeywords(args, keywds, "s|Kp",
      const_cast<char**>(kwlist), &program, &ut_size, &init_solver)) {
    return NULL;
  }

  // setup launcher
  void *shm_base = symsan_init(program, ut_size);
  if (shm_base == (void *)-1) {
    fprintf(stderr, "Failed to map shm: %s\n", strerror(errno));
    return PyErr_SetFromErrno(PyExc_OSError);
  }

  // setup parser (optional)
  if (init_solver) {
    __z3_parser = new symsan::Z3ParserSolver(shm_base, ut_size, __z3_context);
    if (__z3_parser == nullptr) {
      fprintf(stderr, "Failed to initialize parser\n");
      return PyErr_NoMemory();
    }
  }

  return PyCapsule_New(shm_base, "dfsan_label_info", NULL);
}

static PyObject* SymSanConfig(PyObject *self, PyObject *args, PyObject *keywds) {
  static const char *kwlist[]
      = {"input", "args", "debug", "bounds", "undefined", NULL};
  const char *input = NULL;
  PyObject *iargs = NULL;
  int debug = 0;
  int bounds = 0;
  int solve_ub = 0;

  if (!PyArg_ParseTupleAndKeywords(args, keywds, "s|O!iii",
      const_cast<char**>(kwlist), &input, &PyList_Type, &iargs,
      &debug, &bounds, &solve_ub)) {
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

  if (symsan_set_solve_ub(solve_ub) != 0) {
    PyErr_SetString(PyExc_ValueError, "invalid solve_ub");
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
    __z3_parser = nullptr;
  }

  // Clean up attached shm (from init_parser with shm name)
  if (__attached_shm != nullptr) {
    munmap(__attached_shm, __attached_shm_size);
    __attached_shm = nullptr;
    __attached_shm_size = 0;
  } else {
    // Only call symsan_destroy if we used init (launcher mode)
    symsan_destroy();
  }

  Py_RETURN_NONE;
}

// Initialize parser from shared memory (by name or address)
// Usage: init_parser(shm_name, size) or init_parser(shm_capsule, size)
static PyObject* InitParser(PyObject *self, PyObject *args) {
  PyObject *shm_arg = NULL;
  unsigned long long shm_size = 0;

  if (!PyArg_ParseTuple(args, "OK", &shm_arg, &shm_size)) {
    return NULL;
  }

  // Clean up any previous parser
  if (__z3_parser != nullptr) {
    delete __z3_parser;
    __z3_parser = nullptr;
  }
  if (__attached_shm != nullptr) {
    munmap(__attached_shm, __attached_shm_size);
    __attached_shm = nullptr;
    __attached_shm_size = 0;
  }

  void *shm_base = nullptr;

  if (PyUnicode_Check(shm_arg)) {
    // shm_arg is a string (shared memory name)
    const char *shm_name = PyUnicode_AsUTF8(shm_arg);
    if (shm_name == NULL) {
      return NULL;
    }

    int shm_fd = shm_open(shm_name, O_RDWR, S_IRUSR | S_IWUSR);
    if (shm_fd == -1) {
      fprintf(stderr, "Failed to open shm '%s': %s\n", shm_name, strerror(errno));
      return PyErr_SetFromErrno(PyExc_OSError);
    }

    shm_base = mmap(0, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    close(shm_fd);

    if (shm_base == MAP_FAILED) {
      fprintf(stderr, "Failed to mmap shm: %s\n", strerror(errno));
      return PyErr_SetFromErrno(PyExc_OSError);
    }

    __attached_shm = shm_base;
    __attached_shm_size = shm_size;
  } else if (PyCapsule_CheckExact(shm_arg)) {
    // shm_arg is a capsule (already mapped address)
    shm_base = PyCapsule_GetPointer(shm_arg, "dfsan_label_info");
    if (shm_base == NULL) {
      return NULL;
    }
    // Don't track for munmap - caller owns this memory
  } else if (PyLong_Check(shm_arg)) {
    // shm_arg is an integer address
    shm_base = (void *)PyLong_AsUnsignedLongLong(shm_arg);
    if (PyErr_Occurred()) {
      return NULL;
    }
    // Don't track for munmap - caller owns this memory
  } else {
    PyErr_SetString(PyExc_TypeError, "first argument must be shm name (str), capsule, or address (int)");
    return NULL;
  }

  // Create the parser
  __z3_parser = new symsan::Z3ParserSolver(shm_base, shm_size, __z3_context);
  if (__z3_parser == nullptr) {
    if (__attached_shm != nullptr) {
      munmap(__attached_shm, __attached_shm_size);
      __attached_shm = nullptr;
      __attached_shm_size = 0;
    }
    fprintf(stderr, "Failed to initialize parser\n");
    return PyErr_NoMemory();
  }

  Py_RETURN_NONE;
}

// Reset parser with new input data
static PyObject* ResetParser(PyObject *self, PyObject *args) {
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

  // Always copy input data in Python to avoid dangling pointers
  if (__z3_parser->restart(inputs, true) != 0) {
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
    auto &val = solutions[i];
    PyObject *sol = PyDict_New();

    // Common fields for all operations
    PyDict_SetItemString(sol, "op", PyLong_FromLong((int)val.op));
    PyDict_SetItemString(sol, "id", PyLong_FromUnsignedLong(val.id));
    PyDict_SetItemString(sol, "offset", PyLong_FromUnsignedLong(val.offset));

    // Operation-specific fields
    using op_t = symsan::Z3ParserSolver::solution_op_t;
    switch (val.op) {
      case op_t::SET:
        PyDict_SetItemString(sol, "val", PyLong_FromUnsignedLong(val.val));
        break;
      case op_t::INSERT:
        PyDict_SetItemString(sol, "data",
            PyBytes_FromStringAndSize((char*)val.data.data(), val.data.size()));
        break;
      case op_t::DELETE:
        PyDict_SetItemString(sol, "len", PyLong_FromUnsignedLong(val.len));
        break;
    }

    PyList_SetItem(sols, i, sol);
  }

  PyObject *ret = PyTuple_New(2);
  PyTuple_SetItem(ret, 0, PyLong_FromLong(status));
  PyTuple_SetItem(ret, 1, sols);

  return ret;
}

static PyMethodDef SymSanMethods[] = {
  {"init", (PyCFunction)SymSanInit, METH_VARARGS | METH_KEYWORDS, "initialize symsan target"},
  {"config", (PyCFunction)SymSanConfig, METH_VARARGS | METH_KEYWORDS, "config symsan"},
  {"run", (PyCFunction)SymSanRun, METH_VARARGS | METH_KEYWORDS, "run symsan target, optional stdin=file"},
  {"read_event", SymSanReadEvent, METH_VARARGS, "read a symsan event"},
  {"terminate", (PyCFunction)SymSanTerminate, METH_NOARGS, "terminate current symsan instance"},
  {"destroy", (PyCFunction)SymSanDestroy, METH_NOARGS, "destroy symsan target"},
  {"init_parser", InitParser, METH_VARARGS, "initialize parser from shared memory (name or address)"},
  {"reset_input", ResetParser, METH_VARARGS, "reset the symbolic expression parser with a new input"},
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

  PyObject *module = PyModule_Create(&SymSanModule);
  if (module == NULL) {
    return NULL;
  }

  // Create OpType enum class
  PyObject *enum_module = PyImport_ImportModule("enum");
  if (enum_module == NULL) {
    Py_DECREF(module);
    return NULL;
  }

  PyObject *int_enum = PyObject_GetAttrString(enum_module, "IntEnum");
  Py_DECREF(enum_module);
  if (int_enum == NULL) {
    Py_DECREF(module);
    return NULL;
  }

  // Create OpType enum with SET=0, INSERT=1, DELETE=2
  PyObject *enum_dict = PyDict_New();
  PyDict_SetItemString(enum_dict, "SET", PyLong_FromLong(0));
  PyDict_SetItemString(enum_dict, "INSERT", PyLong_FromLong(1));
  PyDict_SetItemString(enum_dict, "DELETE", PyLong_FromLong(2));

  PyObject *enum_args = PyTuple_Pack(2, PyUnicode_FromString("OpType"), enum_dict);
  Py_DECREF(enum_dict);

  PyObject *op_type_enum = PyObject_CallObject(int_enum, enum_args);
  Py_DECREF(int_enum);
  Py_DECREF(enum_args);

  if (op_type_enum == NULL) {
    Py_DECREF(module);
    return NULL;
  }

  // Add OpType to module
  PyModule_AddObject(module, "OpType", op_type_enum);

  return module;
}
