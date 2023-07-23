import ctypes

class OperationUnsupportedError(SystemExit):
    pass

class TaintFlag:
    F_ADD_CONS = 0b0001
    F_LOOP_EXIT = 0b0010
    F_LOOP_LATCH = 0b0100
    F_HAS_DISTANCE = 0b1000

class pipe_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("msg_type", ctypes.c_uint16),
                ("flags", ctypes.c_uint16),
                ("instance_id", ctypes.c_uint32),
                ("addr", ctypes.c_ulong),
                ("context", ctypes.c_uint32),
                ("id", ctypes.c_uint32),
                ("label", ctypes.c_uint32),
                ("result", ctypes.c_uint64)]

class gep_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("ptr_label", ctypes.c_uint32),
                ("index_label", ctypes.c_uint32),
                ("ptr", ctypes.c_ulong),
                ("index", ctypes.c_int64),
                ("num_elems", ctypes.c_uint64),
                ("elem_size", ctypes.c_uint64),
                ("current_offset", ctypes.c_int64)]

class memcmp_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("label", ctypes.c_uint32)]
    content = bytes()

class mazerunner_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("flags", ctypes.c_uint16),
                ("id", ctypes.c_uint32),
                ("addr", ctypes.c_ulong),
                ("context", ctypes.c_uint32),
                ("bb_dist", ctypes.c_uint64),
                ("avg_dist", ctypes.c_uint64)]

class concrete_value(ctypes.Union):
    _fields_ = [("i", ctypes.c_uint64),
                ("f", ctypes.c_float),
                ("d", ctypes.c_double)]

class dfsan_label_info(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("l1", ctypes.c_uint32),
                ("l2", ctypes.c_uint32),
                ("op1", concrete_value),
                ("op2", concrete_value),
                ("op", ctypes.c_uint16),
                ("size", ctypes.c_uint16),
                ("hash", ctypes.c_uint32)]
